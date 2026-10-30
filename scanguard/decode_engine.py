"""Mesin dekode: membongkar muatan yang disembunyikan dengan penyandian.

Mesin lain mencocokkan pola pada isi berkas apa adanya. Kelemahan itu dipakai
malware: perintahnya disandikan lebih dulu - base64, hex, gzip, kode karakter,
atau `-EncodedCommand` PowerShell - sehingga teks berbahayanya tidak pernah
muncul di berkas mentah. Aturan YARA yang mencari `vssadmin delete shadows`
tidak akan menemukannya, karena rangkaian huruf itu tidak ada di sana.

Mesin ini membongkar penyandian itu lebih dulu, lalu memeriksa isi hasilnya.
Kalau teks yang tersembunyi ternyata memuat kemampuan berbahaya, itu dilaporkan
beserta bukti hasil dekodenya.

Yang sengaja **tidak** dilakukan:

* **Berkas tidak pernah dijalankan.** Semuanya hanya pembacaan byte dan dekode
  di memori. Tidak ada shellcode yang dieksekusi, tidak ada sandbox, tidak ada
  koneksi jaringan.
* **Menemukan penyandian saja tidak cukup untuk melaporkan.** Base64 sangat
  lazim di berkas yang sah: sertifikat, gambar, dan berkas konfigurasi
  memakainya terus-menerus. Laporan hanya dibuat bila isi hasil dekode memuat
  penanda kemampuan berbahaya, atau bila muatan itu ternyata sebuah program.
* **Tingkat MALWARE tidak pernah diberikan.** Isi hasil dekode adalah bukti
  kuat, tetapi bukan bukti yang bisa diperiksa ulang seperti hash yang cocok
  atau tanda tangan virus. Batas tertinggi mesin ini adalah MENCURIGAKAN.

Batas kerja juga dipasang di mana-mana - kedalaman, ukuran hasil, jumlah
kandidat - karena berkas yang dibuat khusus untuk menggembungkan memori bisa
membuat pemindai mati, dan itu lebih buruk daripada tidak mendeteksi.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import io
import lzma
import re
import zlib
from dataclasses import dataclass, field

from .config import (
    DECODE_MAX_CANDIDATES,
    DECODE_MAX_DEPTH,
    DECODE_MAX_READ_BYTES,
    DECODE_MAX_RESULT_BYTES,
    DECODE_MIN_CANDIDATE,
    ENGINE_DECODE,
    SEV_NOTE,
    SEV_SUSPICIOUS,
)
from .core import Finding

# --------------------------------------------------------------------------- #
# Penanda kemampuan berbahaya
#
# Bobot 3 berarti penanda itu hampir tidak punya kegunaan yang sah. Bobot 2
# berarti lazim pada malware tetapi juga muncul di skrip admin. Bobot 1 berarti
# petunjuk lemah yang hanya berarti bila terkumpul.
# --------------------------------------------------------------------------- #

_CRITICAL, _STRONG, _WEAK = 3, 2, 1

_INDICATORS: tuple[tuple[str, int, str], ...] = (
    # --- Bukti kuat ---------------------------------------------------------- #
    (
        r"vssadmin(?:\.exe)?\s+delete\s+shadows|wbadmin\s+delete\s+catalog"
        r"|wmic\s+shadowcopy\s+delete|Get-WmiObject[^\n]{0,40}Win32_ShadowCopy",
        _CRITICAL,
        "Menghapus cadangan bayangan (ciri khas ransomware)",
    ),
    (
        r"-(?:enc|encodedcommand)\b|FromBase64String",
        _CRITICAL,
        "Menjalankan perintah hasil dekode secara tersembunyi",
    ),
    (
        r"DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|urlopen\(",
        _CRITICAL,
        "Mengunduh kode dari internet lalu menjalankannya",
    ),
    (
        r"Set-MpPreference[^\n]{0,80}DisableRealtimeMonitoring"
        r"|netsh\s+firewall[^\n]{0,40}set\s+opmode\s+disable"
        r"|sc\s+(?:stop|delete)\s+(?:windefend|wscsvc|sense)",
        _CRITICAL,
        "Mematikan perlindungan Windows",
    ),
    (
        r"mimikatz|sekurlsa|lsass\.exe|ntds\.dit|sam\s+save",
        _CRITICAL,
        "Mengambil kredensial dari sistem",
    ),
    # --- Bukti kuat kedua ---------------------------------------------------- #
    (
        r"Invoke-Expression|\biex\b|eval\(|exec\(|os\.system|subprocess\.(?:run|popen|call)",
        _STRONG,
        "Menjalankan kode yang dibentuk saat berjalan",
    ),
    (
        r"certutil[^\n]{0,40}-decode|bitsadmin[^\n]{0,40}/transfer",
        _STRONG,
        "Memakai alat bawaan Windows untuk mengunduh atau menyamarkan berkas",
    ),
    (
        r"schtasks[^\n]{0,60}/create|New-ScheduledTask|reg\s+add[^\n]{0,140}CurrentVersion\\Run",
        _STRONG,
        "Menjadwalkan diri agar berjalan lagi setelah komputer dinyalakan",
    ),
    (
        r"CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|QueueUserAPC|SetWindowsHookEx",
        _STRONG,
        "Menyuntikkan kode ke dalam proses lain",
    ),
    (
        r"wevtutil\s+cl|Clear-EventLog|fsutil\s+usn\s+deletejournal|cipher\s+/w",
        _STRONG,
        "Menghapus jejak aktivitas",
    ),
    (
        r"net\s+(?:localgroup|user)[^\n]{0,60}/(?:add|delete)",
        _STRONG,
        "Mengubah akun atau kelompok pengguna",
    ),
    (
        r"ncat\s|nc\s+-e|/dev/tcp/|socat\s|socket\.socket",
        _STRONG,
        "Membuka jalur komunikasi keluar",
    ),
    # --- Petunjuk lemah ------------------------------------------------------ #
    (r"https?://[^\s\"'<>]{8,}", _WEAK, "Menyebut alamat web"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _WEAK, "Menyebut alamat IP"),
    (
        r"meterpreter|metasploit|cobaltstrike|njrat|quasar|remcos|AsyncRAT",
        _WEAK,
        "Menyebut nama alat kendali jarak jauh yang dikenal",
    ),
    (
        r"Remove-Item[^\n]{0,40}-Force|del\s+/f\s+/q|rm\s+-rf",
        _WEAK,
        "Menghapus berkas secara paksa",
    ),
    (
        r"your files have been encrypted|all your files|kirim bitcoin|bayar tebusan",
        _WEAK,
        "Memuat teks catatan tebusan",
    ),
)

_COMPILED = tuple(
    (re.compile(pola, re.IGNORECASE), bobot, keterangan)
    for pola, bobot, keterangan in _INDICATORS
)

# --- Pola untuk mencari kandidat yang tersandikan -------------------------- #

_B64_RE = re.compile(rb"[A-Za-z0-9+/_-]{%d,}={0,2}" % DECODE_MIN_CANDIDATE)
_HEX_RE = re.compile(rb"(?:[0-9A-Fa-f]{2}){%d,}" % (DECODE_MIN_CANDIDATE // 2))
_CHARCODE_RE = re.compile(rb"(?:1?\d{1,3})(?:\s*,\s*1?\d{1,3}){6,}")
_CHR_CALL_RE = re.compile(rb"chr\(\s*\d{1,3}\s*\)\s*[+.]?\s*", re.IGNORECASE)
_POWERSHELL_ENC_RE = re.compile(
    rb"-[Ee][Nn][Cc](?:[Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd])?\s+([A-Za-z0-9+/=]{20,})"
)
# Bagian teks yang bisa dibaca. ROT13 hanya masuk akal pada teks, bukan pada
# byte acak, jadi kandidatnya dibatasi lebih dulu.
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{%d,}" % 64)

# Penanda jenis berkas yang menandakan hasil dekode adalah sebuah program.
_MAGIC = (
    (b"MZ", "program Windows (PE)"),
    (b"\x7fELF", "program Linux (ELF)"),
    (b"\xca\xfe\xba\xbe", "program macOS/Java"),
    (b"PK\x03\x04", "arsip ZIP"),
    (b"\xd0\xcf\x11\xe0", "dokumen Office lama"),
)


@dataclass
class Decoded:
    """Satu hasil pembongkaran, beserta jejak cara memperolehnya."""

    data: bytes
    # Jenis kandidat asal yang benar-benar ditemukan di berkas (mis. "Base64").
    # Dipisahkan dari `steps` supaya jejak bukti tidak menyesatkan: percobaan
    # pembongkaran gzip pada hasil dekode pernah menimpa asal kandidatnya,
    # sehingga laporan menulis "kandidat data terpadatkan" untuk muatan yang
    # sebenarnya ditemukan sebagai base64.
    origin: str
    depth: int
    steps: list[str] = field(default_factory=list)
    # "decode" berarti terapkan pembongkar `origin`; "decompress" berarti hanya
    # coba bongkar data terpadatkan (dipakai untuk hasil dekode, yang tidak boleh
    # dibongkar ulang dengan pembongkar yang sama).
    op: str = "decode"

    @property
    def jalur(self) -> str:
        """Jejak yang bisa dibaca manusia, mis. 'kandidat base64: bongkar gzip'."""
        if not self.steps:
            return f"kandidat {self.origin.lower()}"
        return f"kandidat {self.origin.lower()}: " + ", ".join(self.steps)

    @property
    def text(self) -> str:
        """Tafsirkan sebagai teks, termasuk UTF-16LE.

        PowerShell `-EncodedCommand` menghasilkan UTF-16LE. Bila ditebak sebagai
        UTF-8, byte nol di antara huruf membuat teksnya tidak terbaca dan
        perintah berbahayanya tidak pernah cocok.
        """
        return _as_text(self.data)


@dataclass
class Indicator:
    weight: int
    label: str


def _as_text(data: bytes) -> str:
    """Ubah byte menjadi teks, dengan menebak UTF-16LE bila polanya cocok.

    PowerShell `-EncodedCommand` menghasilkan UTF-16LE, dan byte nol di antara
    huruf akan membuat teksnya tidak terbaca bila ditebak sebagai UTF-8.
    """
    if not data:
        return ""
    if len(data) >= 4 and data[1::2].count(0) > len(data[1::2]) * 0.6:
        try:
            return data.decode("utf-16-le", "replace")
        except (UnicodeDecodeError, ValueError):
            pass
    return data.decode("utf-8", "replace")


# Tabel untuk membuang byte yang bisa dicetak. Dipakai bersama bytes.translate
# supaya penghitungannya berjalan di kode C, bukan di dalam loop Python.
# Versi pertama memakai `sum(1 for b in data if ...)`, dan pada muatan 8 MB itu
# saja memakan 1,6 detik untuk satu berkas.
_NON_PRINTABLE = bytes(
    b for b in range(256) if not (9 <= b <= 13 or 32 <= b <= 126)
)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    # translate menghapus byte yang tidak bisa dicetak, jadi panjang hasilnya
    # adalah jumlah byte yang bisa dicetak. Versi pertama mengurangi panjang
    # semula dengan panjang hasil, dan itu justru menghitung byte yang TIDAK
    # bisa dicetak - akibatnya setiap teks biasa dinilai sebagai data biner dan
    # seluruh deteksi muatan berhenti bekerja tanpa satu pun uji gagal.
    baik = len(data.translate(None, _NON_PRINTABLE))
    return baik / len(data)


def _is_text(data: bytes, minimum: float = 0.85) -> bool:
    return _printable_ratio(data) >= minimum


def _payload_text(item: Decoded) -> tuple[str, bool]:
    """Teks muatan, dan apakah isinya benar-benar teks.

    Pemeriksaan dilakukan pada teks yang sudah ditafsirkan, bukan pada byte
    mentahnya. Untuk muatan UTF-16LE, byte mentahnya penuh nol sehingga rasio
    keterbacaannya rendah padahal isinya teks biasa - dan versi pertama mesin ini
    melewatkan perintah PowerShell terenkode justru karena itu.
    """
    teks = item.text
    bersih = teks.encode("utf-8", "ignore")
    if len(bersih) < _MIN_TEXT:
        return teks, False
    return teks, _is_text(bersih, 0.80)


def _decompress(data: bytes, limit: int) -> bytes | None:
    """Bongkar data terpadatkan, dengan batas hasil.

    Batas ini bukan hiasan: satu berkas kecil bisa memuai menjadi gigabytes
    (zip bomb). Tanpa batas, pemindai kehabisan memori dan mati.
    """
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
                return handle.read(limit)
        except (OSError, EOFError, zlib.error):
            return None
    if data[:1] == b"\x78":
        try:
            return zlib.decompressobj().decompress(data, limit)
        except zlib.error:
            return None
    if data[:3] == b"BZh":
        try:
            return bz2.BZ2Decompressor().decompress(data, limit)
        except (OSError, EOFError, ValueError):
            return None
    if data[:6] == b"\xfd7zXZ\x00":
        try:
            return lzma.LZMADecompressor().decompress(data, limit)
        except (OSError, EOFError, ValueError, lzma.LZMAError):
            return None
    return None


def _decode_b64(raw: bytes) -> bytes | None:
    teks = raw.rstrip(b"=")
    sisa = len(teks) % 4
    if sisa == 1:
        # Panjang 1 modulo 4 tidak mungkin di base64 mana pun.
        return None
    teks += b"=" * ((4 - sisa) % 4)
    try:
        return base64.b64decode(teks, validate=True)
    except (binascii.Error, ValueError):
        try:
            return base64.urlsafe_b64decode(teks)
        except (binascii.Error, ValueError):
            return None


def _decode_hex(raw: bytes) -> bytes | None:
    if len(raw) % 2:
        raw = raw[:-1]
    try:
        return bytes.fromhex(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


def _decode_charcodes(raw: bytes) -> bytes | None:
    angka = [int(x) for x in re.findall(rb"\d{1,3}", raw)]
    if not angka or any(n > 255 for n in angka):
        return None
    return bytes(angka)


def _rot13(data: bytes) -> bytes | None:
    """Putar huruf 13 langkah. Skrip yang menyembunyikan kata dengan cara ini
    tetap lazim, dan pembongkarannya murah."""
    hasil = bytearray()
    for b in data:
        if 97 <= b <= 122:
            hasil.append((b - 97 + 13) % 26 + 97)
        elif 65 <= b <= 90:
            hasil.append((b - 65 + 13) % 26 + 65)
        else:
            hasil.append(b)
    return bytes(hasil)


def _utf16_from_b64(raw: bytes) -> bytes | None:
    """Khusus `-EncodedCommand`: base64 yang isinya UTF-16LE."""
    data = _decode_b64(raw)
    if data is None:
        return None
    if data[1::2].count(0) < len(data[1::2]) * 0.5:
        return None
    return data


# Panjang terpendek muatan yang layak dinilai sebagai teks. Batas ini hanya
# penyaring murah, bukan penentu: laporan tetap hanya dibuat bila ada penanda
# yang benar-benar cocok. Nilai 24 terlalu tinggi - muatan `IEX (New-Object)`
# yang sah hanya 15 karakter, dan versi pertama mesin ini melewatkannya.
_MIN_TEXT = 12

# Batas panjang teks yang dinilai penanda. Muatan yang benar-benar disandikan
# selalu pendek - perintah PowerShell, skrip, atau shellcode - sedangkan blob
# besar hasil pembongkaran (mis. zip bomb) membuat pencocokan regex lambat
# karena pola berjarak seperti `[^\n]{0,80}` mundur-maju pada jutaan karakter.
# Tanpa batas ini, satu berkas 8 MB memakan waktu 4,5 detik.
_MAX_SCORE_CHARS = 256 * 1024

# Batas ukuran muatan yang masih ditelusuri lebih dalam. Muatan yang benar-benar
# disandikan selalu kecil: perintah PowerShell, skrip, atau shellcode. Tanpa
# batas ini, blob besar hasil pembongkaran (mis. zip bomb) ikut ditelusuri
# berlapis-lapis dan satu berkas bisa memakan waktu berdetik-detik.
_MAX_NESTED_BYTES = 1024 * 1024

# Jatah kandidat per jenis. Tanpa jatah, satu jenis bisa menghabiskan seluruh
# kuota dan jenis lain tidak pernah diperiksa - berkas teks biasa punya puluhan
# ribu rangkaian karakter base64, sehingga pencarian hex dan kode karakter tidak
# akan pernah kebagian.
_BUDGET_PER_KIND = max(4, DECODE_MAX_CANDIDATES // 4)


def _candidates(data: bytes, kinds: tuple[str, ...]) -> list[tuple[str, bytes]]:
    """Cari bagian yang tampak tersandikan di dalam data.

    Pencarian dihentikan begitu jatah satu jenis penuh, dan itu penting untuk
    kecepatan: berkas 16 MB bisa memuat ratusan ribu rangkaian yang tampak
    seperti base64, dan menyusun semuanya lebih dulu membuat pemindaian lambat
    sekali pada berkas yang justru tidak menyembunyikan apa pun.
    """
    hasil: list[tuple[str, bytes]] = []

    def ambil(pola, jenis: str, grup: int = 0) -> None:
        # Jatah berlaku per pemanggilan, dan setiap jenis dipanggil satu kali,
        # jadi hasilnya tepat satu jatah untuk tiap jenis.
        sisa = _BUDGET_PER_KIND
        for match in pola.finditer(data):
            hasil.append((jenis, match.group(grup)))
            sisa -= 1
            if sisa <= 0:
                return

    if "powershell" in kinds:
        ambil(_POWERSHELL_ENC_RE, "Perintah PowerShell terenkode", 1)
    if "base64" in kinds:
        ambil(_B64_RE, "Base64")
    if "hex" in kinds:
        ambil(_HEX_RE, "Heksadesimal")
    if "charcode" in kinds:
        ambil(_CHARCODE_RE, "Daftar kode karakter")
        panggilan = _CHR_CALL_RE.findall(data)
        if len(panggilan) >= 5:
            gabung = b"".join(panggilan)
            if len(gabung) >= DECODE_MIN_CANDIDATE:
                hasil.append(("Panggilan chr()", gabung))
    if "rot13" in kinds:
        ambil(_PRINTABLE_RUN_RE, "Teks (diuji dengan ROT13)")
    return hasil[:DECODE_MAX_CANDIDATES]


def unpack(data: bytes, max_depth: int = DECODE_MAX_DEPTH) -> list[Decoded]:
    """Bongkar penyandian secara bertingkat, dengan batas di setiap arah.

    Berlapis-lapis bukan kemewahan: malware sering membungkus base64 di dalam
    gzip di dalam base64. Satu lapis saja melewatkan sebagian besar kasus nyata.
    """
    data = data[:DECODE_MAX_READ_BYTES]
    hasil: list[Decoded] = []
    terpakai = 0
    dilihat: set[str] = set()
    antrean: list[Decoded] = [
        Decoded(payload, jenis, 0, [])
        for jenis, payload in _candidates(
            data, ("powershell", "base64", "hex", "charcode", "rot13")
        )
    ]

    while antrean:
        if len(hasil) >= DECODE_MAX_CANDIDATES or terpakai >= DECODE_MAX_RESULT_BYTES:
            break
        item = antrean.pop(0)
        for langkah, buka in _open(item):
            if not buka:
                continue
            sidik = hashlib.sha256(buka).hexdigest()
            if sidik in dilihat:
                continue
            dilihat.add(sidik)
            terpakai += len(buka)
            turunan = Decoded(buka, item.origin, item.depth + 1, item.steps + [langkah])
            hasil.append(turunan)
            if turunan.depth >= max_depth or len(buka) > _MAX_NESTED_BYTES:
                continue
            if _is_text(buka):
                for jenis, payload in _candidates(buka, ("base64", "hex", "charcode")):
                    antrean.append(
                        Decoded(payload, jenis, turunan.depth, turunan.steps)
                    )
            # Percobaan pembongkaran data terpadatkan dijadwalkan terpisah,
            # karena isinya tidak bisa dibaca sebagai teks sebelum dibongkar.
            antrean.append(
                Decoded(
                    buka,
                    turunan.origin,
                    turunan.depth,
                    turunan.steps,
                    op="decompress",
                )
            )
    return hasil


def _open(item: Decoded) -> list[tuple[str, bytes]]:
    """Buka satu lapis penyandian. Kembalikan daftar (nama langkah, hasil).

    Data terpadatkan dicoba pada SEMUA jenis, bukan hanya pada data mentah.
    Inilah yang menemukan gzip yang dibungkus base64 - susunan yang paling
    sering dipakai malware, karena menghasilkan teks yang tampak tidak
    berbahaya. Versi pertama mesin ini memakai `return` lebih awal sehingga
    susunan itu tidak pernah terbongkar.
    """
    keluar: list[tuple[str, bytes]] = []
    raw = item.data
    kind = item.origin

    if item.op == "decompress":
        data = _decompress(raw, DECODE_MAX_RESULT_BYTES)
        if data:
            keluar.append(("bongkar data terpadatkan", data))
        return keluar

    if kind == "Perintah PowerShell terenkode":
        data = _utf16_from_b64(raw)
        if data:
            keluar.append(("buka base64 UTF-16LE", data))
    elif kind == "Base64":
        data = _decode_b64(raw)
        if data:
            keluar.append(("buka base64", data))
    elif kind == "Heksadesimal":
        data = _decode_hex(raw)
        if data:
            keluar.append(("buka heksadesimal", data))
    elif kind in ("Daftar kode karakter", "Panggilan chr()"):
        data = _decode_charcodes(raw)
        if data:
            keluar.append(("buka kode karakter", data))
    elif kind == "Teks biasa":
        data = _rot13(raw)
        if data and data != raw:
            keluar.append(("buka ROT13", data))
    # Penyandian sering dipakai hanya untuk membungkus gzip.
    data = _decompress(raw, DECODE_MAX_RESULT_BYTES)
    if data:
        keluar.append(("bongkar data terpadatkan", data))
    return keluar


def score(text: str) -> tuple[int, list[Indicator]]:
    """Hitung nilai kemampuan berbahaya di dalam teks hasil dekode."""
    total = 0
    kena: list[Indicator] = []
    for pola, bobot, keterangan in _COMPILED:
        if pola.search(text):
            total += bobot
            kena.append(Indicator(bobot, keterangan))
    return total, kena


def _embedded_program(data: bytes) -> str:
    for magic, nama in _MAGIC:
        if data.startswith(magic):
            return nama
    return ""


def _severity(total: int, kena: list[Indicator], program: str) -> str:
    """Tentukan tingkat bahaya.

    Tingkat MALWARE tidak pernah dikembalikan. Isi hasil dekode adalah bukti
    kuat, tetapi bukan bukti yang bisa diperiksa ulang seperti hash yang cocok
    atau tanda tangan virus - jadi batasnya MENCURIGAKAN.
    """
    if program:
        return SEV_SUSPICIOUS
    if any(item.weight >= _CRITICAL for item in kena):
        return SEV_SUSPICIOUS
    if total >= 4:
        return SEV_SUSPICIOUS
    return SEV_NOTE


def _potongan(text: str, kena: list[Indicator], batas: int = 220) -> str:
    """Ambil potongan teks di sekitar penanda pertama, untuk ditunjukkan.

    Pengguna harus bisa menilai sendiri, bukan hanya menerima tuduhan. Karena
    itu buktinya ditampilkan, bukan hanya jumlahnya.
    """
    for pola, _bobot, keterangan in _COMPILED:
        match = pola.search(text)
        if match:
            awal = max(0, match.start() - 60)
            cuplik = text[awal:awal + batas].replace("\n", " ").strip()
            return cuplik
    return text[:batas].replace("\n", " ").strip()


class DecodeEngine:
    """Mesin kelima: membongkar penyandian lalu menilai isinya.

    Tidak butuh pustaka luar, tidak butuh internet, dan tidak menyentuh
    antarmuka. Seluruh keputusannya bisa diperiksa ulang dengan membaca kode ini.
    """

    name = ENGINE_DECODE

    def __init__(self, max_depth: int = DECODE_MAX_DEPTH) -> None:
        self.max_depth = max_depth

    @property
    def available(self) -> bool:
        """Selalu siap: hanya memakai pustaka standar Python."""
        return True

    @property
    def status(self) -> str:
        return (
            "Siap. Membongkar base64, hex, gzip/zlib, kode karakter, ROT13, dan "
            "perintah PowerShell terenkode."
        )

    def scan_bytes(self, data: bytes, path: str) -> list[Finding]:
        """Periksa data mentah. Dipisahkan dari scan_file supaya bisa diuji."""
        try:
            hasil = unpack(data, self.max_depth)
        except Exception:  # noqa: BLE001 - berkas aneh tidak boleh menghentikan pemindaian
            return []

        findings: list[Finding] = []
        dilaporkan: set[str] = set()

        for item in hasil:
            program = _embedded_program(item.data)
            teks, is_teks = _payload_text(item)
            total, kena = (0, [])
            if not program and is_teks:
                total, kena = score(teks[:_MAX_SCORE_CHARS])
            if not program and not kena:
                continue

            sidik = hashlib.sha256(item.data).hexdigest()[:16]
            if sidik in dilaporkan:
                continue
            dilaporkan.add(sidik)

            if program:
                detail = (
                    f"Muatan tersembunyi berisi {program}, {len(item.data)} byte. "
                    f"Cara dibongkar: {item.jalur}. "
                    f"Program yang disembunyikan di dalam berkas lain sering "
                    f"dipakai untuk menghindari pemeriksaan."
                )
                rule = "Program tertanam dalam muatan terenkode"
            else:
                label = "; ".join(dict.fromkeys(i.label for i in kena))
                detail = (
                    f"Cara dibongkar: {item.jalur}. Nilai {total}. "
                    f"Ditemukan: {label}. "
                    f"Cuplikan hasil dekode: {_potongan(teks, kena)!r}"
                )
                rule = "Muatan terenkode dengan kemampuan berbahaya"

            findings.append(
                Finding(
                    path=path,
                    engine=ENGINE_DECODE,
                    rule=rule,
                    detail=detail,
                    severity=_severity(total, kena, program),
                )
            )
        return findings

    def scan_file(self, path: str) -> list[Finding]:
        """Baca berkas lalu periksa. Batas baca lebih kecil dari mesin lain.

        Hasil dekode jarang berada di ujung berkas raksasa, sedangkan pencarian
        pola pada 16 MB sekaligus membuat satu berkas memakan waktu lama.
        """
        try:
            with open(path, "rb") as handle:
                data = handle.read(DECODE_MAX_READ_BYTES)
        except OSError:
            return []
        return self.scan_bytes(data, path)
