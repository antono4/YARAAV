"""Analisis berkas PE (program Windows) memakai pustaka pefile.

Ini bagian yang membaca struktur di dalam program, bukan sekadar mencari teks.
Yang diperiksa adalah hal-hal yang di dunia nyata memang dipakai untuk menilai
sebuah program:

* **Impor mencurigakan** - fungsi Windows yang berkaitan dengan penyuntikan
  kode, pencurian kredensial, pengubahan memori proses lain, atau pengintaian.
  Program biasa hampir tidak pernah memakainya bersamaan.
* **Rasio entropi section** - section yang isinya hampir acak berarti program
  sudah dipadatkan (packed) atau dienkripsi, cara paling umum malware
  menyembunyikan isinya dari antivirus.
* **Nama section tidak lazim** - UPX, .themida, .vmp, dan sejenisnya adalah
  nama pemadat yang dikenal.
* **Waktu kompilasi di masa depan** - penanda waktu yang dimanipulasi.
* **Rekayasa balik yang dangkal** - jumlah section tidak wajar, entry point
  di luar section kode, dan sebagainya.

Semua temuan diberi **skor**, dan skor itu menentukan tingkat bahaya. Satu
petunjuk saja tidak cukup untuk memvonis; beberapa petunjuk yang muncul
bersamaan jauh lebih berarti. Inilah cara kerja deteksi heuristik.
"""

from __future__ import annotations

import math
import os
import threading
from dataclasses import dataclass, field

from .config import (
    ENGINE_PE,
    ENTROPY_PACKED_THRESHOLD,
    SEV_MALWARE,
    SEV_NOTE,
    SEV_SUSPICIOUS,
)
from .core import Finding, looks_like_pe, shannon_entropy

# Fungsi Windows yang, bila muncul bersamaan, menunjukkan niat menyuntikkan
# kode ke proses lain atau mencuri data dari dalam memori.
# Setiap entri: (bobot, penjelasan, bukti_kuat).
#
# "bukti_kuat" menandai fungsi yang hampir tidak pernah dipakai program biasa.
# Pembedaan ini penting: satu petunjuk lemah (misalnya memanggil VirtualProtect)
# sangat umum pada program normal, jadi tidak boleh membuat program dinyatakan
# mencurigakan. Deteksi baru berarti bila ada bukti kuat, atau bila banyak
# petunjuk lemah muncul bersamaan.
SUSPICIOUS_IMPORTS: dict[str, tuple[int, str, bool]] = {
    # --- Bukti kuat: penyuntikan kode ke proses lain ---------------------- #
    "virtualallocex": (30, "Mengalokasikan memori di proses lain (penyuntikan kode)", True),
    "writeprocessmemory": (35, "Menulis ke memori proses lain (penyuntikan kode)", True),
    "createremotethread": (35, "Membuat thread di proses lain (penyuntikan kode)", True),
    "ntcreatethreadex": (30, "Membuat thread di proses lain (varian tidak resmi)", True),
    "queueuserapc": (25, "Menyuntikkan kode lewat APC", True),
    "readprocessmemory": (25, "Membaca memori proses lain", True),
    "virtualprotectex": (20, "Mengubah hak akses memori proses lain", True),
    "setwindowshookex": (25, "Memasang hook global untuk merekam aktivitas", True),
    "setwindowshookexa": (25, "Memasang hook global", True),
    "getasynckeystate": (25, "Membaca keadaan tombol (perekam ketikan)", True),
    "urldownloadtofilea": (20, "Mengunduh berkas dari internet lalu menyimpannya", True),
    "urldownloadtofilew": (20, "Mengunduh berkas dari internet lalu menyimpannya", True),
    "checkremotedebuggerpresent": (18, "Memeriksa keberadaan alat analisis", True),
    "getclipboarddata": (18, "Membaca isi clipboard", True),
    "cryptencrypt": (15, "Mengenkripsi data", True),
    # --- Petunjuk lemah: bisa muncul pada program biasa ------------------- #
    "openprocess": (15, "Membuka proses lain untuk diperiksa", False),
    "createtoolhelp32snapshot": (12, "Mendaftar seluruh proses yang berjalan", False),
    "process32first": (10, "Menelusuri daftar proses", False),
    "process32next": (10, "Menelusuri daftar proses", False),
    "virtualprotect": (8, "Mengubah hak akses halaman memori", False),
    "loadlibrarya": (8, "Memuat pustaka saat program berjalan", False),
    "getprocaddress": (8, "Mencari alamat fungsi saat program berjalan", False),
    "winexec": (12, "Menjalankan program lain (cara lama)", False),
    "shellexecutea": (8, "Menjalankan berkas atau program lain", False),
    "shellexecutew": (8, "Menjalankan berkas atau program lain", False),
    "internetopenurla": (15, "Membuka alamat internet", False),
    "winhttpopen": (10, "Membuka koneksi HTTP", False),
    "wsastartup": (5, "Membuka koneksi jaringan", False),
    "cryptgenrandom": (8, "Membuat angka acak untuk kunci enkripsi", False),
    "getkeystate": (15, "Membaca keadaan tombol", False),
    "getforegroundwindow": (12, "Mengintai jendela yang sedang aktif", False),
    "terminateprocess": (10, "Menghentikan proses lain", False),
    "adjusttokenprivileges": (15, "Menaikkan hak akses proses", False),
    "isdebuggerpresent": (10, "Memeriksa apakah sedang dianalisis", False),
    "outputdebugstringa": (5, "Menulis pesan debug", False),
}

# Nama pemadat (packer) yang dikenal.
PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", "upx!",
    ".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2",
    ".aspack", ".adata", ".nsp0", ".nsp1", ".petite",
    ".mpress1", ".mpress2", ".enigma1", ".enigma2",
    ".pklstb", ".boom", ".packed", ".pack",
}

# Tanggal paling awal yang masuk akal untuk sebuah program. Waktu kompilasi
# yang lebih tua dari ini hampir selalu hasil pemalsuan.
MIN_PLAUSIBLE_YEAR = 1995


@dataclass
class PEAnalysis:
    """Ringkasan struktur sebuah berkas PE."""

    is_pe: bool = False
    is_dotnet: bool = False
    machine: str = ""
    subsystem: str = ""
    timestamp: int = 0
    timestamp_text: str = ""
    section_count: int = 0
    sections: list[dict] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    import_count: int = 0
    entry_point: int = 0
    entry_section: str = ""
    max_section_entropy: float = 0.0
    packed_section_names: list[str] = field(default_factory=list)
    packed: bool = False
    signature: str = ""
    score: int = 0
    notes: list[str] = field(default_factory=list)
    error: str = ""


class PEEngine:
    """Membaca struktur PE dan menghitung skor risiko."""

    name = ENGINE_PE

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._import_error = ""

    @property
    def available(self) -> bool:
        try:
            import pefile  # noqa: F401
        except ImportError as error:
            self._import_error = str(error)
            return False
        return True

    @property
    def status(self) -> str:
        if self.available:
            return "pefile siap menganalisis struktur program Windows."
        return (
            "pefile tidak terpasang, jadi analisis PE dilewati. "
            f"Pasang dengan: pip install pefile ({self._import_error})"
        )

    def analyze(self, path: str) -> PEAnalysis:
        """Baca struktur PE satu berkas. Tidak melempar error untuk berkas aneh."""
        result = PEAnalysis()
        if not self.available:
            result.error = "pefile tidak terpasang"
            return result
        if not looks_like_pe(path):
            return result

        import pefile

        try:
            pe = pefile.PE(path, fast_load=True)
        except Exception as error:  # noqa: BLE001 - berkas rusak bukan alasan berhenti
            result.error = f"Struktur PE tidak bisa dibaca: {error}"
            return result

        try:
            with self._lock:
                self._fill(pe, result)
        except Exception as error:  # noqa: BLE001
            result.error = f"Analisis PE gagal: {error}"
        finally:
            pe.close()
        return result

    # ------------------------------------------------------------------ #

    def _fill(self, pe, result: PEAnalysis) -> None:
        import pefile

        result.is_pe = True

        machine = pe.FILE_HEADER.Machine
        result.machine = pefile.MACHINE_TYPE.get(machine, f"0x{machine:x}")
        result.timestamp = pe.FILE_HEADER.TimeDateStamp
        result.timestamp_text = _timestamp_text(result.timestamp)
        result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "Subsystem"):
            result.subsystem = pefile.SUBSYSTEM_TYPE.get(
                pe.OPTIONAL_HEADER.Subsystem, "tidak diketahui"
            )

        # Bagian .NET berarti program memuat kode yang dikelola (mis. C#).
        try:
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            ]
            result.is_dotnet = directory.VirtualAddress != 0
        except (AttributeError, IndexError, KeyError):
            result.is_dotnet = False

        # --- Section ---------------------------------------------------- #
        sections = getattr(pe, "sections", []) or []
        result.section_count = len(sections)
        for section in sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", "replace")
            raw = section.get_data() or b""
            # Sample isi section agar entropi tidak memakan waktu pada berkas besar.
            sample = raw[: 2 * 1024 * 1024]
            entropy = shannon_entropy(sample) if sample else 0.0
            result.sections.append(
                {
                    "name": name,
                    "size": len(raw),
                    "entropy": entropy,
                    "executable": bool(section.Characteristics & 0x20000000),
                    "writable": bool(section.Characteristics & 0x80000000),
                }
            )
            if entropy > result.max_section_entropy:
                result.max_section_entropy = entropy
            if name.lower() in PACKER_SECTIONS:
                result.packed_section_names.append(name)

        # --- Impor ------------------------------------------------------ #
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
        except Exception:  # noqa: BLE001
            pass
        imports: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = (entry.dll or b"").decode("ascii", "replace").lower()
            for symbol in entry.imports or []:
                if symbol.name:
                    imports.append(symbol.name.decode("ascii", "replace").lower())
                else:
                    imports.append(f"ordinal:{symbol.ordinal}@{dll}")
        result.imports = imports
        result.import_count = len(imports)

        result.entry_section = _section_for_rva(pe, result.entry_point)
        result.signature = self._read_signature(pe)

        self._score(result)

    def _read_signature(self, pe) -> str:
        """Periksa apakah berkas punya blok tanda tangan digital.

        Program yang ditandatangani secara digital jauh lebih kecil
        kemungkinannya berbahaya, jadi petunjuk ini menurunkan skor risiko.
        Program tanpa tanda tangan tidak otomatis jahat - hampir semua
        perangkat lunak gratis memang tidak ditandatangani.
        """
        try:
            # Indeks 4 pada data directory adalah IMAGE_DIRECTORY_ENTRY_SECURITY.
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if directory.VirtualAddress and directory.Size:
                return "ada blok tanda tangan digital"
        except (AttributeError, IndexError, TypeError):
            pass
        return ""

    # ------------------------------------------------------------------ #

    def _score(self, result: PEAnalysis) -> None:
        """Hitung skor risiko dari semua petunjuk yang ditemukan.

        Prinsipnya: **deteksi butuh bukti**. Program biasa memakai banyak API
        Windows yang "terdengar berbahaya" (VirtualProtect, OpenProcess) untuk
        hal yang wajar, jadi petunjuk seperti itu sendirian hanya menghasilkan
        catatan, bukan tuduhan. Tingkat MENCURIGAKAN dan MALWARE hanya dicapai
        bila ada bukti kuat atau banyak petunjuk yang saling menguatkan.
        """
        strong_score = 0
        weak_score = 0
        notes = result.notes

        # --- Impor --------------------------------------------------------- #
        hits = [
            (*SUSPICIOUS_IMPORTS[name], name)
            for name in result.imports
            if name in SUSPICIOUS_IMPORTS
        ]
        strong_hits = [h for h in hits if h[2]]
        weak_hits = [h for h in hits if not h[2]]

        if strong_hits:
            strong_hits.sort(key=lambda h: h[0], reverse=True)
            strong_score += min(sum(h[0] for h in strong_hits[:6]), 60)
            for weight, explanation, _, name in strong_hits[:3]:
                notes.append(f"Impor {name}: {explanation}")
        if weak_hits:
            weak_hits.sort(key=lambda h: h[0], reverse=True)
            # Banyak petunjuk lemah yang muncul bersamaan tetap berarti, tetapi
            # sumbangannya dibatasi supaya tidak bisa menuduh sendirian.
            weak_score += min(sum(h[0] for h in weak_hits[:6]), 25)

        # --- Program yang dipadatkan --------------------------------------- #
        packed = False
        if result.packed_section_names:
            packed = True
            strong_score += 40
            notes.append(
                "Nama section pemadat dikenal: " + ", ".join(result.packed_section_names)
            )
        elif result.max_section_entropy >= ENTROPY_PACKED_THRESHOLD:
            packed = True
            strong_score += 30
            notes.append(
                f"Section dengan entropi {result.max_section_entropy:.2f}/8.00 "
                f"(isi hampir acak - kemungkinan dipadatkan atau dienkripsi)"
            )

        # --- Section yang bisa ditulis sekaligus dijalankan ---------------- #
        writable_executable = [
            s["name"] for s in result.sections if s["executable"] and s["writable"]
        ]
        if writable_executable:
            weak_score += 15
            notes.append(
                "Section yang bisa ditulis sekaligus dijalankan: "
                + ", ".join(writable_executable[:4])
            )

        # --- Jumlah section ------------------------------------------------ #
        # Ambangnya tinggi karena program yang dibuat alat modern (dan biner
        # hasil kompilasi silang) memang sering punya banyak section.
        if result.section_count > 20:
            weak_score += 10
            notes.append(f"Jumlah section tidak wajar ({result.section_count})")
        elif result.section_count == 0:
            weak_score += 10
            notes.append("Berkas PE tanpa section sama sekali")

        # --- Titik masuk di luar section kode ------------------------------ #
        if result.entry_section and not _section_is_executable(
            result.sections, result.entry_section
        ):
            strong_score += 20
            notes.append(
                f"Titik masuk program berada di section '{result.entry_section}' "
                f"yang bukan kode"
            )

        # --- Waktu kompilasi dimanipulasi ---------------------------------- #
        year = _year_of(result.timestamp)
        if year and (year < MIN_PLAUSIBLE_YEAR or year > 2100):
            weak_score += 15
            notes.append(f"Waktu kompilasi tidak masuk akal: {result.timestamp_text}")

        # --- Impor sangat sedikit untuk program sebesar ini ---------------- #
        if result.import_count <= 3 and result.section_count >= 3:
            strong_score += 20
            notes.append(
                f"Hanya {result.import_count} fungsi yang diimpor - terlalu sedikit "
                f"untuk program normal sebesar ini"
            )

        # --- Keterangan tambahan ------------------------------------------- #
        if result.is_dotnet:
            notes.append("Program .NET (kode terkelola)")
        if result.signature:
            notes.append("Ada tanda tangan digital")
            strong_score = max(strong_score - 15, 0)
            weak_score = max(weak_score - 10, 0)

        # Tanpa satu pun bukti kuat, skor dibatasi sehingga paling tinggi hanya
        # menghasilkan catatan PERLU DIPERIKSA. Inilah yang mencegah program
        # normal dituduh mencurigakan.
        if strong_score == 0:
            result.score = min(weak_score, 25)
        else:
            result.score = min(strong_score + weak_score, 100)
        result.packed = packed

    def scan_file(self, path: str) -> list[Finding]:
        """Ubah hasil analisis PE menjadi daftar temuan."""
        analysis = self.analyze(path)
        if not analysis.is_pe:
            return []
        if analysis.error:
            return [
                Finding(
                    path=path,
                    engine=ENGINE_PE,
                    rule="PE tidak terbaca",
                    detail=analysis.error,
                    severity=SEV_NOTE,
                )
            ]

        # Ambang lapor. Angka 25 dipilih dengan alasan: karena _score() membatasi
        # skor ke 25 bila tidak ada bukti kuat sama sekali, maka ambang ini
        # membuat "petunjuk lemah sendirian" hanya bisa menghasilkan catatan
        # PERLU DIPERIKSA - dan hanya bila petunjuknya terkumpul cukup banyak.
        # Program normal yang kebetulan memakai satu-dua API yang terdengar
        # berbahaya tidak akan muncul di laporan.
        findings = []
        if analysis.score >= 60:
            severity = SEV_MALWARE
        elif analysis.score >= 30:
            severity = SEV_SUSPICIOUS
        elif analysis.score >= 25:
            severity = SEV_NOTE
        else:
            return []

        findings.append(
            Finding(
                path=path,
                engine=ENGINE_PE,
                rule=f"Skor heuristik PE {analysis.score}/100",
                detail="; ".join(analysis.notes[:5])
                or "Struktur program tidak lazim",
                severity=severity,
            )
        )
        return findings


def _stamp_to_datetime(stamp: int):
    """Ubah penanda waktu PE menjadi datetime UTC, atau None bila tidak masuk akal."""
    if not stamp:
        return None
    import datetime

    try:
        return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _timestamp_text(stamp: int) -> str:
    moment = _stamp_to_datetime(stamp)
    return moment.strftime("%d-%m-%Y %H:%M UTC") if moment else "tidak ada"


def _year_of(stamp: int) -> int | None:
    moment = _stamp_to_datetime(stamp)
    return moment.year if moment else None


def _section_for_rva(pe, rva: int) -> str:
    for section in getattr(pe, "sections", []) or []:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < end:
            return section.Name.rstrip(b"\x00").decode("ascii", "replace")
    return ""


def _section_is_executable(sections: list[dict], name: str) -> bool:
    for section in sections:
        if section["name"] == name:
            return bool(section["executable"])
    return True
