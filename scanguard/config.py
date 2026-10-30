"""Konstanta dan lokasi berkas untuk mesin pemindai ScanGuard."""

from __future__ import annotations

import os
import sys

APP_NAME = "ScanGuard"
APP_VERSION = "2.0.0"
APP_TAGLINE = "Mesin pemindai multi-engine: hash, YARA, PE, dekode muatan, dan ClamAV"

# --- Tingkat bahaya -------------------------------------------------------- #
SEV_MALWARE = "MALWARE"
SEV_SUSPICIOUS = "MENCURIGAKAN"
SEV_NOTE = "PERLU DIPERIKSA"

SEVERITY_ORDER = {SEV_MALWARE: 0, SEV_SUSPICIOUS: 1, SEV_NOTE: 2}

# Nama tag pada widget tkinter.Text tidak boleh mengandung spasi: Tk akan
# memecahnya menjadi beberapa tag dan warnanya tidak terpakai.
SEVERITY_TAGS = {
    SEV_MALWARE: "sev_malware",
    SEV_SUSPICIOUS: "sev_suspicious",
    SEV_NOTE: "sev_note",
}
TAG_INFO = "info"
TAG_OK = "ok"

# --- Nama mesin ------------------------------------------------------------ #
ENGINE_HASH = "Hash SHA-256"
ENGINE_YARA = "YARA"
ENGINE_PE = "Analisis PE"
ENGINE_CLAMAV = "ClamAV"
ENGINE_NAME = "Nama & ukuran"
ENGINE_AI = "AI: deteksi anomali"
ENGINE_DECODE = "Dekode muatan"

# --- Batas pemindaian ------------------------------------------------------ #
# Hanya bagian awal berkas yang dibaca untuk pencarian pola teks dan analisis
# PE. Berkas berukuran gigabyte tidak mungkin dibaca seluruhnya, dan header PE
# selalu berada di bagian awal.
MAX_READ_BYTES = 16 * 1024 * 1024  # 16 MB
# Batas ukuran berkas yang dihitung hash-nya: berkas raksasa (mis. image disk)
# membuat pemindaian lambat tanpa manfaat.
MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB
BIG_FILE_BYTES = 20 * 1024 * 1024  # 20 MB
ENTROPY_PACKED_THRESHOLD = 7.2

# --- Mesin dekode (pembongkar penyandian) ---------------------------------- #
# Batas-batas ini bukan hiasan. Berkas yang dibuat khusus untuk menggembungkan
# memori (zip bomb) atau untuk memaksa pemindai bekerja tanpa henti bisa membuat
# program mati, dan pemindai yang mati lebih buruk daripada pemindai yang
# melewatkan satu berkas.
#
# Batas baca lebih kecil daripada MAX_READ_BYTES: hasil dekode hampir selalu
# berada di bagian awal berkas, sedangkan pencarian pola pada 16 MB sekaligus
# membuat satu berkas memakan waktu lama.
DECODE_MAX_READ_BYTES = 8 * 1024 * 1024
# Panjang terpendek rangkaian yang dianggap kandidat. Terlalu pendek berarti
# setiap kata biasa ikut diuji dan pemindaian penuh kebisingan.
DECODE_MIN_CANDIDATE = 24
# Paling banyak hasil dekode yang diperiksa per berkas.
DECODE_MAX_CANDIDATES = 60
# Paling banyak lapis penyandian yang dibongkar. Base64 di dalam gzip di dalam
# base64 sudah tiga lapis; lebih dari ini hampir selalu berkas yang sengaja
# dibuat untuk memperlambat pemindai.
DECODE_MAX_DEPTH = 3
# Batas ukuran satu hasil dekode. Satu berkas kecil bisa memuai menjadi
# gigabytes tanpa batas ini.
DECODE_MAX_RESULT_BYTES = 8 * 1024 * 1024
# --- Perlindungan waktu nyata (RTP) --------------------------------------- #
# Batas jumlah folder pantauan. Setiap folder menambah satu penelusuran penuh
# setiap putaran, jadi menambah banyak folder membuat pemantauan makin berat.
MAX_WATCHED_FOLDERS = 8

# Waktu maksimal untuk satu berkas. Berkas aneh (mis. named pipe atau berkas
# jaringan yang menggantung) bisa memblokir; tanpa batas ini pemindaian tidak
# pernah selesai.
FILE_TIMEOUT_SECONDS = 60.0

EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp",
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".hta", ".jar", ".py", ".pyw", ".sh", ".apk",
        ".docm", ".xlsm", ".pptm", ".rtf",
    }
)
EXECUTABLE_EXTENSIONS_BARE = frozenset(e.lstrip(".") for e in EXECUTABLE_EXTENSIONS)

DISGUISE_EXTENSIONS = frozenset(
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
        ".gif", ".txt", ".mp3", ".mp4", ".zip", ".rar", ".csv",
    }
)

SKIP_DIR_NAMES = frozenset(
    {"$recycle.bin", "system volume information", "__pycache__", ".git"}
)


def data_dir() -> str:
    """Folder untuk data yang bertahan: basis data hash, karantina, aturan.

    Di Windows dipakai %LOCALAPPDATA%, di Linux/macOS dipakai ~/.local/share.
    Program yang dipasang di Program Files tidak boleh menulis ke folder
    sendiri, jadi data selalu ditaruh di folder milik pengguna.
    """
    override = os.environ.get("SCANGUARD_DATA_DIR")
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, APP_NAME)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return os.path.join(base, APP_NAME)


def project_root() -> str:
    """Folder yang berisi aset/ dan rules/ - di bundel .exe atau di kode sumber."""
    # PyInstaller mode --onefile mengekstrak berkas data ke folder sementara
    # yang ditunjuk sys._MEIPASS.
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        return bundle
    # Dijalankan dari kode sumber: config.py ada di <proyek>/scanguard/, jadi
    # folder proyek adalah satu tingkat di atasnya.
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_path(relative: str) -> str:
    """Lokasi berkas bawaan, baik dijalankan dari kode maupun dari .exe.

    Diperiksa di dua tempat: di dalam bundel (mode .exe) dan di folder proyek
    (mode kode sumber). Tanpa pemeriksaan kedua, ikon dan aturan tidak ditemukan
    saat program dijalankan langsung dengan `python antivirus.py`.
    """
    candidates = [
        os.path.join(project_root(), relative),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), relative),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def default_rules_path() -> str:
    """Cari berkas aturan YARA bawaan: di dalam bundel atau di folder proyek."""
    candidates = [
        resource_path(os.path.join("rules", "scanguard.yar")),
        os.path.normpath(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..", "rules", "scanguard.yar"
            )
        ),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[1]


def ensure_data_dir() -> str:
    path = data_dir()
    os.makedirs(path, exist_ok=True)
    return path
