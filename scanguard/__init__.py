"""ScanGuard - pemindai malware berbasis mesin jamak untuk tujuan belajar.

Isi paket ini:
    config        - konstanta dan lokasi berkas
    core          - struktur data dan fungsi bantu (hash, entropi, ukuran)
    hashes        - basis data hash malware (SQLite) dan pembaruannya
    yara_engine   - pencocokan pola dengan aturan YARA
    pe_engine     - analisis struktur program Windows (PE)
    clamav_engine - integrasi ClamAV (opsional)
    quarantine    - karantina aman dengan pemulihan
    scanner       - orkestrator yang menyatukan semua mesin
    report        - penyusun laporan teks
    settings      - pengaturan pengguna
    dialogs       - jendela pengaturan, pembaruan, dan karantina
    gui           - antarmuka utama tkinter
"""

from .config import APP_NAME, APP_VERSION

__all__ = ["APP_NAME", "APP_VERSION"]
