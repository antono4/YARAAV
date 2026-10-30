"""Skrip bantu: buat folder contoh berisi berkas uji untuk tangkapan layar.

Semua berkas yang dibuat di sini **tidak berbahaya**. Yang ditulis hanyalah teks
yang kebetulan cocok dengan aturan YARA bawaan ScanGuard, ditambah berkas kecil
dengan entropi tinggi. Tujuannya supaya tangkapan layar README menampilkan
keadaan yang nyata - ketiga tingkat bahaya benar-benar muncul karena mesin
memang mendeteksinya, bukan karena lognya disunting.

Berkas karantina/EICAR tidak dibuat. Berkas EICAR akan langsung ditolak
antivirus yang berjalan di komputer, sehingga skrip ini gagal separuh jalan
tanpa alasan yang jelas bagi pemakainya.

Jalankan:
    python3 tools/make_demo_folder.py <folder>
"""

from __future__ import annotations

import os
import random
import sys


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    folder = sys.argv[1]
    os.makedirs(folder, exist_ok=True)

    # --- Dokumen biasa: jadi pembanding bagi deteksi anomali ---------------- #
    dokumen = os.path.join(folder, "Dokumen")
    os.makedirs(dokumen, exist_ok=True)
    for index in range(14):
        _write_text(
            os.path.join(dokumen, f"catatan-rapat-{index:02d}.txt"),
            "Laporan bulanan divisi operasional.\n"
            "Agenda rapat, daftar hadir, dan tindak lanjut.\n"
            "Tidak ada berkas terlampir.\n" * 12,
        )

    # --- MALWARE: perilaku khas ransomware (aturan YARA) -------------------- #
    _write_text(
        os.path.join(folder, "update_aman.bat"),
        "@echo off\r\n"
        "rem Skrip contoh untuk tangkapan layar - tidak berbahaya\r\n"
        "vssadmin delete shadows /all /quiet\r\n"
        "bcdedit /set recoveryenabled no\r\n",
    )
    _write_text(
        os.path.join(folder, "BACA_INI_PENTING.txt"),
        "All your files are encrypted.\n"
        "To decrypt your files, send bitcoin to the bitcoin address below.\n"
        "Do not rename any file.\n",
    )

    # --- MENCURIGAKAN: PowerShell tersembunyi (aturan YARA) ----------------- #
    _write_text(
        os.path.join(folder, "sinkronisasi.bat"),
        "@echo off\r\n"
        "rem Skrip contoh untuk tangkapan layar - tidak berbahaya\r\n"
        "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==\r\n",
    )

    # --- MENCURIGAKAN: perintah jahat yang disandikan (mesin dekode) -------- #
    # Perintah di dalam berkas ini tidak pernah muncul sebagai teks, karena
    # dipadatkan lalu di-base64. Aturan YARA tidak bisa menemukannya; hanya
    # mesin dekode yang bisa, karena ia membongkar penyandiannya lebih dulu.
    import base64 as _base64
    import gzip as _gzip

    tersembunyi = _base64.b64encode(
        _gzip.compress(
            b"vssadmin delete shadows /all /quiet\r\n"
            b"bcdedit /set recoveryenabled no\r\n"
            b"wbadmin delete catalog -quiet\r\n"
        )
    ).decode()
    _write_text(
        os.path.join(folder, "pembaruan-sistem.bat"),
        "@echo off\r\n"
        "rem Skrip contoh untuk tangkapan layar - tidak berbahaya\r\n"
        "set DATA=" + tersembunyi + "\r\n"
        "echo %DATA% | powershell -Command -\r\n",
    )

    # --- PERLU DIPERIKSA: nama berkas berkedok ganda ------------------------ #
    _write_text(
        os.path.join(folder, "faktur-2026.pdf.exe"),
        "Program contoh untuk tangkapan layar. Isinya hanya teks biasa.\n",
    )

    # --- PERLU DIPERIKSA: berkas kecil berentropi tinggi -------------------- #
    # Berkas acak seperti ini juga menyimpang dari dokumen di sekitarnya, jadi
    # deteksi anomali akan menyorotnya. Itu memang perilaku yang ingin
    # diperlihatkan di tangkapan layar.
    random.seed(7)
    with open(os.path.join(folder, "cache-biner.dat"), "wb") as handle:
        handle.write(bytes(random.randrange(256) for _ in range(200_000)))

    # --- PERLU DIPERIKSA: berkas program yang jauh lebih besar dari wajar --- #
    # Akhiran harus berupa akhiran program: mesin "Nama & ukuran" hanya mencatat
    # ukuran besar untuk berkas yang memang program, karena berkas data besar
    # (video, basis data) adalah hal yang lumrah.
    random.seed(5)
    with open(os.path.join(folder, "arsip-cadangan.exe"), "wb") as handle:
        handle.write(bytes(random.randrange(256) for _ in range(21 * 1024 * 1024)))

    print(f"Folder contoh dibuat di: {folder}")
    for root, _dirs, files in os.walk(folder):
        for name in sorted(files):
            path = os.path.join(root, name)
            print(f"  {os.path.relpath(path, folder):<34} {os.path.getsize(path):>9,} byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
