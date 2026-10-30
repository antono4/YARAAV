# -*- mode: python ; coding: utf-8 -*-
"""Konfigurasi PyInstaller untuk ScanGuard.

Cara pakai:  python -m PyInstaller --noconfirm --clean ScanGuard.spec
Hasil     :  dist/ScanGuard.exe  (satu berkas, tanpa jendela hitam)

Berkas .spec dipakai agar hasil build selalu sama. Kalau ingin memakai perintah
langsung tanpa .spec, bentuknya:

    python -m PyInstaller --onefile --windowed --name ScanGuard ^
        --icon assets/icon.ico ^
        --add-data "assets;assets" --add-data "rules;rules" ^
        --hidden-import yara --hidden-import pefile antivirus.py

Perhatikan dua hal penting untuk program ini:

1. `--hidden-import yara` dan `--hidden-import pefile` **wajib**. Keduanya
   diimpor di dalam fungsi, bukan di bagian atas berkas, sehingga PyInstaller
   tidak bisa menemukannya sendiri. Tanpa baris itu, .exe akan jalan tetapi
   mesin YARA dan analisis PE diam-diam tidak aktif.
2. Folder `rules` harus ikut disalin, karena aturan YARA dibaca dari berkas
   saat program dijalankan.
3. Paket `scanguard.ai` diimpor seluruhnya. Model bahasa memakai `urllib` dari
   pustaka standar, jadi tidak ada pustaka tambahan yang perlu dibundel - tetapi
   modulnya sendiri tetap harus ikut, karena diimpor di dalam fungsi.
"""

import os

from PyInstaller.utils.hooks import collect_dynamic_libs

block_cipher = None

# Sertakan berkas data. Pasangan (sumber, folder tujuan) ditulis dengan
# os.path.join agar berkas ini tetap benar di Windows maupun saat diuji di Linux.
datas = [
    (os.path.join("assets", "icon.ico"), "assets"),
    (os.path.join("assets", "icon_256.png"), "assets"),
    (os.path.join("rules", "scanguard.yar"), "rules"),
]

binaries = []
hiddenimports = [
    # Modul AI diimpor di dalam fungsi (agar program tetap jalan bila ada bagian
    # yang hilang), sehingga PyInstaller tidak menemukannya sendiri.
    "scanguard.ai",
    "scanguard.ai.base",
    "scanguard.ai.analyst",
    "scanguard.ai.anomaly",
    "scanguard.ai.assistant",
    "scanguard.ai.cache",
    "scanguard.ai.privacy",
    # Mode latar belakang (--rtp) diimpor di dalam fungsi, karena program utama
    # tidak memakainya. Tanpa didaftarkan di sini, ScanGuard.exe --rtp akan
    # gagal di komputer pengguna walaupun jalan baik di kode sumber.
    "scanguard.background",
    "scanguard.autostart",
    # urllib dipakai untuk memanggil penyedia AI. Sebagian modulnya diimpor
    # secara dinamis oleh pustaka standar, jadi ikut didaftarkan.
    "urllib.request",
    "urllib.error",
    "json",
]

# --- yara-python ------------------------------------------------------------ #
# yara-python adalah modul C: ia memuat pustaka bersama (libyara). Pustaka itu
# harus ikut dibundel, kalau tidak mesin YARA gagal diimpor di komputer lain.
try:
    import yara  # noqa: F401

    hiddenimports.append("yara")
    binaries += collect_dynamic_libs("yara")
except ImportError:
    print("PERINGATAN: yara-python tidak terpasang. .exe akan dibuat tanpa mesin YARA.")

# --- pefile ----------------------------------------------------------------- #
try:
    import pefile  # noqa: F401

    hiddenimports.append("pefile")
except ImportError:
    print("PERINGATAN: pefile tidak terpasang. .exe akan dibuat tanpa analisis PE.")

a = Analysis(
    ["antivirus.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Pustaka besar yang tidak dipakai program ini - dibuang agar .exe kecil.
        "numpy", "pandas", "matplotlib", "scipy", "pytest", "setuptools",
        "pip", "unittest", "PIL", "cryptography",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="ScanGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX dimatikan: pemadatan UPX adalah penyebab paling umum .exe hasil
    # PyInstaller dituduh virus oleh antivirus lain.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=False supaya tidak ada jendela Command Prompt di belakang GUI.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join("assets", "icon.ico"),
)
