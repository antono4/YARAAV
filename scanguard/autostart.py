"""Mulai otomatis saat Windows menyala.

Menambahkan satu nilai di registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
supaya ScanGuard dijalankan lagi setiap kali pengguna masuk ke Windows.

HKCU dipakai, bukan HKLM, karena menulis ke HKLM butuh hak administrator. Program
antivirus yang meminta hak administrator hanya untuk memasang dirinya sendiri akan
ditolak pengguna - dengan alasan yang benar. HKCU tidak butuh hak istimewa apa
pun, dan hanya berlaku untuk pengguna yang memasangnya.

Berkas ini tidak melakukan apa pun di Linux atau macOS: registry Windows tidak ada
di sana, jadi setiap fungsi mengembalikan "tidak didukung" tanpa melempar
kesalahan. Program tetap bisa jalan seperti biasa, hanya fitur ini yang tidak
tersedia.
"""

from __future__ import annotations

import os
import sys

from .config import APP_NAME, project_root

# Lokasi nilai di registry. Disimpan sebagai satu nilai bernama APP_NAME di bawah
# kunci Run milik pengguna saat ini.
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = APP_NAME
ARGUMEN_PANTAU = "--rtp"


def is_supported() -> bool:
    """Apakah sistem ini punya registry Windows."""
    return os.name == "nt"


def launch_command() -> str:
    """Perintah yang dijalankan Windows saat pengguna masuk.

    Selalu memakai opsi --rtp: yang perlu berjalan di latar belakang hanya
    pemantauannya, bukan jendela penuh. Tanpa opsi itu, program akan membuka
    jendela lebar setiap kali pengguna menyalakan komputer.
    """
    if getattr(sys, "frozen", False):
        # Sudah berupa .exe: perintahnya adalah berkas itu sendiri.
        return f'"{sys.executable}" {ARGUMEN_PANTAU}'
    # Dijalankan dari kode sumber. pythonw.exe dipakai, bukan python.exe, supaya
    # tidak ada jendela hitam yang ikut terbuka.
    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        exe = exe[: -len("python.exe")] + "pythonw.exe"
    skrip = os.path.join(project_root(), "antivirus.py")
    return f'"{exe}" "{skrip}" {ARGUMEN_PANTAU}'


def is_enabled() -> bool:
    """Apakah ScanGuard sudah terdaftar untuk mulai otomatis."""
    if not is_supported():
        return False
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as kunci:
            nilai, _tipe = winreg.QueryValueEx(kunci, VALUE_NAME)
            return bool(nilai)
    except FileNotFoundError:
        # Kunci atau nilainya belum ada: belum pernah dinyalakan.
        return False
    except OSError:
        # Registry tidak bisa dibaca (kebijakan sistem, profil rusak). Dianggap
        # belum aktif, bukan gagal keras.
        return False


def enable() -> tuple[bool, str]:
    """Daftarkan ScanGuard agar mulai otomatis. Kembalikan (berhasil, pesan)."""
    if not is_supported():
        return False, "Mulai otomatis hanya tersedia di Windows."
    perintah = launch_command()
    try:
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as kunci:
            winreg.SetValueEx(kunci, VALUE_NAME, 0, winreg.REG_SZ, perintah)
    except OSError as error:
        return False, f"Tidak bisa menulis ke registry: {error}"
    return True, f"ScanGuard akan mulai otomatis saat Anda masuk ke Windows.\n{perintah}"


def disable() -> tuple[bool, str]:
    """Hapus pendaftaran mulai otomatis. Kembalikan (berhasil, pesan)."""
    if not is_supported():
        return False, "Mulai otomatis hanya tersedia di Windows."
    try:
        import winreg

        try:
            kunci = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE
            )
        except FileNotFoundError:
            # Kunci Run-nya sendiri belum ada, jadi tidak ada yang perlu dihapus.
            # Ini bukan kegagalan: hasil akhirnya sama dengan berhasil.
            return True, "ScanGuard memang belum terdaftar untuk mulai otomatis."
        with kunci:
            try:
                winreg.DeleteValue(kunci, VALUE_NAME)
            except FileNotFoundError:
                return True, "ScanGuard memang belum terdaftar untuk mulai otomatis."
    except OSError as error:
        return False, f"Tidak bisa mengubah registry: {error}"
    return True, "ScanGuard tidak lagi mulai otomatis saat Anda masuk ke Windows."
