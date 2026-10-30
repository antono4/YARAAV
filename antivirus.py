"""Titik masuk ScanGuard.

Berkas ini sengaja tipis. Tugasnya hanya menyiapkan penanganan kesalahan darurat
dan memanggil antarmuka utama. Seluruh logika ada di paket `scanguard/`.

Cara menjalankan dari kode sumber:
    python antivirus.py

Cara membuat .exe: lihat build_exe.bat atau README.md.
"""

from __future__ import annotations

import os
import sys


def _fatal(message: str) -> None:
    """Tampilkan kesalahan sebelum jendela sempat terbuka.

    Kesalahan seperti pustaka tkinter tidak terpasang harus terlihat jelas,
    bukan jendela yang langsung menutup tanpa penjelasan apa pun.
    """
    sys.stderr.write(message + "\n")
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("ScanGuard tidak bisa dijalankan", message)
        root.destroy()
    except Exception:  # noqa: BLE001 - bila tkinter pun tidak ada, cukup dicetak
        pass


def _check_engines() -> int:
    """Periksa mesin deteksi tanpa membuka jendela, lalu cetak hasilnya.

    Berguna untuk memastikan hasil build .exe benar-benar lengkap: kalau mesin
    YARA atau analisis PE gagal ikut terbungkus, masalah itu akan terlihat di
    sini - bukan baru ketahuan saat pengguna memindai folder.

    Jalankan:  ScanGuard.exe --cek-mesin
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scanguard.config import APP_NAME, APP_VERSION, data_dir, default_rules_path
    from scanguard.scanner import ScanEngine

    print(f"{APP_NAME} {APP_VERSION}")
    print(f"Folder data : {data_dir()}")
    print(f"Berkas aturan: {default_rules_path()}")
    print()

    engine = ScanEngine()
    report = engine.prepare()
    problems = 0
    for item in report["engines"]:
        status = "siap" if item["ok"] else "TIDAK SIAP"
        print(f"[{status}] {item['name']}")
        print(f"          {item['message']}")
        if not item["ok"]:
            problems += 1
    print()
    problems += _check_ai()
    print()
    if problems:
        print(f"{problems} bagian tidak siap. Program tetap bisa jalan, tetapi")
        print("deteksinya berkurang. Lihat keterangan di atas.")
    else:
        print("Semua mesin siap dipakai.")
    return 0 if problems == 0 else 2



def _check_ai() -> int:
    """Periksa bagian kecerdasan buatan, cetak hasilnya, kembalikan jumlah masalah.

    Deteksi anomali diuji sungguhan dengan berkas kecil yang dibuat sementara,
    supaya hasilnya membuktikan modelnya benar-benar bisa dilatih di komputer
    ini - bukan sekadar "modulnya bisa diimpor".
    """
    import tempfile

    problems = 0

    # --- Deteksi anomali (lokal, tanpa internet) --------------------------- #
    try:
        from scanguard.ai.anomaly import MIN_FILES, find_anomalies
    except ImportError as error:
        print("[TIDAK SIAP] AI: deteksi anomali")
        print(f"          Modul tidak bisa diimpor: {error}")
        return 1

    try:
        with tempfile.TemporaryDirectory() as folder:
            for index in range(MIN_FILES + 2):
                with open(os.path.join(folder, f"dokumen{index}.txt"), "w") as handle:
                    handle.write("catatan biasa\n" * 40)
            berkas = [
                os.path.join(folder, name) for name in sorted(os.listdir(folder))
            ]
            hasil = find_anomalies(berkas)
        print("[siap] AI: deteksi anomali")
        print(
            f"          Model lokal berjalan. Diuji pada {len(berkas)} berkas "
            f"serupa, {len(hasil)} ditandai menyimpang (benar: tidak ada)."
        )
    except Exception as error:  # noqa: BLE001 - apa pun harus terlihat
        print("[TIDAK SIAP] AI: deteksi anomali")
        print(f"          Gagal dilatih: {error}")
        problems += 1

    # --- Model bahasa ------------------------------------------------------ #
    try:
        from scanguard.ai.base import PROVIDERS, build_client_from_settings
        from scanguard.settings import Settings
    except ImportError as error:
        print("[TIDAK SIAP] AI: model bahasa")
        print(f"          Modul tidak bisa diimpor: {error}")
        return problems + 1

    settings = Settings.load()
    client = build_client_from_settings(settings)
    print("[siap] AI: model bahasa")
    if client.ready:
        print(f"          Siap dipakai: {client.describe()}")
    else:
        # Ini bukan masalah: fitur ini memang opsional dan bawaannya mati.
        print(
            f"          Belum diaktifkan ({PROVIDERS[client.provider]['label']}). "
            "Isi di Pengaturan > Kecerdasan Buatan,"
        )
        print(
            "          atau pakai Ollama agar model berjalan di komputer sendiri "
            "tanpa biaya."
        )
    return problems

def main() -> int:
    # Izinkan menjalankan langsung dari folder proyek tanpa memasang paket.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    if "--cek-mesin" in sys.argv or "--self-test" in sys.argv:
        return _check_engines()

    try:
        import tkinter  # noqa: F401
    except ImportError:
        _fatal(
            "tkinter tidak terpasang.\n\n"
            "Di Windows: pasang ulang Python dari python.org (tkinter sudah "
            "termasuk di dalamnya).\n"
            "Di Linux: sudo apt install python3-tk"
        )
        return 1

    try:
        from scanguard.gui import main as gui_main
    except ImportError as error:
        _fatal(
            "Ada bagian program yang tidak lengkap.\n\n"
            f"Keterangan: {error}\n\n"
            "Pastikan folder 'scanguard' dan 'rules' berada di samping berkas ini."
        )
        return 1

    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
