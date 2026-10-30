"""Skrip bantu: buka GUI, pindai folder contoh, lalu simpan tangkapan layar.

Dipakai untuk memverifikasi tampilan, bukan bagian dari aplikasi. Skrip ini
memeriksa dua hal yang sulit dilihat dengan mata: apakah tombol terpotong, dan
apakah warna per tingkat bahaya benar-benar muncul di layar (dihitung dari
piksel, bukan dikira-kira).

Jalankan:
    xvfb-run -a --server-args="-screen 0 1200x820x24" \\
        python3 tools/screenshot.py <folder> <keluaran.png>

Di komputer biasa (ada layar) cukup:
    python3 tools/screenshot.py <folder> <keluaran.png>
"""

import os
import subprocess
import sys
import time
import tkinter as tk
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanguard import dialogs, gui  # noqa: E402

# Kotak dialog bersifat modal: di lingkungan tanpa layar ia menunggu klik yang
# tidak akan datang, sehingga skrip ini menggantung tanpa pesan. Diganti di sini;
# logika aplikasinya tetap yang asli.
_dialog = mock.Mock()
# askyesno harus mengembalikan False secara eksplisit. Objek Mock dianggap
# bernilai True, sehingga penawaran karantina akan dijawab "ya" dan berkas uji
# dipindahkan ke karantina - folder contoh jadi kosong di tangkapan layar
# berikutnya. Skrip ini hanya untuk melihat tampilan, jadi tidak boleh mengubah
# berkas apa pun.
_dialog.askyesno.return_value = False
mock.patch.object(gui, "messagebox", _dialog).start()
mock.patch.object(dialogs, "messagebox", _dialog).start()


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    folder, out = sys.argv[1], sys.argv[2]

    root = tk.Tk()
    app = gui.ScanGuardApp(root)
    app.folder_var.set(folder)
    root.update()

    # Pindai dijalankan setelah jendela benar-benar tergambar.
    root.after(300, app.start_scan)

    deadline = time.time() + 300
    while time.time() < deadline:
        root.update()
        if not app.scanning and app.last_summary is not None:
            break
        time.sleep(0.05)
    root.update()
    time.sleep(0.4)  # beri waktu pengelola jendela menggambar ulang

    # --- Periksa tata letak -------------------------------------------------- #
    print("--- tata letak ---")
    for name, widget in (
        ("Pilih Folder", app.choose_btn),
        ("Mulai Pindai", app.scan_btn),
        ("Hentikan", app.stop_btn),
    ):
        required, actual = widget.winfo_reqwidth(), widget.winfo_width()
        state = "OK" if actual >= required else "TERPOTONG"
        print(f"  {name:<14} lebar diminta={required:<4} aktual={actual:<4} {state}")

    # --- Periksa warna yang benar-benar dipakai di log ----------------------- #
    print("--- tag warna yang dipakai di log ---")
    used: set[str] = set()
    last_line = int(app.log.index("end-1c").split(".")[0])
    for line in range(1, last_line + 1):
        used |= set(app.log.tag_names(f"{line}.0"))
    print("  ", sorted(used))

    expected = set(gui.SEVERITY_TAGS.values())
    missing = expected - used
    if missing:
        print("   tag yang belum terpakai:", sorted(missing))

    # --- Simpan tangkapan layar --------------------------------------------- #
    # Dua kali: di posisi tergulir bawah (temuan terbaru) dan di posisi atas
    # (temuan pertama). Perlu keduanya, karena log otomatis menggulir ke bawah
    # sehingga temuan di awal tidak terlihat pada tangkapan layar pertama.
    base, ext = os.path.splitext(out)
    top_out = f"{base}-atas{ext or '.png'}"

    captures = []
    for label, position in (("bawah", "end"), ("atas", "1.0")):
        app.log.see(position)
        root.update()
        time.sleep(0.3)
        target_path = out if label == "bawah" else top_out
        subprocess.run(["import", "-window", "root", target_path], check=True)
        captures.append((label, target_path))
        print(f"tangkapan layar ({label}) disimpan: {target_path}")

    # --- Hitung piksel per warna tingkat bahaya ------------------------------ #
    # Warna yang benar-benar dirender muncul puluhan piksel; warna yang tidak
    # pernah dipakai muncul nol. Ini membuktikan warna, bukan sekadar mengira.
    try:
        from PIL import Image

        print("--- jumlah piksel per warna tingkat bahaya ---")
        for label, path in captures:
            image = Image.open(path).convert("RGB")
            pixels = list(image.get_flattened_data())
            print(f"  [{label}] {path}")
            for name, hex_color in (
                ("MALWARE (merah)", gui.COLORS["danger"]),
                ("MENCURIGAKAN (kuning)", gui.COLORS["warn"]),
                ("PERLU DIPERIKSA (biru)", gui.COLORS["note"]),
                ("bersih (hijau)", gui.COLORS["ok"]),
            ):
                target = tuple(
                    int(hex_color.lstrip("#")[i : i + 2], 16) for i in (0, 2, 4)
                )
                count = sum(1 for pixel in pixels if pixel == target)
                mark = "" if count else "   <- tidak terlihat di posisi ini"
                print(f"    {name:<26} {hex_color}  {count} piksel{mark}")
    except ImportError:
        print("(Pillow tidak terpasang - penghitungan piksel dilewati)")

    root.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main())
