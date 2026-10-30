"""Skrip bantu: buka GUI, pindai folder contoh, lalu simpan tangkapan layar.

Dipakai untuk memverifikasi tampilan dan untuk membuat gambar README. Skrip ini
memeriksa dua hal yang sulit dilihat dengan mata: apakah tombol terpotong, dan
apakah warna per tingkat bahaya benar-benar muncul di layar (dihitung dari
piksel, bukan dikira-kira).

Hasilnya empat berkas gambar: jendela utama pada posisi log paling bawah, jendela
utama pada posisi paling atas, jendela Asisten AI, dan jendela Pengaturan.

Jalankan:
    xvfb-run -a --server-args="-screen 0 1100x760x24" \\
        python3 tools/screenshot.py <folder> docs

Di komputer biasa (ada layar) cukup:
    python3 tools/screenshot.py <folder> docs
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


def _grab(path: str, window=None) -> None:
    """Simpan tangkapan layar, lalu pangkas tepat sebesar jendelanya.

    `import -window root` menangkap seluruh layar virtual. Tanpa dipangkas,
    gambar berisi tepi hitam selebar selisih antara ukuran jendela dan ukuran
    layar maya - terlihat seperti gambar rusak, dan membuat teks lebih kecil
    daripada seharusnya ketika ditampilkan di README.
    """
    subprocess.run(["import", "-window", "root", path], check=True)
    if window is None:
        return
    try:
        from PIL import Image

        lebar, tinggi = window.winfo_width(), window.winfo_height()
        if lebar > 1 and tinggi > 1:
            with Image.open(path) as image:
                image.convert("RGB").crop((0, 0, lebar, tinggi)).save(path)
    except ImportError:
        pass


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
    # `out` boleh berupa folder (untuk README) atau nama berkas .png (untuk
    # pemeriksaan cepat). Nama berkasnya ditentukan dari bentuk yang diberikan.
    if os.path.splitext(out)[1]:
        base, ext = os.path.splitext(out)
        target_dir = os.path.dirname(base) or "."
        names = {
            "bawah": os.path.basename(base) + ext,
            "atas": os.path.basename(base) + "-atas" + ext,
        }
    else:
        target_dir = out
        names = {
            "bawah": "tangkapan-jendela-utama.png",
            "atas": "tangkapan-jendela-utama-atas.png",
        }
    os.makedirs(target_dir, exist_ok=True)

    captures = []
    for label, position in (("bawah", "end"), ("atas", "1.0")):
        app.log.see(position)
        root.update()
        time.sleep(0.3)
        target_path = os.path.join(target_dir, names[label])
        _grab(target_path, app.root)
        captures.append((label, target_path))
        print(f"tangkapan layar ({label}) disimpan: {target_path}")

    # --- Jendela Asisten AI -------------------------------------------------- #
    # Dibuka setelah pemindaian selesai supaya bahan jawabannya sudah ada.
    asisten = dialogs.AssistantWindow(root, app)
    root.update()
    asisten.ask("kenapa berkas saya ditandai?")
    root.update()
    time.sleep(0.4)
    asisten_path = os.path.join(target_dir, "tangkapan-asisten-ai.png")
    _grab(asisten_path, asisten)
    print(f"tangkapan layar (asisten AI) disimpan: {asisten_path}")
    asisten.destroy()
    root.update()

    # --- Jendela Pengaturan -------------------------------------------------- #
    pengaturan = dialogs.SettingsWindow(root, app)
    root.update()
    # Gulir ke bawah supaya bagian kecerdasan buatan terlihat. Bagian itu ada di
    # paling bawah jendela, jadi tanpa digulir gambar hanya menampilkan kunci
    # MalwareBazaar - dan pembaca tidak melihat ada kemampuan AI sama sekali.
    pengaturan.scroll_area.canvas.yview_moveto(1.0)
    root.update()
    time.sleep(0.4)
    pengaturan_path = os.path.join(target_dir, "tangkapan-pengaturan.png")
    _grab(pengaturan_path, pengaturan)
    print(f"tangkapan layar (pengaturan) disimpan: {pengaturan_path}")
    pengaturan.destroy()
    root.update()

    # --- Hitung piksel per warna tingkat bahaya ------------------------------ #
    # Warna yang benar-benar dirender muncul puluhan piksel; warna yang tidak
    # pernah dipakai muncul nol. Ini membuktikan warna, bukan sekadar mengira.
    try:
        from PIL import Image

        # Jendela yang gagal tergambar menghasilkan gambar nyaris satu warna.
        # Angka ini menangkapnya; mata bisa saja tidak menyadarinya di layar kecil.
        print("--- keragaman warna tiap gambar ---")
        for label, path in [
            ("utama bawah", captures[0][1]),
            ("utama atas", captures[1][1]),
            ("asisten AI", asisten_path),
            ("pengaturan", pengaturan_path),
        ]:
            image = Image.open(path).convert("RGB")
            jumlah = len(set(image.get_flattened_data()))
            status = "OK" if jumlah > 200 else "MENCURIGAKAN - gambar hampir satu warna"
            print(f"  {label:<12} {jumlah:>6} warna berbeda   {status}")

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
