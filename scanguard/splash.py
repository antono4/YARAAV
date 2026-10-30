"""Layar pembuka yang tampil sebentar saat program dijalankan.

Tujuannya sederhana: memberi tahu pengguna bahwa program sedang bersiap, bukan
menggantung. Karena itu layar ini hanya berisi nama, versi, dan satu baris
keterangan - bukan animasi panjang yang justru memperlambat.

Layar ini tidak pernah menjadi jendela utama. Ia selalu ditutup sebelum
jendela utama dipakai, dan penutupannya aman dipanggil lebih dari sekali.
"""

from __future__ import annotations

import time
import tkinter as tk

from .config import APP_NAME, APP_TAGLINE, APP_VERSION

# Lama tampil paling singkat. Tanpa batas ini, di komputer cepat layar pembuka
# hanya berkedip satu bingkai, dan pengguna justru melihat sesuatu yang aneh.
MIN_VISIBLE_MS = 900

LEBAR = 460
TINGGI = 250


class SplashScreen:
    """Layar pembuka bergaya sama dengan jendela utama."""

    def __init__(self, parent: tk.Misc, colors: dict, minimum_ms: int = MIN_VISIBLE_MS) -> None:
        self.colors = colors
        self.minimum_ms = minimum_ms
        self._closed = False
        self._job: str | None = None
        self._start = time.monotonic()

        self.window = tk.Toplevel(parent)
        # Tanpa bingkai: layar pembuka bukan jendela kerja, jadi tombol tutup
        # dan bilah judul hanya mengganggu.
        self.window.overrideredirect(True)
        self.window.configure(bg=colors["panel"])
        self.window.attributes("-topmost", True)
        self._center(parent)

        isi = tk.Frame(self.window, bg=colors["panel"], padx=28, pady=24)
        isi.pack(fill="both", expand=True)

        tk.Label(
            isi,
            text=APP_NAME,
            bg=colors["panel"],
            # accent, bukan brand: brand (#ff6b00) hanya 2,86:1 di atas putih
            # dan hanya boleh dipakai untuk garis atau isian.
            fg=colors["accent"],
            font=("Segoe UI", 26, "bold"),
            anchor="w",
        ).pack(fill="x")

        # Garis tipis berwarna merek, seperti di panel kiri jendela utama.
        garis = tk.Frame(isi, bg=colors["brand"], height=3)
        garis.pack(fill="x", pady=(6, 10))

        tk.Label(
            isi,
            text=f"Versi {APP_VERSION}",
            bg=colors["panel"],
            fg=colors["text"],
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(fill="x")

        tk.Label(
            isi,
            text=APP_TAGLINE,
            bg=colors["panel"],
            fg=colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=LEBAR - 60,
        ).pack(fill="x", pady=(2, 0))

        self.status_var = tk.StringVar(value="Menyiapkan mesin pemindai...")
        tk.Label(
            isi,
            textvariable=self.status_var,
            bg=colors["panel"],
            fg=colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", pady=(14, 4))

        # Bilah bergerak, bukan bilah bertingkat: tahap persiapan tidak punya
        # jumlah langkah yang pasti, dan bilah bertingkat yang berhenti di 70%
        # terlihat seperti program macet.
        self.bar = tk.Frame(isi, bg=colors["trough"], height=6)
        self.bar.pack(fill="x")
        self.fill = tk.Frame(self.bar, bg=colors["brand"], height=6, width=0)
        self.fill.place(x=0, y=0, relheight=1.0)

        self._animate(0)
        # minimum_ms=0 berarti "jangan tutup sendiri" (dipakai alat tangkapan
        # layar). Menjadwalkan after(0) akan menutup jendela sebelum sempat
        # difoto.
        if self.minimum_ms > 0:
            self._schedule_close()

    # ------------------------------------------------------------------ -- #

    def _center(self, parent: tk.Misc) -> None:
        """Letakkan di tengah layar, bukan di tengah induknya.

        Induknya masih tersembunyi saat layar ini dibuat, jadi posisinya harus
        dihitung dari ukuran layar.
        """
        lebar_layar = parent.winfo_screenwidth()
        tinggi_layar = parent.winfo_screenheight()
        x = max(0, (lebar_layar - LEBAR) // 2)
        y = max(0, (tinggi_layar - TINGGI) // 2)
        self.window.geometry(f"{LEBAR}x{TINGGI}+{x}+{y}")

    def _animate(self, posisi: int) -> None:
        if self._closed:
            return
        try:
            lebar = self.bar.winfo_width()
        except tk.TclError:
            return
        if lebar <= 1:
            lebar = LEBAR - 56
        ubin = max(40, lebar // 4)
        langkah = 8
        geser = (posisi % (lebar + ubin + langkah)) - ubin
        self.fill.place_configure(x=geser, width=ubin)
        try:
            self._job = self.window.after(16, self._animate, posisi + langkah)
        except tk.TclError:
            pass

    def _schedule_close(self) -> None:
        """Tutup otomatis setelah waktu paling singkat.

        Jendela utama biasanya siap jauh lebih cepat. Menutup di sini membuat
        layar pembuka tidak pernah menggantung bila ada tahap persiapan yang
        gagal tanpa melempar kesalahan.
        """
        try:
            self.window.after(self.minimum_ms, self.close)
        except tk.TclError:
            pass

    def remaining_ms(self) -> int:
        """Sisa waktu tampil paling singkat, dalam milidetik."""
        sisa = self.minimum_ms - (time.monotonic() - self._start) * 1000
        return max(0, int(sisa))

    def set_status(self, teks: str) -> None:
        """Perbarui keterangan tahap persiapan yang sedang berjalan."""
        if self._closed:
            return
        try:
            self.status_var.set(teks)
        except tk.TclError:
            pass

    def close(self) -> None:
        """Tutup layar pembuka. Aman dipanggil berkali-kali."""
        if self._closed:
            return
        self._closed = True
        if self._job is not None:
            try:
                self.window.after_cancel(self._job)
            except (tk.TclError, ValueError):
                pass
            self._job = None
        try:
            self.window.destroy()
        except tk.TclError:
            pass
