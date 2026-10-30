"""Ikon menu, digambar sebagai vektor di atas tk.Canvas.

Ikon digambar, bukan disimpan sebagai berkas gambar, karena dua alasan:

1. Emoji tidak dipakai sama sekali. Di Windows yang tidak punya font emoji,
   emoji tampil sebagai kotak kosong - ikon yang rusak lebih buruk daripada
   tidak ada ikon.
2. Berkas PNG akan menambah Pillow sebagai kebutuhan saat program dijalankan.
   Pillow sekarang hanya dipakai alat bantu pembuatan ikon, dan itu disengaja:
   membawanya ke dalam `.exe` menambah ukuran tanpa manfaat.

Semua ikon digambar di kotak 16x16 dengan garis setebal 1,6 px, sehingga
ketebalannya seragam di seluruh menu. Warna garis diisi pemanggil, supaya ikon
bisa mengikuti warna menu biasa maupun warna sorotan menu aktif.
"""

from __future__ import annotations

import tkinter as tk

# Kotak gambar 16x16, tetapi canvas-nya 2 px lebih besar dan gambarnya digeser
# 1 px. Tanpa margin ini, ujung garis yang paling luar menyentuh tepi canvas dan
# terpotong setengah - terlihat sebagai ikon yang penyok.
GAMBAR = 16
MARGIN = 2
UKURAN = GAMBAR + MARGIN * 2
TEBAL = 1.6


def _garis(canvas: tk.Canvas, warna: str, titik: list[float]) -> None:
    canvas.create_line(
        *titik,
        fill=warna,
        width=TEBAL,
        capstyle="round",
        joinstyle="round",
    )


def _oval(canvas: tk.Canvas, warna: str, x0: float, y0: float, x1: float, y1: float) -> None:
    canvas.create_oval(
        x0, y0, x1, y1, outline=warna, width=TEBAL
    )


def _busur(
    canvas: tk.Canvas, warna: str, x0: float, y0: float, x1: float, y1: float, awal: float, akhir: float
) -> None:
    canvas.create_arc(
        x0,
        y0,
        x1,
        y1,
        start=awal,
        extent=akhir,
        style="arc",
        outline=warna,
        width=TEBAL,
    )


def _beranda(canvas: tk.Canvas, warna: str) -> None:
    """Rumah: atap segitiga dan badan kotak."""
    _garis(canvas, warna, [2, 7.5, 8, 2.5, 14, 7.5])
    _garis(canvas, warna, [4, 7, 4, 13.5, 12, 13.5, 12, 7])
    # Pintu, supaya bentuknya terbaca sebagai rumah dan bukan segi lima.
    _garis(canvas, warna, [7, 13.5, 7, 10.5, 9, 10.5, 9, 13.5])


def _pindai(canvas: tk.Canvas, warna: str) -> None:
    """Kaca pembesar."""
    _oval(canvas, warna, 2, 2, 11, 11)
    _garis(canvas, warna, [9.8, 9.8, 14, 14])


def _karantina(canvas: tk.Canvas, warna: str) -> None:
    """Kotak arsip: tutup dan badan."""
    _garis(canvas, warna, [2, 5.5, 14, 5.5])
    _garis(canvas, warna, [2.8, 5.5, 2.8, 13.5, 13.2, 13.5, 13.2, 5.5])
    # Gagang kecil di tengah badan.
    _garis(canvas, warna, [6.5, 9, 9.5, 9])


def _perlindungan(canvas: tk.Canvas, warna: str) -> None:
    """Perisai dengan denyut: dua busur dan satu titik pusat."""
    _garis(canvas, warna, [8, 2, 13, 4.5, 13, 8.5, 8, 14, 3, 8.5, 3, 4.5, 8, 2])
    _busur(canvas, warna, 5.5, 5.5, 10.5, 10.5, 200, 140)
    canvas.create_oval(7, 7, 9, 9, fill=warna, outline=warna)


def _asisten(canvas: tk.Canvas, warna: str) -> None:
    """Balon percakapan dengan tiga titik."""
    _garis(
        canvas,
        warna,
        [2.5, 3, 13.5, 3, 13.5, 10, 9, 10, 6, 13, 6, 10, 2.5, 10, 2.5, 3],
    )
    # Kotak kecil, bukan oval beroutline: pada ukuran 16 px, tiga oval dengan
    # garis tepi saling menempel dan berubah jadi satu garis lurus.
    for x in (4.6, 7.6, 10.6):
        canvas.create_rectangle(x, 5.9, x + 1.2, 7.1, fill=warna, outline=warna)


def _pembaruan(canvas: tk.Canvas, warna: str) -> None:
    """Panah melingkar."""
    # Busur dibuka di kanan atas, tempat ujung panah dipasang.
    _busur(canvas, warna, 2.5, 3.5, 13.5, 14.5, 80, 280)
    # Segitiga, bukan tiga garis: pada ukuran 16 px, tiga garis saling menempel
    # dan ujung panahnya hilang.
    canvas.create_polygon(
        10.4, 1.6, 14.2, 3.4, 11.0, 6.0, fill=warna, outline=warna
    )


def _pengaturan(canvas: tk.Canvas, warna: str) -> None:
    """Tiga penggeser, bukan roda gigi.

    Roda gigi adalah lambang pengaturan yang paling dikenal, tetapi pada ukuran
    16 px gigi-giginya saling menempel dengan lingkarannya dan hasilnya jadi
    gumpalan yang tidak terbaca. Tiga garis dengan kenop di posisi berbeda
    langsung terbaca, dan itu arti yang sama.
    """
    for y, x_kenop in ((4.5, 10.5), (8.0, 5.5), (11.5, 9.0)):
        _garis(canvas, warna, [2.5, y, 13.5, y])
        canvas.create_rectangle(
            x_kenop - 1.5, y - 1.8, x_kenop + 1.5, y + 1.8,
            fill=warna, outline=warna,
        )


_GAMBAR = {
    "beranda": _beranda,
    "pindai": _pindai,
    "karantina": _karantina,
    "rtp": _perlindungan,
    "asisten": _asisten,
    "pembaruan": _pembaruan,
    "pengaturan": _pengaturan,
}


def kinds() -> list[str]:
    """Nama ikon yang tersedia. Dipakai uji untuk memastikan semuanya tergambar."""
    return sorted(_GAMBAR)


def draw(canvas: tk.Canvas, kind: str, warna: str) -> None:
    """Gambar ikon `kind` di atas canvas. Isi canvas lama dibuang lebih dulu."""
    canvas.delete("all")
    fungsi = _GAMBAR.get(kind)
    if fungsi is None:
        return
    fungsi(canvas, warna)
    canvas.move("all", MARGIN, MARGIN)
