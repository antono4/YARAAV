"""Membuat file ikon aplikasi (assets/icon.ico) secara terprogram.

Dijalankan sekali saja saat menyiapkan proyek:
    python tools/make_icon.py

Ikon digambar dalam beberapa ukuran karena Windows memakainya berbeda-beda:
16x16 di taskbar/Explorer, 32x32 di desktop, 256x256 di tampilan ikon besar.
File .ico boleh berisi banyak ukuran sekaligus - itulah sebabnya ikon harus
digambar ulang per ukuran, bukan hanya diperbesar dari satu gambar.
"""

import os

from PIL import Image, ImageDraw

ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
SIZES = (16, 24, 32, 48, 64, 128, 256)

BG_TOP = (22, 33, 44)
BG_BOTTOM = (12, 20, 28)
SHIELD = (47, 158, 111)
SHIELD_DARK = (23, 105, 74)
CHECK = (240, 248, 244)


def draw_icon(size: int) -> Image.Image:
    """Gambar satu ukuran ikon: kotak gelap + perisai + tanda centang."""
    scale = 8  # gambar besar dulu, lalu diperkecil agar tepinya halus
    canvas = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    side = size * scale

    # Latar bergradasi: digambar baris per baris karena ImageDraw tidak punya gradasi.
    for y in range(side):
        blend = y / max(side - 1, 1)
        color = tuple(
            round(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * blend) for i in range(3)
        )
        draw.line([(0, y), (side, y)], fill=color + (255,))

    radius = side * 0.22
    mask = Image.new("L", (side, side), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, side - 1, side - 1], radius, fill=255)
    canvas.putalpha(mask)

    # Perisai: badan persegi panjang dengan ujung bawah meruncing.
    pad = side * 0.20
    top = pad
    bottom = side - pad
    left = pad
    right = side - pad
    mid_y = top + (bottom - top) * 0.52
    shield = [
        (left, top),
        (right, top),
        (right, mid_y),
        (side / 2, bottom),
        (left, mid_y),
    ]
    draw.polygon(shield, fill=SHIELD)

    # Sisi kanan diberi bayangan supaya bentuk perisai terbaca di ukuran kecil.
    draw.polygon(
        [(side / 2, top), (right, top), (right, mid_y), (side / 2, bottom)],
        fill=SHIELD_DARK,
    )

    # Tanda centang.
    stroke = max(int(side * 0.075), 2)
    draw.line(
        [
            (side * 0.34, side * 0.47),
            (side * 0.45, side * 0.60),
            (side * 0.67, side * 0.33),
        ],
        fill=CHECK,
        width=stroke,
        joint="curve",
    )

    return canvas.resize((size, size), Image.LANCZOS)


def main() -> None:
    os.makedirs(ASSETS, exist_ok=True)
    frames = [draw_icon(size) for size in SIZES]
    ico_path = os.path.join(ASSETS, "icon.ico")
    frames[-1].save(ico_path, format="ICO", sizes=[(s, s) for s in SIZES])
    png_path = os.path.join(ASSETS, "icon_256.png")
    frames[-1].save(png_path)
    print("tersimpan:", ico_path)
    print("tersimpan:", png_path)


if __name__ == "__main__":
    main()
