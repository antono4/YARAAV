"""Tema warna ScanGuard.

Semua pasangan teks/latar di sini **dihitung** memenuhi WCAG AA (minimal 4,5:1),
bukan dinilai dari gambar. Angkanya ada di `tests/test_core.py` dan dihitung
ulang setiap kali pengujian dijalankan, sehingga tema tidak bisa diam-diam
merusak keterbacaan.

Satu hal yang penting dipahami tentang warna merek: oranye khas SMADAV
(`#ff6b00`) hanya punya kontras 2,86:1 di atas putih. Itu **jauh** di bawah
ambang teks yang terbaca. Karena itu ada dua keluarga warna:

* `accent` dan `fill_*`  - cukup gelap untuk dipakai sebagai teks dan tombol.
* `brand` dan `brand_soft` - hanya untuk isian, garis, dan sorotan. **Jangan
  pernah** dipakai sebagai warna teks.

Menggabungkan keduanya menjadi satu warna akan memaksa salah satu pihak kalah:
teks jadi tidak terbaca, atau mereknya hilang.
"""

from __future__ import annotations

# --- Palet utama: tema terang, gaya SMADAV --------------------------------- #
COLORS = {
    # Latar
    "bg": "#f2f4f7",          # latar jendela
    "panel": "#ffffff",       # kartu dan kotak
    "sidebar": "#ffffff",     # panel navigasi kiri
    "border": "#dbe1e8",      # garis pemisah tipis
    # Teks
    "text": "#1a2430",        # 15,68:1 di atas panel
    "muted": "#5b6875",       # 5,70:1 di atas panel
    "sidebar_text": "#334155",
    # Warna merek. Hanya untuk isian dan garis - tidak pernah untuk teks.
    "brand": "#ff6b00",       # oranye SMADAV
    "brand_soft": "#fff1e6",  # sorotan lembut untuk menu aktif
    "brand_line": "#ffb27a",
    # Aksen yang cukup gelap untuk dipakai sebagai teks dan tombol.
    "accent": "#b34700",      # 5,50:1 di atas panel
    "fill": "#b34700",
    "fill_active": "#9a3d00",
    "secondary": "#e6eaef",
    "secondary_active": "#d5dbe3",
    "sidebar_active": "#fff1e6",
    "sidebar_hover": "#f1f5f9",
    # Tingkat bahaya. Di tema terang, warna cerah tidak terbaca: kuning terang
    # di atas putih nyaris tidak terlihat. Nilainya diturunkan sampai lolos
    # 4,5:1, dan uji kontras memastikan itu.
    "danger": "#b3261e",      # 6,54:1
    "warn": "#8a5300",        # 6,33:1
    "note": "#1b4fa8",        # 7,69:1
    "ok": "#0f6b3d",          # 6,58:1
    # Tombol berbahaya
    "danger_fill": "#b3261e",
    "danger_active": "#8f1d17",
    # Bilah kemajuan. Memakai oranye merek karena ini isian, bukan teks.
    "bar": "#e8590c",
    "trough": "#e6eaef",
}

# Warna yang **hanya boleh** dipakai sebagai isian atau garis. Dipakai oleh
# pengujian untuk memastikan tidak ada yang memakainya sebagai warna teks.
FILL_ONLY_KEYS = frozenset({"brand", "brand_line", "bar"})
