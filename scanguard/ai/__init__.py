"""Bagian kecerdasan buatan ScanGuard.

AI di sini dipakai untuk hal yang memang tidak bisa dikerjakan aturan tetap:

1. **Penjelasan temuan** (`analyst.py`) - menerjemahkan temuan teknis menjadi
   bahasa yang bisa dipahami, dan menilai apakah temuan itu masuk akal.
2. **Deteksi anomali** (`anomaly.py`) - memakai model AI lokal untuk mencari
   berkas yang "terasa janggal" dibandingkan berkas lain di folder yang sama,
   sehingga berkas berbahaya yang belum pernah tercatat pun bisa tersorot.
3. **Asisten tanya-jawab** (`assistant.py`) - pengguna bisa bertanya bebas
   tentang hasil pemindaian atau tentang malware.

Prinsip yang dipegang seluruh modul di sini:

* **Tanpa AI, program tetap berfungsi penuh.** Semua bagian AI bersifat
  opsional dan gagal dengan aman.
* **AI tidak pernah menentukan tingkat bahaya.** Tingkat MALWARE/MENCURIGAKAN/
  PERLU DIPERIKSA hanya boleh datang dari mesin deteksi yang hasilnya dapat
  diperiksa ulang (hash, aturan, struktur berkas). AI memberi keterangan dan
  dugaan, bukan putusan.
* **Tidak ada berkas yang diunggah.** Yang dikirim ke model hanya ringkasan
  (nama, ukuran, hash, jenis temuan) dan potongan berkas yang sudah dibersihkan
  dari data pribadi.
* **Kunci API tidak pernah ditulis ke log atau ke berkas repo.**
"""

from .base import AnalysisResult, FileReport, LlmError, LlmReply, Usage
from .privacy import redact_text, summarise_findings

__all__ = [
    "AnalysisResult",
    "FileReport",
    "LlmError",
    "LlmReply",
    "Usage",
    "redact_text",
    "summarise_findings",
]
