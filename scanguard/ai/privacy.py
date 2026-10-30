"""Menyiapkan data sebelum dikirim ke model AI.

Bagian ini ada karena mengirim data ke penyedia AI adalah **tindakan yang
mengeluarkan informasi dari komputer pengguna**. Itu tidak boleh terjadi tanpa
sepengetahuan mereka, dan data yang keluar harus sesedikit mungkin.

Aturan yang dipegang:

* Nama pengguna Windows, alamat email, nomor telepon, nomor kartu, dan alamat IP
  diganti sebelum dikirim. Path lengkap `C:\\Users\\Budi\\...` berubah menjadi
  `C:\\Users\\<pengguna>\\...`.
* Isi berkas **tidak pernah** ikut, kecuali pengguna menyalakan sendiri pilihan
  "sertakan cuplikan berkas" di Pengaturan.
* Yang dikirim hanya hal-hal yang memang dibutuhkan untuk menjawab: nama berkas,
  ukuran, hash, dan daftar temuan.
"""

from __future__ import annotations

import re

# Pola yang diganti. Urutannya penting: email diperiksa sebelum pola yang lebih
# umum, supaya tidak setengah tergantikan.
_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b",
        "<email>",
        "alamat email",
    ),
    (
        r"\b(?:\d[ -]*?){13,19}\b",
        "<nomor-kartu>",
        "deretan angka panjang (kemungkinan nomor kartu)",
    ),
    (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "<alamat-ip>",
        "alamat IP",
    ),
    (
        r"\b(?:\+62|62|0)8\d{1,3}[ -]?\d{3,4}[ -]?\d{3,5}\b",
        "<nomor-telepon>",
        "nomor telepon Indonesia",
    ),
    (
        # Path Windows: C:\Users\<nama>\... -> C:\Users\<pengguna>\...
        r"(?i)([A-Z]:\\Users\\)([^\\/\s]+)",
        r"\1<pengguna>",
        "nama pengguna Windows pada path",
    ),
    (
        r"(?i)(/home/)([^/\s]+)",
        r"\1<pengguna>",
        "nama pengguna Linux pada path",
    ),
    (
        r"(?i)(/Users/)([^/\s]+)",
        r"\1<pengguna>",
        "nama pengguna macOS pada path",
    ),
]


def redact_text(text: str) -> str:
    """Ganti data pribadi yang terlihat di dalam teks."""
    result = text
    for pattern, replacement, _label in _PATTERNS:
        result = re.sub(pattern, replacement, result)
    return result


def detect_personal_data(text: str) -> list[str]:
    """Sebutkan jenis data pribadi yang ditemukan, untuk ditampilkan ke pengguna.

    Dipakai untuk memberi tahu pengguna *apa* yang akan disamarkan, bukan hanya
    diam-diam menyamarkannya. Pengguna berhak tahu datanya diperlakukan
    bagaimana.
    """
    found: list[str] = []
    for pattern, _replacement, label in _PATTERNS:
        if re.search(pattern, text) and label not in found:
            found.append(label)
    return found


def build_context(
    summary,
    max_files: int = 40,
    include_snippet: bool = False,
) -> str:
    """Susun ringkasan hasil pemindaian untuk dikirim ke model.

    Hanya temuan yang dikirim, bukan seluruh daftar berkas. Folder berisi
    50.000 berkas tidak perlu dikirim seluruhnya untuk bisa dijelaskan.

    `include_snippet` hanya boleh dinyalakan pengguna secara sadar: itu berarti
    isi berkas ikut keluar dari komputer.
    """
    lines = [
        "RINGKASAN PEMINDAIAN",
        f"Folder: {redact_text(summary.root)}",
        f"Berkas diperiksa: {summary.scanned_files} dari {summary.total_files}",
        f"Berkas dilewati: {summary.skipped_files}, gagal dibaca: {summary.error_files}",
        f"Mesin yang dipakai: {', '.join(summary.engines_used) or '-'}",
        "",
        f"Temuan: {summary.infected} malware, {summary.suspicious} mencurigakan, "
        f"{summary.notes} perlu diperiksa",
        "",
    ]

    if not summary.findings:
        lines.append("Tidak ada temuan sama sekali.")
        return "\n".join(lines)

    # Kelompokkan per berkas supaya model melihat satu berkas dengan seluruh
    # temuannya, bukan baris-baris yang terpisah-pisah.
    grouped: dict[str, list] = {}
    for finding in summary.findings:
        grouped.setdefault(finding.path, []).append(finding)

    # Urutkan dari yang paling berbahaya, lalu batasi jumlahnya.
    def worst_rank(items: list) -> int:
        order = {"MALWARE": 0, "MENCURIGAKAN": 1, "PERLU DIPERIKSA": 2}
        return min(order.get(f.severity, 3) for f in items)

    ordered = sorted(grouped.items(), key=lambda item: worst_rank(item[1]))
    lines.append("DAFTAR TEMUAN:")
    for path, findings in ordered[:max_files]:
        severity = findings[0].severity
        lines.append(f"\n[{severity}] {redact_text(path)}")
        for finding in findings:
            lines.append(f"  - ({finding.engine}) {finding.rule}: {finding.detail}")

    if len(ordered) > max_files:
        lines.append(
            f"\n... dan {len(ordered) - max_files} berkas lain dengan temuan "
            f"(tidak dikirim agar permintaan tidak terlalu panjang)."
        )
    return "\n".join(lines)


def build_file_context(report) -> str:
    """Susun keterangan satu berkas untuk diminta penjelasan atasnya.

    Seluruh teks yang dihasilkan disamarkan sebelum dikembalikan. Bagian detail
    temuan sering memuat path lengkap dan alamat email - misalnya "ditemukan di
    C:\\Users\\Budi\\... dan dikirim ke budi@mail.com" - sehingga menyamarkan
    hanya nama berkas tidak cukup.
    """
    lines = [
        "BERKAS YANG DIPERIKSA",
        f"Nama: {report.name}",
        f"Ukuran: {report.size} byte",
        f"SHA-256: {report.sha256}",
        f"Ekstensi: {report.extension or '(tidak ada)'}",
    ]
    if report.section_summary:
        lines.append(f"Struktur: {report.section_summary}")
    if report.findings:
        lines.append("")
        lines.append("TEMUAN MESIN PEMINDAI:")
        for finding in report.findings:
            lines.append(
                f"  - [{finding.get('severity','?')}] ({finding.get('engine','?')}) "
                f"{finding.get('rule','?')}: {finding.get('detail','')}"
            )
    else:
        lines.append("")
        lines.append("Tidak ada temuan dari mesin pemindai.")
    if report.snippet:
        lines.append("")
        lines.append("CUPLIKAN AWAL BERKAS (atas izin pengguna):")
        lines.append(report.snippet[:1500])

    # Satu tempat penyamaran untuk seluruh teks. Menyamarkan per bagian mudah
    # terlewat, dan yang terlewat tidak akan terlihat sampai data pengguna
    # sudah telanjur terkirim.
    return redact_text("\n".join(lines))


def summarise_findings(summary) -> dict:
    """Hitung angka ringkas dari temuan, untuk ditampilkan di antarmuka."""
    by_engine: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in summary.findings:
        by_engine[finding.engine] = by_engine.get(finding.engine, 0) + 1
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    return {
        "total": len(summary.findings),
        "by_engine": by_engine,
        "by_severity": by_severity,
        "files_with_findings": len({f.path for f in summary.findings}),
    }
