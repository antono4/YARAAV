"""Menyusun laporan pemindaian dalam bentuk teks yang bisa disimpan.

Laporan sengaja memuat informasi yang membuat hasilnya bisa dipercaya dan
ditindaklanjuti: hash berkas, mesin mana yang menemukan apa, dan berapa lama
pemindaian berjalan. Laporan yang hanya berbunyi "ada virus" tidak berguna.
"""

from __future__ import annotations

import os
from datetime import datetime

from .config import APP_NAME, APP_VERSION, SEVERITY_ORDER
from .core import ScanSummary, format_size, human_time


def build_report(summary: ScanSummary, engine_status: list[dict] | None = None) -> str:
    """Ubah ringkasan pemindaian menjadi teks laporan."""
    lines: list[str] = []
    width = 74

    lines.append("=" * width)
    lines.append(f"  LAPORAN PEMINDAIAN {APP_NAME} {APP_VERSION}")
    lines.append("=" * width)
    lines.append(f"Folder      : {summary.root}")
    lines.append(
        f"Waktu       : "
        f"{summary.finished_at.strftime('%d-%m-%Y %H:%M:%S') if summary.finished_at else '-'}"
    )
    lines.append(f"Durasi      : {human_time(summary.elapsed)}")
    if summary.stopped:
        lines.append("Catatan     : Pemindaian DIHENTIKAN sebelum selesai.")
    lines.append("")

    lines.append("-" * width)
    lines.append("  RINGKASAN")
    lines.append("-" * width)
    lines.append(f"Berkas ditemukan    : {summary.total_files}")
    lines.append(f"Berkas diperiksa    : {summary.scanned_files}")
    if summary.cached_files:
        lines.append(f"  di antaranya dari hasil pemindaian sebelumnya : {summary.cached_files}")
    lines.append(f"Berkas dilewati     : {summary.skipped_files}")
    lines.append(f"Berkas gagal dibaca : {summary.error_files}")
    lines.append("")
    lines.append(f"Temuan MALWARE          : {summary.infected}")
    lines.append(f"Temuan MENCURIGAKAN     : {summary.suspicious}")
    lines.append(f"Temuan PERLU DIPERIKSA  : {summary.notes}")
    lines.append("")

    if summary.engines_used:
        lines.append("Mesin yang dipakai  : " + ", ".join(summary.engines_used))
    if engine_status:
        lines.append("")
        lines.append("Status mesin:")
        for item in engine_status:
            mark = "siap" if item.get("ok") else "tidak tersedia"
            lines.append(f"  [{mark}] {item.get('name')}: {item.get('message')}")

    lines.append("")
    if not summary.findings:
        lines.append("-" * width)
        lines.append("  TIDAK ADA TEMUAN")
        lines.append("-" * width)
        lines.append("Tidak ada berkas yang cocok dengan aturan pemindaian.")
        lines.append("")
        lines.append(
            "Catatan: tidak ada temuan BUKAN berarti berkas pasti aman. "
            "Pemindai berbasis tanda tangan dan aturan hanya mengenali apa yang "
            "sudah diketahui. Perilaku baru yang belum pernah tercatat bisa lolos."
        )
    else:
        lines.append("-" * width)
        lines.append(f"  DAFTAR TEMUAN ({len(summary.findings)})")
        lines.append("-" * width)
        ordered = sorted(
            summary.findings,
            key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.engine),
        )
        current_file = None
        for finding in ordered:
            if finding.path != current_file:
                current_file = finding.path
                try:
                    size = format_size(os.path.getsize(finding.path))
                except OSError:
                    size = "ukuran tidak terbaca"
                lines.append("")
                lines.append(f"[{finding.severity}] {finding.path}")
                lines.append(f"    ukuran: {size}")
            lines.append(f"    - ({finding.engine}) {finding.rule}")
            lines.append(f"      {finding.detail}")

    lines.append("")
    lines.append("=" * width)
    lines.append("  HASIL INI BUKAN JAMINAN KEAMANAN")
    lines.append("=" * width)
    lines.append(
        "Pemindai ini bekerja dengan tiga cara: membandingkan sidik jari (hash)\n"
        "berkas dengan daftar malware yang sudah dikonfirmasi, mencocokkan pola\n"
        "perilaku dengan aturan YARA, dan menilai struktur program Windows.\n\n"
        "Keterbatasannya nyata: malware yang belum pernah tercatat (baru dibuat\n"
        "atau diubah sedikit) tidak akan dikenali. Karena itu program ini TIDAK\n"
        "boleh dijadikan satu-satunya pelindung komputer. Tetap gunakan Windows\n"
        "Defender atau antivirus resmi sebagai pertahanan utama, dan jadikan\n"
        "hasil pemindaian ini sebagai bahan pemeriksaan tambahan."
    )
    lines.append("")
    lines.append(f"Dibuat oleh {APP_NAME} {APP_VERSION} pada {datetime.now():%d-%m-%Y %H:%M:%S}")
    lines.append("")
    return "\n".join(lines)
