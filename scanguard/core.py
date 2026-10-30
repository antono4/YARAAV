"""Struktur data dan fungsi bantu yang dipakai semua mesin pemindai."""

from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .config import (
    DISGUISE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS_BARE,
    MAX_HASH_BYTES,
    SEV_MALWARE,
    SEV_NOTE,
    SEV_SUSPICIOUS,
)

# Berapa banyak data yang dibaca sekali jalan saat menghitung hash.
HASH_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Finding:
    """Satu temuan pada satu berkas."""

    path: str
    engine: str
    rule: str
    detail: str
    severity: str

    @property
    def key(self) -> tuple[str, str, str]:
        """Identitas temuan, dipakai untuk membuang duplikat.

        Satu berkas bisa memicu aturan yang sama berkali-kali dengan detail
        berbeda (misalnya dua nama fungsi Windows yang berbeda), jadi yang
        dianggap duplikat hanya baris yang benar-benar identik.
        """
        return (self.path, self.rule, self.detail)


@dataclass
class FileReport:
    """Hasil pemeriksaan satu berkas."""

    path: str
    size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    skipped: str = ""
    duration: float = 0.0

    @property
    def worst(self) -> str | None:
        """Tingkat bahaya terberat pada berkas ini, atau None bila bersih."""
        if not self.findings:
            return None
        from .config import SEVERITY_ORDER

        return min(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


@dataclass
class ScanSummary:
    """Ringkasan satu kali pemindaian folder."""

    root: str
    total_files: int = 0
    scanned_files: int = 0
    skipped_files: int = 0
    error_files: int = 0
    cached_files: int = 0
    infected: int = 0
    suspicious: int = 0
    notes: int = 0
    findings: list[Finding] = field(default_factory=list)
    elapsed: float = 0.0
    stopped: bool = False
    finished_at: datetime | None = None
    engines_used: list[str] = field(default_factory=list)


def finding_to_dict(finding: Finding) -> dict:
    """Ubah temuan menjadi bentuk yang bisa disimpan di basis data."""
    return {
        "path": finding.path,
        "engine": finding.engine,
        "rule": finding.rule,
        "detail": finding.detail,
        "severity": finding.severity,
    }


def finding_from_dict(data: dict) -> Finding:
    """Kembalikan temuan dari basis data. Data yang rusak tidak membuat crash."""
    return Finding(
        path=data.get("path", ""),
        engine=data.get("engine", ""),
        rule=data.get("rule", ""),
        detail=data.get("detail", ""),
        severity=data.get("severity", SEV_NOTE),
    )


def format_size(num_bytes: int) -> str:
    """Ubah jumlah byte menjadi teks yang enak dibaca."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def shannon_entropy(data: bytes) -> float:
    """Hitung entropi Shannon (0.0 - 8.0 bit per byte).

    Teks biasa berkisar 3-5, program normal 6-6.8, sedangkan berkas yang sudah
    dikompres atau dienkripsi mendekati 8 karena byte-nya hampir acak. Angka ini
    juga berarti "seberapa tidak bisa dibaca manusja", sehingga berguna untuk
    mendeteksi berkas yang disamarkan.
    """
    if not data:
        return 0.0
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total) for count in Counter(data).values()
    )


def is_double_extension(filename: str) -> str | None:
    """Kembalikan ekstensi penyamaran bila nama berkas berekstensi ganda.

    Contoh: "Faktur.pdf.exe" -> ".pdf" (dikira dokumen, ternyata program).
    """
    parts = os.path.basename(filename).lower().split(".")
    if len(parts) >= 3 and parts[-1] in EXECUTABLE_EXTENSIONS_BARE:
        if f".{parts[-2]}" in DISGUISE_EXTENSIONS:
            return f".{parts[-2]}"
    return None


def hash_file(path: str, max_bytes: int = MAX_HASH_BYTES) -> tuple[str, str, str]:
    """Hitung SHA-256, SHA-1, dan MD5 sekaligus sambil membaca berkas sekali.

    Ketiganya dihitung bersamaan karena membaca berkas dari disk jauh lebih
    lambat daripada menghitung hash-nya. SHA-256 dipakai sebagai kunci utama;
    SHA-1 dan MD5 tetap disimpan karena basis data malware publik masih banyak
    yang memakai keduanya.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    read = 0
    with open(path, "rb") as handle:
        while True:
            if read >= max_bytes:
                break
            chunk = handle.read(HASH_CHUNK)
            if not chunk:
                break
            read += len(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


def looks_like_pe(path: str) -> bool:
    """Periksa cepat apakah berkas berupa program Windows (format PE).

    Berkas PE selalu diawali dua byte "MZ". Pemeriksaan ini sengaja murah
    supaya analisis PE hanya dijalankan pada kandidat yang masuk akal.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def is_executable_extension(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in EXECUTABLE_EXTENSIONS


def severity_for_score(score: int) -> str:
    """Ubah skor heuristik menjadi tingkat bahaya."""
    if score >= 60:
        return SEV_MALWARE
    if score >= 30:
        return SEV_SUSPICIOUS
    return SEV_NOTE


def human_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} detik"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes} menit {rest} detik"
