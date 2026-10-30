"""Mesin YARA: pencocokan pola pada berkas memakai format aturan standar industri.

YARA adalah bahasa aturan yang dipakai VirusTotal, sandbox malware, dan tim
tanggap insiden. Memakai YARA berarti aturan yang ditulis untuk alat lain bisa
langsung dipakai di sini, dan sebaliknya.

Aturan dikompilasi sekali lalu dipakai berulang kali. Kompilasi adalah bagian
yang paling lambat, jadi hasilnya di-cache ke berkas agar pembukaan program
berikutnya cepat. Cache dibuang otomatis bila berkas aturan berubah.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from .config import (
    ENGINE_YARA,
    MAX_READ_BYTES,
    SEV_MALWARE,
    SEV_NOTE,
    SEV_SUSPICIOUS,
    data_dir,
    default_rules_path,
    ensure_data_dir,
)
from .core import Finding

# Tingkat bahaya yang dideklarasikan di bagian `meta` aturan YARA.
_META_SEVERITY = {
    "MALWARE": SEV_MALWARE,
    "MENCURIGAKAN": SEV_SUSPICIOUS,
    "PERLU DIPERIKSA": SEV_NOTE,
}


@dataclass
class RuleLoadResult:
    ok: bool
    message: str
    rule_count: int = 0
    rules_path: str = ""
    used_cache: bool = False


class YaraEngine:
    """Pembungkus yara-python dengan cache hasil kompilasi."""

    name = ENGINE_YARA

    def __init__(self, rules_path: str | None = None) -> None:
        self.rules_path = rules_path or default_rules_path()
        self._rules = None
        self._lock = threading.Lock()
        self._status = RuleLoadResult(False, "Aturan YARA belum dimuat.")
        self._import_error = ""

    # -------------------------------------------------------- pemuatan -- #

    @property
    def available(self) -> bool:
        """Apakah pustaka yara-python bisa diimpor.

        Diperiksa terpisah karena yara-python memerlukan pustaka C yang tidak
        selalu bisa dibungkus PyInstaller. Program harus tetap jalan - hanya
        tanpa mesin ini - kalau pustakanya tidak ada.
        """
        try:
            import yara  # noqa: F401
        except ImportError as error:
            self._import_error = str(error)
            return False
        return True

    def load(self) -> RuleLoadResult:
        """Kompilasi berkas aturan, memakai cache bila masih berlaku."""
        if not self.available:
            self._status = RuleLoadResult(
                False,
                "yara-python tidak terpasang, jadi mesin YARA dilewati. "
                f"Pasang dengan: pip install yara-python ({self._import_error})",
            )
            return self._status

        if not os.path.exists(self.rules_path):
            self._status = RuleLoadResult(
                False, f"Berkas aturan tidak ditemukan: {self.rules_path}"
            )
            return self._status

        import yara

        cache_path = self._cache_path()
        try:
            rules, from_cache = self._load_cached(yara, cache_path)
        except Exception as error:  # noqa: BLE001 - kesalahan aturan harus terbaca
            self._status = RuleLoadResult(
                False, f"Aturan YARA gagal dikompilasi: {error}"
            )
            return self._status

        count = len(list(rules))
        with self._lock:
            self._rules = rules
        self._status = RuleLoadResult(
            True,
            f"{count} aturan YARA siap dipakai."
            + (" (dimuat dari cache)" if from_cache else " (baru dikompilasi)"),
            rule_count=count,
            rules_path=self.rules_path,
            used_cache=from_cache,
        )
        return self._status

    def _cache_path(self) -> str:
        ensure_data_dir()
        return os.path.join(data_dir(), "rules_compiled.yarc")

    def _load_cached(self, yara, cache_path: str):
        """Muat dari cache bila berkas aturan belum berubah; jika tidak, kompilasi.

        Kembalikan (rules, apakah_diambil_dari_cache).
        """
        rules_mtime = os.path.getmtime(self.rules_path)
        if os.path.exists(cache_path) and os.path.getmtime(cache_path) >= rules_mtime:
            try:
                return yara.load(cache_path), True
            except Exception:  # noqa: BLE001 - cache rusak, kompilasi ulang saja
                pass
        rules = yara.compile(filepath=self.rules_path)
        try:
            rules.save(cache_path)
        except Exception:  # noqa: BLE001 - gagal menyimpan cache bukan masalah besar
            pass
        return rules, False

    # ------------------------------------------------------- pemeriksaan -- #

    def reload(self) -> RuleLoadResult:
        """Paksa kompilasi ulang, misalnya setelah aturan diperbarui."""
        cache_path = self._cache_path()
        if os.path.exists(cache_path):
            try:
                os.remove(cache_path)
            except OSError:
                pass
        return self.load()

    def scan_file(self, path: str) -> list[Finding]:
        """Cocokkan satu berkas dengan seluruh aturan."""
        with self._lock:
            rules = self._rules
        if rules is None:
            return []

        try:
            with open(path, "rb") as handle:
                data = handle.read(MAX_READ_BYTES)
        except OSError:
            return []

        try:
            matches = rules.match(data=data, timeout=30)
        except Exception:  # noqa: BLE001 - berkas aneh tidak boleh menghentikan pemindaian
            return []

        findings = []
        for match in matches:
            meta = match.meta or {}
            severity = _META_SEVERITY.get(
                str(meta.get("severity", "")).upper(), SEV_SUSPICIOUS
            )
            description = meta.get("description") or "Pola mencurigakan terdeteksi"
            strings = ""
            if match.strings:
                # Tampilkan potongan yang cocok agar pengguna bisa menilai sendiri.
                pieces = []
                for item in match.strings[:3]:
                    try:
                        raw = item.instances[0].matched_data[:40]
                        pieces.append(raw.decode("utf-8", "replace"))
                    except (AttributeError, IndexError):
                        continue
                if pieces:
                    strings = " | pola: " + ", ".join(repr(p) for p in pieces)
            findings.append(
                Finding(
                    path=path,
                    engine=ENGINE_YARA,
                    rule=match.rule,
                    detail=f"{description}{strings}",
                    severity=severity,
                )
            )
        return findings

    @property
    def status(self) -> RuleLoadResult:
        return self._status

    @property
    def loaded(self) -> bool:
        """Apakah aturan sudah dikompilasi dan siap dipakai."""
        with self._lock:
            return self._rules is not None
