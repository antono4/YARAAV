"""Orkestrator pemindaian: menjalankan semua mesin dan menyusun laporan.

Tugas modul ini adalah menyatukan empat mesin menjadi satu alur yang masuk akal:

    hash SHA-256  ->  cocok dengan basis data malware? (paling menentukan)
    YARA          ->  cocok dengan pola perilaku?
    analisis PE   ->  struktur program mencurigakan?
    ClamAV        ->  dikenali basis data antivirus? (dijalankan per kelompok)

Tiga hal yang membuat pemindaian ini praktis dipakai pada folder sungguhan:

* **Cache berbasis perubahan berkas.** Berkas yang ukuran dan waktu ubahnya
  sama tidak diperiksa ulang, jadi pemindaian kedua jauh lebih cepat. Cache
  otomatis dianggap tidak berlaku bila basis data hash atau aturan YARA berubah,
  supaya hasil lama yang sudah usang tidak dipercaya.
* **Batas waktu per berkas.** Berkas aneh (named pipe, berkas jaringan yang
  menggantung) bisa memblokir selamanya. Setiap berkas dibatasi waktunya, dan
  berkas yang melewati batas dicatat apa adanya - bukan didiamkan.
* **Penghentian yang rapi.** Pemindaian bisa dihentikan kapan saja lewat
  threading.Event, dan berkas yang sudah diperiksa tetap dilaporkan.
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime

from .ai.anomaly import anomalies_to_findings, find_anomalies
from .clamav_engine import ClamAVEngine
from .config import (
    BIG_FILE_BYTES,
    ENGINE_AI,
    ENGINE_DECODE,
    ENGINE_HASH,
    ENGINE_NAME,
    ENGINE_PE,
    ENGINE_YARA,
    FILE_TIMEOUT_SECONDS,
    MAX_HASH_BYTES,
    SEV_NOTE,
    SEV_SUSPICIOUS,
    SKIP_DIR_NAMES,
)
from .core import (
    Finding,
    ScanSummary,
    finding_from_dict,
    finding_to_dict,
    format_size,
    hash_file,
    is_double_extension,
    is_executable_extension,
)
from .decode_engine import DecodeEngine
from .hashes import HashDatabase
from .pe_engine import PEEngine
from .quarantine import Quarantine
from .yara_engine import YaraEngine


class ScanEngine:
    """Mesin pemindai utama. Tidak menyentuh antarmuka sama sekali."""

    def __init__(
        self,
        database: HashDatabase | None = None,
        quarantine: Quarantine | None = None,
        use_clamav: bool = True,
        use_yara: bool = True,
        use_pe: bool = True,
        use_decode: bool = True,
        rules_path: str | None = None,
    ) -> None:
        self.db = database or HashDatabase()
        self.quarantine = quarantine or Quarantine()
        self.hash_engine = True
        self.yara = YaraEngine(rules_path) if use_yara else None
        self.pe = PEEngine() if use_pe else None
        self.clamav = ClamAVEngine() if use_clamav else None
        self.decode = DecodeEngine() if use_decode else None
        self.exclusions: list[str] = []
        self._engines_ready = False

    def _ensure_engines(self) -> None:
        """Muat mesin yang butuh persiapan, sekali saja.

        YARA harus dikompilasi sebelum bisa dipakai. Tanpa pemuatan otomatis di
        sini, memanggil scan_file() atau scan_directory() tanpa prepare() lebih
        dulu akan melewati mesin YARA tanpa peringatan apa pun - deteksi
        kehilangan salah satu mesinnya secara diam-diam.
        """
        if self._engines_ready:
            return
        self._engines_ready = True
        if self.yara is not None and not self.yara.loaded:
            self.yara.load()

    # ---------------------------------------------------------- persiapan -- #

    def prepare(self) -> dict:
        """Siapkan semua mesin. Kembalikan ringkasan status untuk ditampilkan."""
        report: dict = {"engines": [], "warnings": []}

        self.db.seed_if_empty()
        stats = self.db.stats()
        report["engines"].append(
            {
                "name": ENGINE_HASH,
                "ok": True,
                "message": f"{stats['total']} hash di basis data"
                + (
                    f", diperbarui {stats['last_update_text']}"
                    if stats.get("last_update_text")
                    else " (belum pernah diperbarui)"
                ),
            }
        )

        if self.yara is not None:
            status = self.yara.load()
            report["engines"].append(
                {
                    "name": ENGINE_YARA,
                    "ok": status.ok,
                    "message": status.message,
                }
            )
            if not status.ok:
                report["warnings"].append(status.message)

        if self.pe is not None:
            available = self.pe.available
            report["engines"].append(
                {"name": ENGINE_PE, "ok": available, "message": self.pe.status}
            )
            if not available:
                report["warnings"].append(self.pe.status)

        if self.decode is not None:
            report["engines"].append(
                {"name": ENGINE_DECODE, "ok": True, "message": self.decode.status}
            )

        if self.clamav is not None:
            status = self.clamav.detect(force=True)
            report["engines"].append(
                {"name": "ClamAV", "ok": status.available, "message": status.message}
            )
            if not status.available:
                report["warnings"].append(status.message)

        return report

    # --------------------------------------------------------- satu berkas -- #

    def scan_file(self, path: str, use_cache: bool = True) -> list[Finding]:
        """Periksa satu berkas dengan semua mesin (tanpa ClamAV, yang berkelompok)."""
        return self._scan_file_internal(path, use_cache, with_clamav=False)[0]

    def _scan_file_internal(
        self, path: str, use_cache: bool, with_clamav: bool
    ) -> tuple[list[Finding], str, dict]:
        """Inti pemeriksaan satu berkas.

        Kembalikan (temuan, hash_sha256, info_tambahan).
        """
        self._ensure_engines()
        findings: list[Finding] = []
        info: dict = {
            "skipped": "",
            "error": "",
            "size": 0,
            "sha256": "",
            "from_cache": False,
        }

        try:
            stat = os.stat(path)
        except OSError as error:
            info["error"] = f"Tidak bisa membaca informasi berkas: {error}"
            return findings, "", info
        size = stat.st_size
        info["size"] = size

        # --- Nama & ukuran: murah, jadi diperiksa lebih dulu ---------------- #
        disguise = is_double_extension(os.path.basename(path))
        if disguise:
            findings.append(
                Finding(
                    path=path,
                    engine=ENGINE_NAME,
                    rule="Ekstensi ganda",
                    detail=f"Bernama seperti {disguise} tetapi sebenarnya program",
                    severity=SEV_SUSPICIOUS,
                )
            )

        # Berkas program yang jauh lebih besar dari wajar. Ini hanya catatan:
        # banyak program besar memang sah (permainan, perkakas desain), jadi
        # ukuran sendirian bukan bukti apa-apa. Yang membuatnya layak dicatat
        # adalah karena ukuran besar sering dipakai untuk menyembunyikan isi.
        if is_executable_extension(path) and size > BIG_FILE_BYTES:
            findings.append(
                Finding(
                    path=path,
                    engine=ENGINE_NAME,
                    rule="Ukuran tidak wajar",
                    detail=(
                        f"Program berukuran {format_size(size)}, di atas "
                        f"{format_size(BIG_FILE_BYTES)}. Ukuran besar bisa dipakai "
                        f"untuk menyembunyikan isi, tetapi banyak program besar "
                        f"juga sah."
                    ),
                    severity=SEV_NOTE,
                )
            )

        # --- Cache ---------------------------------------------------------- #
        context = self._cache_context()
        if use_cache:
            cached = self.db.get_cached(path, size, stat.st_mtime)
            if cached and cached[1].startswith(context):
                sha256, _verdict, stored = cached
                # Temuan lama dipakai kembali supaya laporan tetap lengkap.
                restored = [finding_from_dict(item) for item in stored]
                info["from_cache"] = True
                info["sha256"] = sha256
                return findings + restored, sha256, info

        # --- Hash: mesin paling menentukan --------------------------------- #
        if size > MAX_HASH_BYTES:
            info["skipped"] = (
                f"Dilewati: ukuran {format_size(size)} melebihi batas "
                f"{format_size(MAX_HASH_BYTES)} untuk penghitungan hash"
            )
            return findings, "", info

        try:
            sha256, sha1, md5 = hash_file(path)
        except OSError as error:
            info["error"] = f"Berkas tidak bisa dibaca: {error}"
            return findings, "", info
        info["sha256"] = sha256

        match = self.db.lookup(sha256=sha256, sha1=sha1, md5=md5)
        if match:
            findings.append(
                Finding(
                    path=path,
                    engine=ENGINE_HASH,
                    rule="Cocok basis data malware",
                    detail=match.detail(),
                    severity="MALWARE",
                )
            )

        # --- YARA ----------------------------------------------------------- #
        if self.yara is not None:
            findings.extend(self.yara.scan_file(path))

        # --- Analisis PE ---------------------------------------------------- #
        if self.pe is not None:
            findings.extend(self.pe.scan_file(path))

        # --- Dekode muatan --------------------------------------------------- #
        # Dijalankan setelah YARA dan PE: keduanya melihat berkas apa adanya,
        # sedangkan mesin ini membongkar penyandiannya lebih dulu. Perintah yang
        # disandikan tidak akan pernah cocok dengan aturan YARA, karena teksnya
        # tidak ada di berkas mentah.
        if self.decode is not None:
            findings.extend(self.decode.scan_file(path))

        # --- ClamAV untuk satu berkas (dipakai saat pemindaian berkas tunggal) #
        if with_clamav and self.clamav is not None and self.clamav.available:
            findings.extend(self.clamav.scan_file(path))

        # Simpan hasil ke cache bersama konteksnya.
        verdict = self._verdict_of(findings)
        self.db.put_cached(
            path,
            size,
            stat.st_mtime,
            sha256,
            f"{context}:{verdict}",
            [finding_to_dict(f) for f in findings],
        )
        return findings, sha256, info

    # --------------------------------------------------------- satu folder -- #

    def iter_files(self, root: str):
        """Telusuri folder secara rekursif dan hasilkan path setiap berkas."""
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
            # Buang folder sistem dan tautan simbolik supaya tidak berputar-putar.
            dirnames[:] = [
                d
                for d in dirnames
                if d.lower() not in SKIP_DIR_NAMES
                and not os.path.islink(os.path.join(dirpath, d))
            ]
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if os.path.islink(path):
                    continue
                if self.is_excluded(path):
                    continue
                yield path

    def is_excluded(self, path: str) -> bool:
        """Periksa apakah berkas masuk daftar pengecualian pengguna."""
        lowered = path.lower()
        for item in self.exclusions:
            item = item.strip().lower()
            if item and item in lowered:
                return True
        return False

    def scan_directory(
        self,
        root: str,
        stop_event: threading.Event | None = None,
        on_progress=None,
        on_finding=None,
        on_status=None,
        use_cache: bool = True,
        use_anomaly: bool = False,
    ) -> ScanSummary:
        """Pindai seluruh folder. Callback dipanggil dari thread pekerja.

        `use_anomaly=True` menyalakan deteksi anomali berbasis AI lokal. Itu
        memerlukan satu tahap tambahan di akhir pemindaian, karena modelnya baru
        bisa dilatih setelah seluruh berkas terlihat. Hasilnya selalu berupa
        catatan PERLU DIPERIKSA, tidak pernah tuduhan malware.
        """
        self._ensure_engines()
        stop_event = stop_event or threading.Event()
        summary = ScanSummary(root=root, finished_at=datetime.now())
        started = time.time()

        engines = [ENGINE_HASH, ENGINE_NAME]
        if self.yara is not None and self.yara.status.ok:
            engines.append(ENGINE_YARA)
        if self.pe is not None and self.pe.available:
            engines.append(ENGINE_PE)
        if self.decode is not None:
            engines.append(ENGINE_DECODE)
        clamav_ready = (
            self.clamav is not None and self.clamav.available
        )
        if clamav_ready:
            engines.append("ClamAV")
        if use_anomaly:
            engines.append(ENGINE_AI)
        summary.engines_used = engines

        files = list(self.iter_files(root))
        summary.total_files = len(files)
        if on_status:
            on_status(f"Menemukan {len(files)} berkas untuk diperiksa", len(files))

        # --- Tahap 1: per berkas, mesin yang cepat dan murah ---------------- #
        examined: list[str] = []
        cached_count = 0
        for index, path in enumerate(files, start=1):
            if stop_event.is_set():
                break
            summary.scanned_files += 1
            findings, sha256, info = self._scan_one_with_timeout(path, use_cache)
            if info["error"]:
                summary.error_files += 1
            if info["skipped"]:
                summary.skipped_files += 1
            if info["from_cache"]:
                cached_count += 1
            else:
                # Berkas yang hasilnya diambil dari cache tidak perlu dikirim
                # lagi ke ClamAV - itu yang membuat pemindaian ulang cepat.
                examined.append(path)
            self._absorb(summary, findings, on_finding)
            if on_progress:
                on_progress(index, len(files), path, sha256, info["skipped"] or info["error"])
        summary.cached_files = cached_count

        # --- Tahap 2: ClamAV sekaligus dalam kelompok ----------------------- #
        # ClamAV memuat basis datanya sekali per pemanggilan, jadi berkas
        # dikirim berkelompok. Tahap ini dilewati bila pemindaian dihentikan.
        if clamav_ready and examined and not stop_event.is_set():
            if on_status:
                on_status("Memeriksa kelompok berkas dengan ClamAV", len(examined))

            def on_batch(done: int, total: int) -> None:
                if on_status:
                    on_status(f"ClamAV: {done}/{total} berkas diperiksa", total)

            result = self.clamav.scan_paths(examined, on_batch=on_batch)
            for path, signature in result.infected.items():
                finding = ClamAVEngine._finding(path, signature)
                self._absorb(summary, [finding], on_finding)
                self._merge_cache_findings(path, [finding])

        # --- Tahap 3: deteksi anomali dengan model AI lokal ----------------- #
        # Dijalankan paling akhir karena modelnya perlu melihat seluruh berkas
        # lebih dulu. Tahap ini tidak butuh internet dan tidak butuh kunci API.
        if use_anomaly and not stop_event.is_set() and files:
            if on_status:
                on_status(
                    f"Melatih model AI dari {len(files)} berkas untuk mencari "
                    "yang menyimpang",
                    len(files),
                )
            try:
                anomalies = find_anomalies(files)
            except Exception as error:  # noqa: BLE001 - AI tidak boleh menggagalkan pemindaian
                # Deteksi anomali bersifat tambahan. Kalau gagal, pemindaian
                # tetap dianggap berhasil dan pengguna diberi tahu.
                if on_status:
                    on_status(f"Deteksi anomali dilewati: {error}", len(files))
            else:
                findings = anomalies_to_findings(anomalies)
                self._absorb(summary, findings, on_finding)
                if on_status:
                    on_status(
                        f"Deteksi anomali selesai: {len(anomalies)} berkas menyimpang",
                        len(files),
                    )

        summary.elapsed = time.time() - started
        summary.stopped = stop_event.is_set()
        summary.finished_at = datetime.now()
        return summary

    def _scan_one_with_timeout(
        self, path: str, use_cache: bool
    ) -> tuple[list[Finding], str, dict]:
        """Jalankan pemeriksaan satu berkas dengan batas waktu.

        Batas waktu diperlukan karena berkas aneh bisa membuat pembacaan
        menggantung. Bila batasnya terlampaui, berkas dicatat sebagai
        bermasalah dan pemindaian lanjut - tidak menggantung selamanya.
        """
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(self._scan_file_internal, path, use_cache, False)
            try:
                return future.result(timeout=FILE_TIMEOUT_SECONDS)
            except FutureTimeout:
                info = {
                    "skipped": "",
                    "error": (
                        f"Melewati batas waktu {FILE_TIMEOUT_SECONDS:.0f} detik; "
                        f"berkas tidak bisa diperiksa"
                    ),
                    "size": 0,
                    "sha256": "",
                }
                return [], "", info
        finally:
            # wait=False supaya program tidak menunggu thread yang menggantung.
            executor.shutdown(wait=False)

    def _merge_cache_findings(self, path: str, extra: list[Finding]) -> None:
        """Gabungkan temuan tambahan ke catatan cache berkas.

        ClamAV baru berjalan setelah tahap pertama, jadi temuannya belum ada
        saat cache ditulis. Tanpa penggabungan ini, pemindaian ulang yang
        memakai cache akan kehilangan temuan ClamAV dan laporannya jadi tidak
        lengkap - padahal hasilnya sama.
        """
        try:
            stat = os.stat(path)
        except OSError:
            return
        context = self._cache_context()
        cached = self.db.get_cached(path, stat.st_size, stat.st_mtime)
        sha256 = ""
        existing: list[dict] = []
        if cached and cached[1].startswith(context):
            sha256, _verdict, existing = cached

        merged: list[Finding] = [finding_from_dict(item) for item in existing]
        merged.extend(extra)
        unique: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for finding in merged:
            if finding.key in seen:
                continue
            seen.add(finding.key)
            unique.append(finding)

        self.db.put_cached(
            path,
            stat.st_size,
            stat.st_mtime,
            sha256,
            f"{context}:{self._verdict_of(unique)}",
            [finding_to_dict(f) for f in unique],
        )

    @staticmethod
    def _verdict_of(findings: list[Finding]) -> str:
        if not findings:
            return "bersih"
        from .config import SEVERITY_ORDER

        return min(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @staticmethod
    def _absorb(summary: ScanSummary, findings: list[Finding], on_finding) -> None:
        """Masukkan temuan ke ringkasan dan teruskan ke pemanggil."""
        seen = {(f.path, f.rule, f.detail) for f in summary.findings}
        for finding in findings:
            if finding.key in seen:
                continue
            seen.add(finding.key)
            summary.findings.append(finding)
            if finding.severity == "MALWARE":
                summary.infected += 1
            elif finding.severity == SEV_SUSPICIOUS:
                summary.suspicious += 1
            else:
                summary.notes += 1
            if on_finding:
                on_finding(finding)

    def _cache_context(self) -> str:
        """Tanda pengenal keadaan mesin, dipakai menentukan cache masih sah.

        Cache harus dianggap usang bila basis data hash atau aturan YARA
        berubah: hasil lama yang dibuat dengan aturan lama tidak boleh dipercaya
        begitu saja.
        """
        parts = [f"h{self.db.count()}", f"d{1 if self.decode is not None else 0}"]
        if self.yara is not None:
            try:
                parts.append(f"y{int(os.path.getmtime(self.yara.rules_path))}")
            except OSError:
                parts.append("y0")
        return "v2-" + "-".join(parts)
