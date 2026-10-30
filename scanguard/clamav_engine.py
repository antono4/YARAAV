"""Integrasi ClamAV: mesin signature sungguhan milik pihak ketiga.

ClamAV adalah antivirus open source yang dipakai untuk memindai lampiran email
di banyak server. Basis datanya berisi ratusan ribu tanda tangan malware dan
diperbarui beberapa kali sehari. Ini mesin dengan cakupan deteksi terluas di
proyek ini - jauh melampaui aturan YARA bawaan yang hanya contoh.

Dua hal penting tentang cara pemakaiannya:

1. **clamscan selalu memuat seluruh basis data lebih dulu.** Diukur di mesin
   uji: dibutuhkan sekitar 7,5 detik hanya untuk memuat basis data, baik untuk
   satu berkas maupun dua puluh berkas. Jadi memanggil clamscan per berkas akan
   sangat lambat. Karena itu berkas dikirim dalam kelompok besar sekaligus
   memakai opsi `--file-list`, yang juga menghindari batas panjang argumen
   perintah.
2. **ClamAV mungkin tidak terpasang.** Ini mesin opsional. Kalau `clamscan`
   tidak ditemukan, program harus tetap jalan dengan mesin lain dan memberi tahu
   pengguna dengan jelas - bukan gagal diam-diam.

Catatan tentang `--max-filesize`: nilai bawaannya (25 MB) membuat berkas besar
dilewati dan dianggap bersih. Itu berbahaya karena malware berukuran besar akan
lolos tanpa pemberitahuan, jadi batasnya dinaikkan.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field

from .config import ENGINE_CLAMAV, SEV_MALWARE, SEV_NOTE, SEV_SUSPICIOUS
from .core import Finding

# Jumlah berkas per pemanggilan clamscan. Basis data dimuat sekali per
# pemanggilan, jadi kelompok besar lebih hemat. Nilainya tidak boleh terlalu
# besar supaya kemajuan pemindaian tetap terlihat.
BATCH_SIZE = 200

# Batas ukuran berkas yang diperiksa ClamAV. Dinaikkan dari bawaan 25 MB.
MAX_SCAN_SIZE = "200M"

# Keluaran clamscan: "<path>: <tanda tangan> FOUND" atau "<path>: OK".
#
# Nama berkas boleh mengandung titik dua dan spasi (mis. "nama: aneh.txt"), jadi
# pemisah yang benar adalah kemunculan ": " TERAKHIR sebelum penanda FOUND/OK.
# Memakai pemisah pertama akan memotong nama berkas di tengah.
_LINE_FOUND = re.compile(r"^(?P<path>.+): (?P<signature>[^:]+) FOUND$")
_LINE_OK = re.compile(r"^(?P<path>.+): OK$")


@dataclass
class ClamAVStatus:
    available: bool
    message: str
    version: str = ""
    database_date: str = ""
    path: str = ""


@dataclass
class ClamAVResult:
    infected: dict[str, str] = field(default_factory=dict)
    clean: set[str] = field(default_factory=set)
    errors: dict[str, str] = field(default_factory=dict)
    warning: str = ""


def parse_clamscan_output(text: str) -> tuple[dict[str, str], set[str], dict[str, str]]:
    """Baca keluaran clamscan menjadi (terinfeksi, bersih, bermasalah).

    Dipisah dari pemanggilan programnya supaya bisa diuji dengan keluaran
    sungguhan yang sudah disimpan, tanpa perlu ClamAV terpasang.
    """
    infected: dict[str, str] = {}
    clean: set[str] = set()
    errors: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            continue
        if line.startswith("WARNING:"):
            continue
        match = _LINE_FOUND.match(line)
        if match:
            infected[match.group("path")] = match.group("signature")
            continue
        match = _LINE_OK.match(line)
        if match:
            clean.add(match.group("path"))
            continue
        if ": " in line and "Can't access file" not in line:
            path, _, message = line.partition(": ")
            # Baris kesalahan clamscan, misalnya "No such file or directory".
            errors[path] = message.strip()
    return infected, clean, errors


class ClamAVEngine:
    """Menjalankan clamscan untuk sekelompok berkas."""

    name = ENGINE_CLAMAV

    def __init__(self, executable: str | None = None, timeout: float = 900.0) -> None:
        self.executable = executable or shutil.which("clamscan") or "clamscan"
        self.timeout = timeout
        self._status: ClamAVStatus | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------ status -- #

    def detect(self, force: bool = False) -> ClamAVStatus:
        """Periksa apakah clamscan ada dan basis datanya bisa dimuat."""
        with self._lock:
            if self._status is not None and not force:
                return self._status

            found = shutil.which(self.executable) or (
                self.executable if os.path.isfile(self.executable) else None
            )
            if not found:
                self._status = ClamAVStatus(
                    False,
                    "clamscan tidak ditemukan. ClamAV adalah mesin opsional; "
                    "pasang dari https://www.clamav.net/downloads lalu jalankan "
                    "freshclam untuk mengunduh basis data, atau gunakan mesin "
                    "hash dan YARA yang sudah aktif.",
                )
                return self._status

            try:
                completed = subprocess.run(
                    [found, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except (OSError, subprocess.SubprocessError) as error:
                self._status = ClamAVStatus(
                    False, f"clamscan ada tetapi tidak bisa dijalankan: {error}"
                )
                return self._status

            version_line = (completed.stdout or completed.stderr or "").strip()
            # Contoh: "ClamAV 1.4.3/28169/Fri Oct 30 06:26:48 2026"
            parts = version_line.split("/")
            version = parts[0].strip() if parts else version_line
            database_date = parts[2].strip() if len(parts) > 2 else ""

            if completed.returncode != 0 or not database_date:
                self._status = ClamAVStatus(
                    False,
                    "clamscan ditemukan, tetapi basis data virus belum ada atau "
                    "tidak terbaca. Jalankan: sudo freshclam",
                    version=version,
                    path=found,
                )
                return self._status

            self._status = ClamAVStatus(
                True,
                f"ClamAV siap. Basis data diperbarui: {database_date}",
                version=version,
                database_date=database_date,
                path=found,
            )
            return self._status

    @property
    def status(self) -> ClamAVStatus:
        return self.detect()

    @property
    def available(self) -> bool:
        return self.detect().available

    # ------------------------------------------------------- pemindaian -- #

    def scan_paths(self, paths: list[str], on_batch=None) -> ClamAVResult:
        """Pindai daftar berkas dalam beberapa kelompok.

        on_batch(diproses, total) dipanggil setelah setiap kelompok selesai,
        supaya antarmuka bisa menampilkan kemajuan.
        """
        result = ClamAVResult()
        status = self.detect()
        if not status.available:
            result.warning = status.message
            return result
        if not paths:
            return result

        total = len(paths)
        for start in range(0, total, BATCH_SIZE):
            batch = paths[start : start + BATCH_SIZE]
            infected, clean, errors = self._run_batch(batch)
            result.infected.update(infected)
            result.clean.update(clean)
            result.errors.update(errors)
            if on_batch:
                on_batch(min(start + BATCH_SIZE, total), total)
        return result

    def _run_batch(self, batch: list[str]) -> tuple[dict, set, dict]:
        """Jalankan clamscan sekali untuk sekelompok berkas."""
        # Daftar berkas ditulis ke berkas sementara karena argumen perintah
        # punya batas panjang, sedangkan daftar berkas tidak.
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        try:
            with handle:
                for path in batch:
                    handle.write(path + "\n")
            command = [
                self.executable if os.path.isfile(self.executable) else "clamscan",
                "--no-summary",
                "--file-list=" + handle.name,
                "--max-filesize=" + MAX_SCAN_SIZE,
                "--max-scansize=" + MAX_SCAN_SIZE,
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
            except subprocess.TimeoutExpired:
                return {}, set(), {p: "Waktu pemindaian ClamAV habis" for p in batch}
            except OSError as error:
                return {}, set(), {p: f"clamscan gagal dijalankan: {error}" for p in batch}
            output = (completed.stdout or "") + "\n" + (completed.stderr or "")
            return parse_clamscan_output(output)
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                pass

    def scan_file(self, path: str) -> list[Finding]:
        """Pindai satu berkas (untuk keperluan uji atau pemindaian berkas tunggal)."""
        result = self.scan_paths([path])
        findings = []
        signature = result.infected.get(path)
        if signature:
            findings.append(self._finding(path, signature))
        elif path in result.errors:
            findings.append(
                Finding(
                    path=path,
                    engine=ENGINE_CLAMAV,
                    rule="ClamAV tidak bisa memeriksa",
                    detail=result.errors[path],
                    severity=SEV_NOTE,
                )
            )
        return findings

    @staticmethod
    def _finding(path: str, signature: str) -> Finding:
        """Ubah nama tanda tangan ClamAV menjadi temuan."""
        # ClamAV menamai tanda tangannya dengan awalan yang menunjukkan jenis
        # ancaman, misalnya "Win.Trojan.", "Unix.Malware.", "Eicar-".
        #
        # EICAR sengaja tetap digolongkan MALWARE meskipun isinya tidak
        # berbahaya: EICAR adalah cara standar industri untuk menyatakan "berkas
        # ini terdeteksi", dan mesin lain di program ini juga melaporkannya
        # sebagai malware. Berbeda pendapat antar mesin untuk berkas yang sama
        # hanya membingungkan pengguna. Yang diturunkan tingkatnya hanya
        # perangkat lunak yang tidak diinginkan (PUA/adware), karena itu memang
        # bukan malware.
        lowered = signature.lower()
        if any(
            word in lowered
            for word in ("pua", "adware", "toolbar", "unwanted", "riskware")
        ):
            severity = SEV_SUSPICIOUS
        else:
            severity = SEV_MALWARE
        return Finding(
            path=path,
            engine=ENGINE_CLAMAV,
            rule=signature,
            detail=f"ClamAV mengenali tanda tangan '{signature}'",
            severity=severity,
        )
