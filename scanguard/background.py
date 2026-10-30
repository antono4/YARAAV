"""Mode latar belakang: menjalankan pemantauan tanpa membuka jendela.

Dipakai oleh "mulai otomatis saat Windows menyala". Yang berjalan di latar
belakang hanya pemantauannya - bukan jendela penuh, karena jendela lebar yang
muncul sendiri setiap kali pengguna menyalakan komputer akan segera ditutup,
dan setelah ditutup pemantauannya ikut mati.

Batas yang harus dipahami sebelum memakai mode ini:

* **Tidak ada lambang di baki sistem.** Berkas ini hanya memakai pustaka standar,
  jadi tidak ada `pystray`. Akibatnya program ini tidak punya ikon di sudut kanan
  bawah layar: untuk mematikannya, pengguna membuka jendela penuh lalu menekan
  "Perlindungan Nyata" sekali. Karena itu jendela utama selalu tersedia lewat
  menu Windows biasa.
* **Temuan dicatat ke berkas, bukan ke jendela.** Kalau tidak, temuan yang
  terjadi saat pengguna tidak melihat layar akan hilang tanpa jejak. Lokasinya
  dilaporkan saat program dijalankan dengan `--rtp`.

Catatan keamanan: berkas ini tidak pernah menjalankan apa pun dari berkas yang
diperiksa. Ia hanya memanggil mesin pemindai yang sama dengan yang dipakai mode
berjendela.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time

from .config import APP_NAME, data_dir, SEV_MALWARE, SEV_NOTE
from .hashes import HashDatabase
from .quarantine import Quarantine
from .realtime import RealtimeMonitor
from .scanner import ScanEngine
from .settings import Settings

def log_path() -> str:
    """Berkas catatan pemantauan latar belakang."""
    return os.path.join(data_dir(), "pemantauan.log")


class BackgroundWatcher:
    """Jalankan RealtimeMonitor tanpa jendela, catat temuannya ke berkas."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.load()
        self.quarantine = Quarantine()
        self.engine = ScanEngine(
            database=HashDatabase(),
            quarantine=self.quarantine,
            use_yara=self.settings.use_yara,
            use_pe=self.settings.use_pe,
            use_clamav=self.settings.use_clamav,
            use_decode=self.settings.use_decode,
        )
        # Sama seperti mode berjendela: lokasi clamscan dan daftar pengecualian
        # diatur setelah mesin dibuat, karena keduanya bukan parameter
        # pembuatan mesin.
        if self.settings.clamav_path:
            self.engine.clamav.executable = self.settings.clamav_path
        self.engine.exclusions = list(self.settings.exclusions)
        self.monitor: RealtimeMonitor | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.started_at: float | None = None

    # ------------------------------------------------------------------ log -- #

    def _catat(self, baris: str) -> None:
        """Tulis satu baris ke berkas catatan, sekaligus ke stderr bila ada.

        Berkas catatan dibuka dan ditutup setiap kali, bukan ditahan terbuka:
        program ini bisa dimatikan paksa saat Windows keluar, dan baris yang
        masih di penyangga memori akan hilang tanpa jejak.
        """
        # Stempel waktu jam dinding, bukan durasi: catatan ini dibaca manusia
        # yang ingin tahu kapan sesuatu terjadi. human_time() mengubah detik
        # menjadi "8 menit 12 detik", yang salah untuk keperluan ini.
        teks = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {baris}\n"
        try:
            with open(log_path(), "a", encoding="utf-8") as berkas:
                berkas.write(teks)
        except OSError:
            # Tidak bisa menulis catatan tidak boleh menghentikan pemantauan.
            pass
        if sys.stderr is not None:
            try:
                sys.stderr.write(teks)
                sys.stderr.flush()
            except (OSError, ValueError):
                pass

    # -------------------------------------------------------------- kendali -- #

    def folders(self) -> list[str]:
        return [f for f in self.settings.rtp_folders if os.path.isdir(f)]

    def start(self) -> bool:
        """Mulai memantau. Kembalikan False bila tidak ada folder yang bisa dipantau."""
        folders = self.folders()
        if not folders:
            self._catat(
                "Tidak ada folder pantauan yang bisa dipakai. "
                "Tambahkan lewat jendela ScanGuard > Perlindungan Nyata."
            )
            return False
        self.monitor = RealtimeMonitor(
            engine=self.engine,
            on_event=self._kejadian,
            folders=folders,
            interval=self.settings.rtp_interval,
            on_error=lambda error: self._catat(f"Kesalahan pemantauan: {error}"),
        )
        self.monitor.start()
        self.started_at = time.time()
        self._catat(
            "Pemantauan latar belakang AKTIF. Memantau: "
            + ", ".join(folders)
            + f". Jeda {self.settings.rtp_interval:g} detik."
        )
        return True

    def stop(self) -> None:
        self._stop.set()
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
        # Basis data hash harus ditutup: kalau tidak, koneksi SQLite-nya tetap
        # terbuka sampai proses berakhir, dan SQLite melaporkan
        # "unclosed database" saat proses dimatikan dengan sopan.
        try:
            self.engine.db.close()
        except (AttributeError, OSError):
            pass

    def run_forever(self) -> int:
        """Jalankan sampai diminta berhenti. Kembalikan kode keluar."""
        if not self.start():
            return 3

        # Ctrl+C dan permintaan berhenti dari sistem harus benar-benar
        # menghentikan pemantauan, bukan hanya menghentikan penantian. Tanpa
        # penangan ini, berkas catatan bisa ditinggalkan dalam keadaan terbuka.
        def berhenti(_nomor, _bingkai) -> None:  # noqa: ANN001
            self._stop.set()

        for nama in ("SIGINT", "SIGTERM"):
            nomor = getattr(signal, nama, None)
            if nomor is not None:
                try:
                    signal.signal(nomor, berhenti)
                except (OSError, ValueError):
                    # Di Windows sebagian sinyal tidak bisa ditangani dari
                    # thread non-utama; abaikan dan andalkan penantian di bawah.
                    pass

        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        finally:
            self.stop()
            self._catat("Pemantauan latar belakang berhenti.")
        return 0

    # -------------------------------------------------------------- kejadian -- #

    def _kejadian(self, event) -> None:  # noqa: ANN001 - RtEvent
        """Catat satu kejadian pemantauan. Dipanggil dari thread pemantau."""
        if event.error:
            self._catat(f"[PANTAU] {event.path}  {event.error}")
            return
        if event.clean:
            if self.settings.rtp_report_clean:
                self._catat(f"[PANTAU] {os.path.basename(event.path)}: bersih")
            return
        baris = [f"[PANTAU {event.severity}] {event.path}  ({event.action})"]
        for finding in event.findings:
            baris.append(f"    ({finding.engine}) {finding.rule}")
            baris.append(f"    {finding.detail}")
        self._catat("\n".join(baris))

        # Karantina otomatis hanya untuk MALWARE, dan hanya bila pengguna
        # memang menyalakannya. Di mode latar belakang tidak ada jendela untuk
        # bertanya, jadi tanpa pilihan ini temuan hanya dicatat.
        if event.severity == SEV_MALWARE and self.settings.rtp_auto_quarantine:
            temuan = event.findings[0] if event.findings else None
            ok, pesan = self.quarantine.quarantine_file(
                event.path,
                engine=temuan.engine if temuan else "RTP",
                rule=temuan.rule if temuan else "Pemantauan waktu nyata",
                detail=temuan.detail if temuan else "",
                severity=event.severity,
            )
            self._catat(
                f"    {'Dipindahkan ke karantina.' if ok else 'Gagal dikarantina: ' + pesan}"
            )
        elif event.severity == SEV_MALWARE:
            self._catat(
                "    Perlu tindakan: karantina otomatis mati, dan di mode latar "
                "belakang tidak ada jendela untuk bertanya. Buka ScanGuard > "
                "Karantina untuk menindaklanjuti."
            )


def main() -> int:
    """Jalankan pemantauan latar belakang."""
    watcher = BackgroundWatcher()
    if not watcher.settings.rtp_folders:
        sys.stderr.write(
            f"{APP_NAME}: belum ada folder pantauan. Buka jendela ScanGuard dan "
            "pilih Perlindungan Nyata lebih dulu.\n"
        )
        return 3
    return watcher.run_forever()
