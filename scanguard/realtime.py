"""Perlindungan waktu nyata (RTP): periksa berkas begitu muncul di folder pantauan.

Cara kerjanya sengaja sederhana dan bisa diperiksa: setiap beberapa detik
program melihat daftar berkas di folder pantauan, membandingkannya dengan daftar
sebelumnya, lalu memeriksa berkas yang **baru** atau **berubah**. Tidak ada
pemantauan tingkat sistem operasi (tidak ada `ReadDirectoryChangesW`), jadi ini
bukan pengganti perlindungan waktu nyata antivirus komersial - hanya cara agar
berkas yang baru masuk tidak luput sampai pengguna memindai secara manual.

Dua hal yang harus dipahami tentang batasnya:

* **Bukan pencegahan.** Berkasnya sudah ada di disk sebelum diperiksa. Program
  ini melaporkan dan menawarkan karantina, bukan memblokir.
* **Ukuran folder menentukan biaya.** Membandingkan daftar berarti membaca
  seluruh pohon folder setiap putaran. Untuk folder berisi ratusan ribu berkas
  ini berat; karena itu jumlah folder pantauan dibatasi dan ada jeda antar
  putaran.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field

from .config import MAX_WATCHED_FOLDERS, SEVERITY_ORDER
from .core import Finding

# Berapa berkas baru yang diperiksa dalam satu putaran. Tanpa batas ini,
# menyalin folder berisi puluhan ribu berkas membuat program sibuk memeriksa
# berjam-jam tanpa sempat menampilkan apa pun.
MAX_FILES_PER_POLL = 60
# Jeda bawaan antar putaran.
DEFAULT_INTERVAL = 2.0


@dataclass
class RtEvent:
    """Satu kejadian yang ditemukan pemantauan."""

    path: str
    action: str  # "baru" atau "berubah"
    severity: str | None = None
    findings: list[Finding] = field(default_factory=list)
    sha256: str = ""
    error: str = ""

    @property
    def clean(self) -> bool:
        return self.severity is None and not self.error


def snapshot(root: str, is_excluded=None) -> dict[str, tuple[int, int]]:
    """Buat daftar berkas di bawah `root`: {path: (ukuran, waktu ubah)}.

    Berkas yang tidak bisa dibaca informasinya dilewati, bukan digagalkan:
    berkas bisa terhapus atau terkunci tepat saat penelusuran berjalan.
    """
    hasil: dict[str, tuple[int, int]] = {}
    for folder, _dirs, names in os.walk(root):
        for name in names:
            path = os.path.join(folder, name)
            if is_excluded is not None and is_excluded(path):
                continue
            try:
                info = os.stat(path)
            except OSError:
                continue
            hasil[path] = (info.st_size, info.st_mtime_ns)
    return hasil


def diff_snapshots(
    sebelum: dict[str, tuple[int, int]], sesudah: dict[str, tuple[int, int]]
) -> list[tuple[str, str]]:
    """Bandingkan dua daftar. Kembalikan [(path, "baru"|"berubah")]."""
    kejadian: list[tuple[str, str]] = []
    for path, info in sesudah.items():
        lama = sebelum.get(path)
        if lama is None:
            kejadian.append((path, "baru"))
        elif lama != info:
            kejadian.append((path, "berubah"))
    # Urutkan supaya hasilnya bisa diprediksi; os.walk tidak menjamin urutan.
    return sorted(kejadian)


class RealtimeMonitor:
    """Pemantau folder yang berjalan di thread sendiri.

    Kelas ini tidak menyentuh tkinter sama sekali. Ia memanggil `on_event` dari
    thread pemantau, dan tugas pemanggil (GUI) untuk memindahkan kejadian itu ke
    main thread lewat antrean. Aturan "hanya main thread yang menyentuh widget"
    tetap berlaku.
    """

    def __init__(
        self,
        engine,
        on_event,
        folders: list[str] | None = None,
        interval: float = DEFAULT_INTERVAL,
        on_error=None,
    ) -> None:
        self.engine = engine
        self.on_event = on_event
        self.on_error = on_error
        self.folders = list(folders or [])[:MAX_WATCHED_FOLDERS]
        self.interval = max(0.5, float(interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._snapshot: dict[str, tuple[int, int]] = {}
        self._paused = threading.Event()
        # Statistik, dibaca GUI untuk ditampilkan.
        self.checked = 0
        self.found = 0
        self.started_at: float | None = None
        self.last_poll: float | None = None

    # ------------------------------------------------------------ kendali -- #

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def paused(self) -> bool:
        return self._paused.is_set()

    def add_folder(self, folder: str) -> bool:
        """Tambah folder pantauan. Kembalikan False bila sudah penuh."""
        folder = os.path.abspath(folder)
        if folder in self.folders:
            return True
        if len(self.folders) >= MAX_WATCHED_FOLDERS:
            return False
        self.folders.append(folder)
        self._snapshot.update(snapshot(folder, self._is_excluded))
        return True

    def remove_folder(self, folder: str) -> None:
        folder = os.path.abspath(folder)
        self.folders = [f for f in self.folders if f != folder]
        for path in list(self._snapshot):
            if path.startswith(folder + os.sep):
                del self._snapshot[path]

    def pause(self) -> None:
        """Hentikan sementara pemeriksaan, misalnya saat pemindaian manual.

        Pemindaian manual dan pemantauan sama-sama memakai basis data cache yang
        sama. Menjalankan keduanya sekaligus bisa membuat SQLite terkunci.
        """
        self._paused.set()

    def resume(self) -> None:
        self._paused.clear()

    def start(self) -> bool:
        if self.running:
            return False
        self._stop.clear()
        # Daftar awal diambil lebih dulu supaya berkas yang sudah ada sebelum
        # pemantauan dinyalakan tidak ikut dilaporkan sebagai berkas baru.
        self._snapshot = {}
        for folder in self.folders:
            self._snapshot.update(snapshot(folder, self._is_excluded))
        self.started_at = time.time()
        self._thread = threading.Thread(
            target=self._loop, name="scanguard-rtp", daemon=True
        )
        self._thread.start()
        return True

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None
        self.started_at = None

    # -------------------------------------------------------------- inti -- #

    def _is_excluded(self, path: str) -> bool:
        """Berkas yang tidak boleh diperiksa pemantauan.

        Karantina dan folder data harus dilewati. Kalau tidak, berkas yang baru
        dikarantina akan terlihat sebagai berkas baru di folder karantina, lalu
        dikarantina lagi - berputar tanpa henti.
        """
        if self.engine.is_excluded(path):
            return True
        from .config import data_dir

        try:
            return os.path.abspath(path).startswith(os.path.abspath(data_dir()) + os.sep)
        except OSError:
            return False

    def poll(self) -> list[RtEvent]:
        """Satu putaran pemeriksaan. Dipanggil dari thread pemantau."""
        if self.paused:
            return []
        kejadian: list[RtEvent] = []
        for folder in list(self.folders):
            sekarang = snapshot(folder, self._is_excluded)
            # Jeda diperiksa lagi di sini: penelusuran folder bisa berlangsung
            # lama, dan permintaan jeda yang datang di tengah penelusuran harus
            # dihormati. Tanpa pemeriksaan kedua ini, berkas yang muncul tepat
            # saat pengguna menekan "jeda" tetap diperiksa.
            if self.paused:
                break
            for path, action in diff_snapshots(self._snapshot, sekarang)[
                :MAX_FILES_PER_POLL
            ]:
                kejadian.append(self._check(path, action))
            # Daftar lama diganti sebagian: berkas di luar folder ini harus
            # tetap dipertahankan supaya tidak dilaporkan ulang sebagai baru.
            for path in list(self._snapshot):
                if path.startswith(folder + os.sep) or path == folder:
                    del self._snapshot[path]
            self._snapshot.update(sekarang)
        self.last_poll = time.time()
        return kejadian

    def _check(self, path: str, action: str) -> RtEvent:
        """Periksa satu berkas dan tentukan tingkat terburuknya."""
        event = RtEvent(path=path, action=action)
        try:
            if not os.path.isfile(path):
                return event
            findings = self.engine.scan_file(path)
        except OSError as error:
            event.error = f"Tidak bisa memeriksa: {error}"
            return event
        except Exception as error:  # noqa: BLE001
            # Satu berkas yang membuat mesin gagal tidak boleh menghentikan
            # pemantauan; kejadiannya dilaporkan sebagai kesalahan.
            event.error = f"Gagal diperiksa: {error}"
            return event
        self.checked += 1
        event.findings = findings
        if findings:
            terburuk = min(findings, key=lambda f: SEVERITY_ORDER[f.severity])
            event.severity = terburuk.severity
            self.found += 1
        return event

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                for event in self.poll():
                    self.on_event(event)
            except Exception as error:  # noqa: BLE001
                # Pemantauan tidak boleh mati diam-diam karena satu kesalahan.
                if self.on_error is not None:
                    try:
                        self.on_error(error)
                    except Exception:  # noqa: BLE001
                        pass
            # Ditunggu dengan Event supaya stop() tidak perlu menunggu jeda
            # penuh; tanpa ini menutup program terasa menggantung.
            self._stop.wait(self.interval)
