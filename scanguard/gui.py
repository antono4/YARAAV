"""Antarmuka grafis ScanGuard (tkinter).

Aturan terpenting di berkas ini: **hanya main thread yang boleh menyentuh
widget tkinter.** Pemindaian berjalan di thread pekerja, dan thread itu tidak
pernah memanggil `configure()` atau `insert()`. Ia hanya menaruh kejadian ke
`queue.Queue`, lalu main thread mengosongkan antrean itu beberapa kali per
detik lewat `root.after()`.

Kalau aturan ini dilanggar, jendela akan membeku ("Not Responding") atau
program mati dengan error dari dalam Tk.
"""

from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .ai.analyst import AiAnalyst
from .ai.assistant import Assistant
from .ai.base import build_client_from_settings
from .ai.cache import AiCache
from .config import (
    MAX_WATCHED_FOLDERS,
    APP_NAME,
    APP_TAGLINE,
    APP_VERSION,
    SEV_MALWARE,
    SEV_NOTE,
    SEV_SUSPICIOUS,
    SEVERITY_TAGS,
    TAG_INFO,
    TAG_OK,
    resource_path,
)
from .core import Finding, format_size, human_time
from .dialogs import (
    AssistantWindow,
    QuarantineWindow,
    SettingsWindow,
    UpdateWindow,
)
from .hashes import HashDatabase
from .quarantine import Quarantine
from .realtime import RtEvent, RealtimeMonitor
from .report import build_report
from .scanner import ScanEngine
from .settings import Settings
from .splash import SplashScreen
from .theme import COLORS

class ScanGuardApp:
    """Jendela utama."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.colors = COLORS
        self.settings = Settings.load()

        self.queue: queue.Queue = queue.Queue()
        # Penanda waktu dari root.after(). Disimpan supaya bisa dibatalkan saat
        # jendela ditutup. Tanpa pembatalan, Tk akan melaporkan
        # 'invalid command name ..._pump_queue' karena callback dijadwalkan pada
        # widget yang sudah dihancurkan.
        self._pump_job: str | None = None
        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.scanning = False
        self.last_summary = None
        self.engine_status: list[dict] = []
        self._closed = False
        # Tombol sidebar dan halaman yang sedang tampil. Dipakai untuk menandai
        # menu yang aktif, seperti aplikasi desktop pada umumnya.
        self.nav_buttons: dict[str, tk.Button] = {}
        self.current_page = "beranda"

        self.db = HashDatabase()
        self.quarantine = Quarantine()
        self.engine = self._make_engine()
        self.ai_cache = AiCache()
        self.assistant = Assistant()
        # Perlindungan waktu nyata. Objeknya dibuat di sini tetapi belum
        # dijalankan; pengguna yang memutuskan menyalakannya.
        self.rtp: RealtimeMonitor | None = None

        self._build_window()
        self._build_ui()
        self._set_window_icon()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._pump_queue()
        self._update_rtp_status()
        self._announce_startup()

    # ----------------------------------------------------------- persiapan -- #

    def _make_engine(self) -> ScanEngine:
        engine = ScanEngine(
            database=self.db,
            quarantine=self.quarantine,
            use_clamav=self.settings.use_clamav,
            use_yara=self.settings.use_yara,
            use_pe=self.settings.use_pe,
        )
        if self.settings.clamav_path:
            engine.clamav.executable = self.settings.clamav_path
        engine.exclusions = list(self.settings.exclusions)
        return engine

    def _build_window(self) -> None:
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1020x780")
        self.root.minsize(900, 640)
        self.root.configure(bg=self.colors["bg"])

    def _set_window_icon(self) -> None:
        """Pasang ikon jendela. resource_path() menangani mode .exe satu berkas."""
        try:
            png = resource_path(os.path.join("assets", "icon_256.png"))
            if os.path.exists(png):
                self._icon_image = tk.PhotoImage(file=png)
                self.root.iconphoto(True, self._icon_image)
                return
        except tk.TclError:
            pass
        try:
            ico = resource_path(os.path.join("assets", "icon.ico"))
            if os.path.exists(ico):
                self.root.iconbitmap(ico)
        except tk.TclError:
            pass  # ikon gagal dipasang bukan alasan menggagalkan program

    # --------------------------------------------------------------- tata letak -- #

    def _build_ui(self) -> None:
        self._build_topbar()

        # Tata letak gaya aplikasi keamanan: panel navigasi tetap di kiri,
        # isi halaman di kanan. Panel kiri tidak ikut bergulir atau melebar
        # saat jendela diperbesar, sehingga tombol-tombolnya selalu di tempat
        # yang sama.
        shell = tk.Frame(self.root, bg=self.colors["bg"])
        shell.pack(fill="both", expand=True)

        self._build_sidebar(shell)

        main = tk.Frame(shell, bg=self.colors["bg"], padx=18, pady=14)
        main.pack(side="left", fill="both", expand=True)

        self._build_controls(main)
        self._build_progress(main)
        # Footer dipasang dengan side="bottom" SEBELUM area log. Urutan ini
        # penting: widget yang memakai expand=True (area log) menyerap seluruh
        # ruang sisa, sehingga widget sesudahnya bisa terhimpit sampai tinggi
        # 1 piksel. Dengan dipasang lebih dulu di sisi bawah, footer selalu
        # mendapat tingginya dan area log yang mengisi sisanya.
        self._build_footer(main)
        self._build_log(main)

    def _build_topbar(self) -> None:
        """Bilah atas: merek di kiri, keterangan basis data di kanan."""
        topbar = tk.Frame(self.root, bg=self.colors["panel"])
        topbar.pack(fill="x")

        # Garis oranye setebal beberapa piksel di tepi atas. Ini satu-satunya
        # tempat warna merek dipakai pada bidang besar, dan karena hanya garis
        # (bukan teks) kontrasnya tidak perlu 4,5:1.
        tk.Frame(topbar, bg=self.colors["brand"], height=3).pack(fill="x")

        isi = tk.Frame(topbar, bg=self.colors["panel"], padx=16, pady=12)
        isi.pack(fill="x")

        # Ikon perisai digambar dengan Canvas, bukan emoji: emoji tampil sebagai
        # kotak kosong di Windows yang tidak punya font emoji.
        canvas = tk.Canvas(
            isi,
            width=40,
            height=44,
            bg=self.colors["panel"],
            highlightthickness=0,
        )
        canvas.pack(side="left")
        self._draw_shield(canvas)

        titles = tk.Frame(isi, bg=self.colors["panel"])
        titles.pack(side="left", padx=(12, 0))
        tk.Label(
            titles,
            text=APP_NAME,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")
        tk.Label(
            titles,
            text=APP_TAGLINE,
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        self.db_label = tk.Label(
            isi,
            text="",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="right",
        )
        self.db_label.pack(side="right")
        self.refresh_database_label()

        tk.Frame(topbar, bg=self.colors["border"], height=1).pack(fill="x")

    def _build_sidebar(self, parent: tk.Frame) -> None:
        """Panel navigasi kiri, seperti pada aplikasi keamanan umumnya."""
        # Lebar 216 px memberi kelonggaran untuk label terpanjang
        # ("Perbarui Basis Data"). Dengan 196 px label itu hanya bersisa 1 px,
        # sehingga font yang sedikit lebih lebar - misalnya Segoe UI asli di
        # Windows - akan memotongnya.
        sidebar = tk.Frame(parent, bg=self.colors["sidebar"], width=216)
        # pack_propagate(False) wajib: tanpa itu lebar panel mengikuti isinya,
        # sehingga ukurannya berubah-ubah mengikuti panjang teks menu.
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        isi = tk.Frame(sidebar, bg=self.colors["sidebar"], padx=10, pady=14)
        isi.pack(fill="both", expand=True)

        # Beranda adalah halaman yang benar-benar ditampilkan di panel kanan.
        # Menu lain membuka jendela sendiri - sama seperti sebelumnya, tetapi
        # kini tersusun rapi di satu tempat alih-alih berjejer di baris tombol.
        menu = [
            ("beranda", "Beranda", self.show_home),
            ("pindai", "Pindai Cepat", self.choose_folder),
            ("karantina", "Karantina", self.open_quarantine),
            ("rtp", "Perlindungan Nyata", self.toggle_rtp),
            ("asisten", "Asisten AI", self.open_assistant),
            ("pembaruan", "Perbarui Basis Data", self.open_update),
            ("pengaturan", "Pengaturan", self.open_settings),
        ]
        for key, label, command in menu:
            button = self._nav_button(isi, label, command, key)
            button.pack(fill="x", pady=2)
            self.nav_buttons[key] = button

        # Keterangan kecil di kaki panel: mengingatkan sifat alat ini tanpa
        # perlu dibuka di tengah halaman.
        tk.Label(
            isi,
            text="Alat bantu pemeriksaan.\nBukan pengganti antivirus utama.",
            bg=self.colors["sidebar"],
            fg=self.colors["muted"],
            font=("Segoe UI", 8),
            justify="left",
            anchor="w",
            wraplength=190,
        ).pack(side="bottom", fill="x", pady=(12, 0))

        tk.Frame(parent, bg=self.colors["border"], width=1).pack(side="left", fill="y")
        self._mark_active("beranda")

    def _nav_button(self, parent, label: str, command, key: str) -> tk.Button:
        """Tombol menu sidebar.

        Status aktif ditandai warna sorotan, bukan sekadar diingat di dalam
        variabel - pengguna harus bisa melihat halaman mana yang sedang dibuka.
        """
        return tk.Button(
            parent,
            text="  " + label,
            command=command,
            bg=self.colors["sidebar"],
            fg=self.colors["sidebar_text"],
            activebackground=self.colors["sidebar_hover"],
            activeforeground=self.colors["sidebar_text"],
            relief="flat",
            bd=0,
            anchor="w",
            padx=12,
            pady=9,
            cursor="hand2",
            font=("Segoe UI", 10),
        )

    def _mark_active(self, key: str) -> None:
        self.current_page = key
        for name, button in self.nav_buttons.items():
            if name == key:
                button.configure(
                    bg=self.colors["sidebar_active"],
                    fg=self.colors["accent"],
                    font=("Segoe UI", 10, "bold"),
                )
            else:
                button.configure(
                    bg=self.colors["sidebar"],
                    fg=self.colors["sidebar_text"],
                    font=("Segoe UI", 10),
                )

    def show_home(self) -> None:
        """Kembali ke halaman utama dan tandai menunya aktif."""
        self._mark_active("beranda")
        self.root.focus_force()

    def _build_controls(self, parent: tk.Frame) -> None:
        """Kartu utama: status perisai, tombol pindai besar, dan pemilih folder.

        Susunannya meniru aplikasi keamanan pada umumnya: satu tombol besar di
        tengah sebagai tindakan utama, dengan keterangan status di atasnya.
        Tombol besar lebih mudah ditekan dan langsung menunjukkan apa yang
        seharusnya dilakukan pengguna.
        """
        panel = tk.Frame(parent, bg=self.colors["panel"], padx=18, pady=12)
        panel.pack(fill="x")

        # --- Baris status perisai ------------------------------------------- #
        baris_status = tk.Frame(panel, bg=self.colors["panel"])
        baris_status.pack(fill="x")

        self.shield_canvas = tk.Canvas(
            baris_status,
            width=52,
            height=56,
            bg=self.colors["panel"],
            highlightthickness=0,
        )
        self.shield_canvas.pack(side="left")
        self._draw_shield(self.shield_canvas)

        teks_status = tk.Frame(baris_status, bg=self.colors["panel"])
        teks_status.pack(side="left", padx=(14, 0))

        self.headline_var = tk.StringVar(value="Komputer belum diperiksa")
        tk.Label(
            teks_status,
            textvariable=self.headline_var,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            font=("Segoe UI", 15, "bold"),
            anchor="w",
        ).pack(anchor="w")

        self.subheadline_var = tk.StringVar(
            value="Pilih folder, lalu jalankan pemindaian."
        )
        tk.Label(
            teks_status,
            textvariable=self.subheadline_var,
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        # --- Baris folder ---------------------------------------------------- #
        baris_folder = tk.Frame(panel, bg=self.colors["panel"])
        baris_folder.pack(fill="x", pady=(10, 0))

        kotak_folder = tk.Frame(
            baris_folder, bg=self.colors["bg"], padx=10, pady=8
        )
        kotak_folder.pack(side="left", fill="x", expand=True)

        self.folder_var = tk.StringVar(value="Belum ada folder dipilih")
        tk.Label(
            kotak_folder,
            textvariable=self.folder_var,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            font=("Consolas", 9),
            anchor="w",
        ).pack(fill="x")

        self.choose_btn = self._button(baris_folder, "Pilih Folder", self.choose_folder)
        self.choose_btn.pack(side="left", padx=(10, 0))

        # --- Tombol besar ---------------------------------------------------- #
        baris_aksi = tk.Frame(panel, bg=self.colors["panel"])
        baris_aksi.pack(fill="x", pady=(10, 0))

        self.scan_btn = tk.Button(
            baris_aksi,
            text="MULAI PINDAI",
            command=self.start_scan,
            bg=self.colors["fill"],
            fg="#ffffff",
            activebackground=self.colors["fill_active"],
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=28,
            pady=10,
            cursor="hand2",
            font=("Segoe UI", 12, "bold"),
        )
        self.scan_btn.pack(side="left", fill="x", expand=True)

        self.stop_btn = self._button(baris_aksi, "Hentikan", self.stop_scan)
        self.stop_btn.pack(side="left", padx=(10, 0))
        self.stop_btn.configure(state="disabled")

        # --- Alat bantu ------------------------------------------------------ #
        baris_alat = tk.Frame(panel, bg=self.colors["panel"])
        baris_alat.pack(fill="x", pady=(10, 0))
        for text, command in (
            ("Simpan Laporan", self.save_report),
            ("Bersihkan Log", self.clear_log),
        ):
            self._button(baris_alat, text, command).pack(side="left", padx=(0, 8))

    def _draw_shield(self, canvas: tk.Canvas, outline: str | None = None) -> None:
        """Gambar perisai di kanvas.

        Digambar sebagai vektor, bukan emoji: emoji tampil sebagai kotak kosong
        di Windows yang tidak punya font emoji, dan tidak bisa diwarnai.
        """
        w = canvas.winfo_reqwidth()
        h = canvas.winfo_reqheight()
        tengah = w / 2
        points = [
            tengah, 3,
            w - 4, h * 0.22,
            w - 4, h * 0.55,
            tengah, h - 3,
            4, h * 0.55,
            4, h * 0.22,
        ]
        canvas.create_polygon(
            points,
            fill=self.colors["brand"],
            outline=outline or self.colors["accent"],
            width=2,
        )
        canvas.create_line(
            tengah - 8, h * 0.5,
            tengah - 2, h * 0.6,
            tengah + 9, h * 0.36,
            fill="#ffffff",
            width=3,
            capstyle="round",
            joinstyle="round",
        )

    def _build_progress(self, parent: tk.Frame) -> None:
        wrapper = tk.Frame(parent, bg=self.colors["panel"], padx=18, pady=10)
        wrapper.pack(fill="x", pady=(10, 0))

        self.status_var = tk.StringVar(value="Siap. Pilih folder lalu tekan Mulai Pindai.")
        tk.Label(
            wrapper,
            textvariable=self.status_var,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(fill="x")

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "SG.Horizontal.TProgressbar",
            troughcolor=self.colors["trough"],
            background=self.colors["bar"],
            bordercolor=self.colors["trough"],
            lightcolor=self.colors["bar"],
            darkcolor=self.colors["bar"],
            thickness=14,
        )
        self.progress = ttk.Progressbar(
            wrapper,
            style="SG.Horizontal.TProgressbar",
            mode="determinate",
            maximum=100,
        )
        self.progress.pack(fill="x", pady=(6, 0))

        self.counter_var = tk.StringVar(value="")
        tk.Label(
            wrapper,
            textvariable=self.counter_var,
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", pady=(4, 0))

        # Status perlindungan waktu nyata selalu terlihat di kartu utama:
        # fitur yang berjalan di latar belakang harus kelihatan keadaannya,
        # bukan tersembunyi di dalam menu.
        self.rtp_var = tk.StringVar(value="")
        tk.Label(
            wrapper,
            textvariable=self.rtp_var,
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

    def _build_log(self, parent: tk.Frame) -> None:
        wrapper = tk.Frame(parent, bg=self.colors["panel"], padx=18, pady=10)
        # expand=True: area log mengisi seluruh sisa ruang di bawah footer.
        wrapper.pack(fill="both", expand=True, pady=(10, 0))

        tk.Label(
            wrapper,
            text="Hasil pemindaian",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill="x", pady=(0, 6))

        # Kotak log diberi latar agak berbeda dari kartunya supaya batas area
        # yang bisa digulir terlihat jelas di tema terang.
        holder = tk.Frame(wrapper, bg=self.colors["bg"])
        holder.pack(fill="both", expand=True)

        self.log = tk.Text(
            holder,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            wrap="word",
            padx=12,
            pady=10,
            font=("Consolas", 9),
            spacing1=1,
            spacing3=2,
        )
        scrollbar = tk.Scrollbar(holder, command=self.log.yview)
        self.log.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

        # Nama tag Tk tidak boleh mengandung spasi - Tk akan memecahnya menjadi
        # beberapa tag dan warnanya tidak terpakai. Karena itu label manusia
        # dipetakan lebih dulu lewat SEVERITY_TAGS di config.
        self.log.tag_configure(SEVERITY_TAGS[SEV_MALWARE], foreground=self.colors["danger"])
        self.log.tag_configure(
            SEVERITY_TAGS[SEV_SUSPICIOUS], foreground=self.colors["warn"]
        )
        self.log.tag_configure(SEVERITY_TAGS[SEV_NOTE], foreground=self.colors["note"])
        self.log.tag_configure(TAG_OK, foreground=self.colors["ok"])
        self.log.tag_configure(TAG_INFO, foreground=self.colors["muted"])

        # Log hanya untuk dibaca: pengguna boleh menyalin dan menggulir, tetapi
        # tidak boleh mengetik ke dalamnya.
        self.log.bind("<Key>", self._block_typing)
        self.log.bind("<<Paste>>", lambda _e: "break")
        self.log.bind("<<Cut>>", lambda _e: "break")

    def _build_footer(self, parent: tk.Frame) -> None:
        footer = tk.Frame(parent, bg=self.colors["bg"], padx=4)
        # Jarak atas/bawah diberikan lewat pack(), bukan lewat Frame: pady pada
        # Frame Tk hanya menerima satu angka, tidak menerima pasangan.
        footer.pack(side="bottom", fill="x", pady=(10, 2))

        # wraplength membuat teks membungkus ke baris berikutnya, bukan
        # terpotong di tepi jendela saat jendela dipersempit.
        self.footer_label = tk.Label(
            footer,
            text=(
                "Alat bantu pemeriksaan, bukan pengganti antivirus utama. "
                "Deteksi berbasis hash, pola, dan struktur hanya mengenali yang "
                "sudah diketahui."
            ),
            bg=self.colors["bg"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=900,
        )
        self.footer_label.pack(fill="x")
        # Sesuaikan lebar pembungkusan saat jendela diubah ukurannya.
        footer.bind(
            "<Configure>",
            lambda event: self.footer_label.configure(wraplength=max(200, event.width - 8)),
        )

    def _button(self, parent, text: str, command, primary: bool = False) -> tk.Button:
        if primary:
            bg, active, fg = (
                self.colors["fill"],
                self.colors["fill_active"],
                "#ffffff",
            )
        else:
            bg, active, fg = (
                self.colors["secondary"],
                self.colors["secondary_active"],
                self.colors["text"],
            )
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
            font=("Segoe UI", 10, "bold") if primary else ("Segoe UI", 10),
        )

    @staticmethod
    def _block_typing(event) -> str | None:
        # Izinkan tombol navigasi dan salin, tolak yang lain.
        allowed = {
            "Up", "Down", "Left", "Right", "Prior", "Next", "Home", "End",
            "Shift_L", "Shift_R", "Control_L", "Control_R", "Caps_Lock",
            "Tab", "Escape",
        }
        if event.keysym in allowed or (event.state & 0x4):  # 0x4 = Ctrl ditekan
            return None
        return "break"

    # ---------------------------------------------------------------- log -- #

    def _append_log(self, text: str, tag: str = TAG_INFO) -> None:
        """Tambahkan satu baris ke area log (hanya dari main thread)."""
        tag = SEVERITY_TAGS.get(tag, tag)
        self.log.configure(state="normal")
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def log_line(self, text: str, tag: str = TAG_INFO) -> None:
        """Cara aman menulis ke log dari mana saja."""
        self._append_log(text + "\n", tag)

    def clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------------- kejadian -- #

    def _announce_startup(self) -> None:
        self.log_line(f"{APP_NAME} {APP_VERSION} siap dipakai.", TAG_OK)
        self.log_line(
            "Pilih folder, lalu tekan \"Mulai Pindai\". Pemindaian berjalan di "
            "latar belakang sehingga jendela ini tetap bisa dipakai."
        )
        self.log_line("")

    def choose_folder(self) -> None:
        if self.scanning:
            return
        folder = filedialog.askdirectory(title="Pilih folder untuk dipindai")
        if not folder:
            return
        self.folder_var.set(folder)
        self.status_var.set(f"Folder dipilih: {folder}")
        self.log_line(f"Folder dipilih: {folder}")

    # --------------------------------------------------------- pemindaian -- #

    def start_scan(self) -> None:
        if self.scanning:
            return
        # Pemantauan dijeda dulu: pemindaian manual dan pemantauan memakai
        # basis data cache yang sama, dan dua penulis bersamaan bisa membuat
        # SQLite melaporkan "database is locked".
        if self.rtp is not None and self.rtp.running:
            self.rtp.pause()
            self._update_rtp_status()
        folder = self.folder_var.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning(
                "Folder belum dipilih",
                "Pilih folder yang ingin diperiksa lebih dulu dengan tombol "
                "\"Pilih Folder\".",
            )
            return

        self.scanning = True
        self._mark_active("pindai")
        self.stop_event = threading.Event()
        self.scan_btn.configure(state="disabled")
        self.choose_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.configure(value=0)
        self.counter_var.set("")
        self.clear_log()
        self.log_line(f"=== Mulai pemindaian: {folder} ===\n")

        # Thread pekerja. Ia tidak menyentuh widget; hasilnya dikirim lewat antrean.
        self.worker = threading.Thread(
            target=self._worker_scan, args=(folder,), daemon=True
        )
        self.worker.start()

    def _worker_scan(self, folder: str) -> None:
        """Berjalan di thread pekerja."""
        try:
            self.queue.put(("status", "Menyiapkan mesin pemindai..."))
            report = self.engine.prepare()
            self.queue.put(("engines", report))

            summary = self.engine.scan_directory(
                folder,
                stop_event=self.stop_event,
                # Deteksi anomali berbasis AI lokal mengikuti pengaturan
                # pengguna. Bawaannya menyala karena tidak butuh internet,
                # tidak butuh kunci API, dan tidak menimbulkan biaya.
                use_anomaly=bool(self.settings.ai_anomaly),
                on_progress=lambda i, n, path, sha, note: self.queue.put(
                    ("progress", (i, n, path, sha, note))
                ),
                on_finding=lambda finding: self.queue.put(("finding", finding)),
                on_status=lambda message, total: self.queue.put(
                    ("status", message)
                ),
            )
            self.queue.put(("done", summary))
        except Exception as error:  # noqa: BLE001 - kesalahan apa pun harus terlihat
            import traceback

            self.queue.put(("error", f"{error}\n\n{traceback.format_exc()}"))

    def stop_scan(self) -> None:
        if not self.scanning:
            return
        self.stop_event.set()
        self.status_var.set("Menghentikan pemindaian...")
        self.log_line("Permintaan berhenti dikirim; menunggu berkas yang sedang diperiksa.")
        self.stop_btn.configure(state="disabled")

    def _pump_queue(self) -> None:
        """Kosongkan antrean kejadian. Dijalankan di main thread."""
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                try:
                    self._handle_event(kind, payload)
                except Exception:  # noqa: BLE001
                    # Satu kejadian yang gagal tidak boleh mematikan seluruh
                    # antarmuka. Kesalahannya dicatat, lalu antrean lanjut.
                    import traceback

                    self._append_log(
                        "Terjadi kesalahan saat menampilkan hasil:\n"
                        + traceback.format_exc()
                        + "\n",
                        SEVERITY_TAGS[SEV_MALWARE],
                    )
        except queue.Empty:
            pass
        finally:
            # Penjadwalan ulang diletakkan di `finally` supaya pengosongan
            # antrean tetap berjalan walau ada kejadian yang gagal diproses.
            # 80 ms berarti 12 kali per detik: cukup responsif tanpa membuat
            # prosesor sibuk.
            self._pump_job = self.root.after(80, self._pump_queue)

    def _handle_event(self, kind: str, payload) -> None:
        if kind == "status":
            self.status_var.set(payload)

        elif kind == "engines":
            self.engine_status = payload.get("engines", [])
            for item in self.engine_status:
                mark = "siap" if item["ok"] else "tidak tersedia"
                tag = TAG_INFO if item["ok"] else SEVERITY_TAGS[SEV_NOTE]
                self._append_log(f"  [{mark}] {item['name']}: {item['message']}\n", tag)
            self._append_log("\n")

        elif kind == "progress":
            index, total, path, sha256, note = payload
            if total:
                self.progress.configure(value=index * 100 / total)
            name = os.path.basename(path) or path
            if note:
                self._append_log(f"  dilewati  {name} - {note}\n", SEVERITY_TAGS[SEV_NOTE])
            self.counter_var.set(
                f"{index}/{total} berkas diperiksa"
                + (f"  |  SHA-256: {sha256[:16]}..." if sha256 else "")
            )

        elif kind == "finding":
            finding: Finding = payload
            self._append_log(
                f"\n[{finding.severity}] {finding.path}\n", finding.severity
            )
            self._append_log(f"    ({finding.engine}) {finding.rule}\n")
            self._append_log(f"    {finding.detail}\n")

        elif kind == "log":
            # Dipakai thread pekerja untuk menitipkan satu baris log. Tanpa
            # cabang ini pesannya dibuang tanpa pesan kesalahan apa pun, dan
            # pengguna tidak melihat konfirmasi setelah mengarantina berkas.
            text, tag = payload
            self._append_log(text, tag)

        elif kind == "rtp":
            self._render_rtp(payload)

        elif kind == "rtp_error":
            self._append_log(
                f"\n[PANTAU] Kesalahan pemantauan: {payload}\n",
                SEVERITY_TAGS[SEV_NOTE],
            )

        elif kind == "done":
            self._render_done(payload)

        elif kind == "error":
            self._render_error(payload)

    def _render_done(self, summary) -> None:
        self.last_summary = summary
        self.scanning = False
        self.scan_btn.configure(state="normal")
        self.choose_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.progress.configure(value=100)

        self._append_log("\n" + "-" * 66 + "\n")
        if summary.stopped:
            self._append_log("Pemindaian DIHENTIKAN sebelum selesai.\n", SEVERITY_TAGS[SEV_NOTE])
        self._append_log(
            f"Berkas diperiksa: {summary.scanned_files} dari {summary.total_files}"
            + (f" ({summary.cached_files} dari hasil sebelumnya)" if summary.cached_files else "")
            + "\n"
        )
        if summary.skipped_files:
            self._append_log(f"Berkas dilewati: {summary.skipped_files}\n", SEVERITY_TAGS[SEV_NOTE])
        if summary.error_files:
            self._append_log(f"Berkas gagal dibaca: {summary.error_files}\n", SEVERITY_TAGS[SEV_NOTE])

        if summary.findings:
            self._append_log(f"Temuan: {len(summary.findings)}\n")
            # Angka ringkasan diberi warna per tingkat. Baris ini selalu
            # berada di dasar log yang terlihat, jadi warna tingkat bahaya
            # tetap terbaca tanpa perlu menggulir ke atas.
            self._append_log("  ")
            for label, jumlah, severity in (
                ("MALWARE", summary.infected, SEV_MALWARE),
                ("MENCURIGAKAN", summary.suspicious, SEV_SUSPICIOUS),
                ("PERLU DIPERIKSA", summary.notes, SEV_NOTE),
            ):
                self._append_log(
                    f"{label}: {jumlah}",
                    SEVERITY_TAGS[severity],
                )
                if severity != SEV_NOTE:
                    self._append_log("   ")
            self._append_log("\n")
        else:
            self._append_log(
                "Tidak ada temuan. Catatan: ini bukan jaminan berkas pasti aman.\n",
                TAG_OK,
            )

        self._append_log(
            f"Selesai dalam {human_time(summary.elapsed)}. "
            f"Mesin: {', '.join(summary.engines_used)}\n"
        )
        self.status_var.set(
            "Selesai. "
            + (
                f"{summary.infected} malware, {summary.suspicious} mencurigakan."
                if summary.findings
                else "Tidak ada temuan."
            )
        )
        self.counter_var.set("")

        # Perbarui kartu status supaya hasil pemindaian langsung terbaca tanpa
        # harus menggulir log.
        if summary.stopped:
            self._set_status_card(
                "Pemindaian dihentikan",
                "Sebagian berkas belum diperiksa. Jalankan ulang untuk memeriksa semuanya.",
                "note",
            )
        elif summary.infected:
            self._set_status_card(
                f"Ditemukan {summary.infected} berkas berbahaya",
                f"{summary.suspicious} mencurigakan, {summary.notes} perlu diperiksa. "
                "Pindahkan yang berbahaya ke karantina.",
                "danger",
            )
        elif summary.suspicious or summary.notes:
            self._set_status_card(
                f"Ditemukan {summary.suspicious + summary.notes} berkas patut diperiksa",
                "Tidak ada yang pasti berbahaya, tetapi ada yang menyimpang dari biasanya.",
                "warn",
            )
        else:
            self._set_status_card(
                "Tidak ada temuan",
                "Tidak ada yang cocok dengan basis data atau aturan. "
                "Ini bukan jaminan semua berkas aman.",
                "ok",
            )

        # Hasil ditampilkan di halaman utama, jadi sorotan panel kiri
        # dikembalikan ke Beranda. Tanpa ini, menu "Pindai Cepat" tetap
        # tersorot padahal yang terlihat di layar adalah halaman Beranda.
        self._mark_active("beranda")
        # Pemantauan dilanjutkan setelah pemindaian manual selesai.
        if self.rtp is not None and self.rtp.running:
            self.rtp.resume()
            self._update_rtp_status()

        self._offer_quarantine(summary)

    def _set_status_card(self, judul: str, keterangan: str, nada: str) -> None:
        """Ubah teks dan warna kartu status.

        `nada` memilih warna dari palet tingkat bahaya supaya kartu ini memakai
        warna yang sama dengan baris log untuk tingkat yang sama - pengguna tidak
        perlu mempelajari dua arti warna yang berbeda.
        """
        self.headline_var.set(judul)
        self.subheadline_var.set(keterangan)
        # Warna perisai: isian memakai warna merek (hanya isian, bukan teks),
        # garisnya memakai warna nada supaya tingkatnya tetap terbaca.
        warna_garis = {
            "danger": self.colors["danger"],
            "warn": self.colors["warn"],
            "ok": self.colors["ok"],
            "note": self.colors["note"],
        }.get(nada, self.colors["accent"])
        self.shield_canvas.delete("all")
        self._draw_shield(self.shield_canvas, outline=warna_garis)

    # ------------------------------------------------- perlindungan nyata -- #

    def toggle_rtp(self) -> None:
        """Nyalakan atau matikan perlindungan waktu nyata."""
        self._mark_active("rtp")
        if self.rtp is not None and self.rtp.running:
            self.stop_rtp()
            return
        self.start_rtp()

    def start_rtp(self) -> bool:
        """Mulai memantau folder. Kembalikan False bila tidak ada folder pantauan."""
        if self.rtp is not None and self.rtp.running:
            return True
        folders = [f for f in self.settings.rtp_folders if os.path.isdir(f)]
        if not folders:
            self._append_log(
                "\nPerlindungan waktu nyata belum punya folder pantauan. "
                "Tambahkan lewat menu Perlindungan Nyata.\n",
                SEVERITY_TAGS[SEV_NOTE],
            )
            self.choose_rtp_folder()
            folders = [f for f in self.settings.rtp_folders if os.path.isdir(f)]
            if not folders:
                return False

        self.rtp = RealtimeMonitor(
            engine=self.engine,
            on_event=self._rtp_event,
            folders=folders,
            interval=self.settings.rtp_interval,
            on_error=self._rtp_error,
        )
        self.rtp.start()
        self._update_rtp_status()
        self._append_log(
            "\nPerlindungan waktu nyata AKTIF. Memantau "
            + ", ".join(folders)
            + f". Jeda {self.settings.rtp_interval:g} detik.\n",
            TAG_OK,
        )
        self._append_log(
            "Catatan: ini memeriksa berkas yang sudah ada di disk, bukan "
            "memblokir pemasangannya.\n",
            TAG_INFO,
        )
        return True

    def stop_rtp(self) -> None:
        if self.rtp is None:
            return
        self.rtp.stop()
        self._update_rtp_status()
        self._append_log(
            f"\nPerlindungan waktu nyata DIMATIKAN. "
            f"{self.rtp.checked} berkas diperiksa, {self.rtp.found} mencurigakan.\n",
            TAG_INFO,
        )

    def choose_rtp_folder(self) -> None:
        """Minta pengguna memilih folder yang dipantau."""
        folder = filedialog.askdirectory(
            title="Pilih folder yang dipantau terus-menerus"
        )
        if not folder:
            return
        folder = os.path.abspath(folder)
        if folder in self.settings.rtp_folders:
            self._append_log(f"Folder itu sudah dipantau: {folder}\n", TAG_INFO)
            return
        if len(self.settings.rtp_folders) >= MAX_WATCHED_FOLDERS:
            messagebox.showinfo(
                "Batas folder",
                f"Paling banyak {MAX_WATCHED_FOLDERS} folder dipantau sekaligus. "
                "Setiap folder menambah satu penelusuran penuh setiap putaran, "
                "jadi menambah banyak folder membuat pemantauan berat.",
                parent=self.root,
            )
            return
        self.settings.rtp_folders.append(folder)
        self.settings.save()
        if self.rtp is not None:
            self.rtp.add_folder(folder)
        self._update_rtp_status()
        self._append_log(f"Folder ditambahkan ke pantauan: {folder}\n", TAG_OK)

    def _rtp_event(self, event: RtEvent) -> None:
        """Dipanggil dari thread pemantau. Hanya boleh menaruh ke antrean.

        Menyentuh widget dari thread lain membuat jendela membeku atau program
        mati, jadi kejadiannya diteruskan ke main thread lewat antrean yang
        sudah ada.
        """
        self.queue.put(("rtp", event))

    def _rtp_error(self, error: Exception) -> None:
        self.queue.put(("rtp_error", str(error)))

    def _render_rtp(self, event: RtEvent) -> None:
        """Tampilkan satu kejadian pemantauan. Dijalankan di main thread."""
        nama = os.path.basename(event.path) or event.path
        if event.error:
            self._append_log(
                f"\n[PANTAU] {event.path}\n    {event.error}\n",
                SEVERITY_TAGS[SEV_NOTE],
            )
            return
        if event.clean:
            # Berkas bersih hanya ditampilkan bila pengguna memang minta;
            # folder yang ramai akan memenuhi log tanpa ada yang perlu dibaca.
            if self.settings.rtp_report_clean:
                self._append_log(f"[PANTAU] {nama}: bersih\n", TAG_INFO)
            self._update_rtp_status()
            return
        self._append_log(
            f"\n[PANTAU {event.severity}] {event.path}\n", event.severity
        )
        self._append_log(f"    ({event.action}) {nama}\n", TAG_INFO)
        for finding in event.findings:
            self._append_log(f"    ({finding.engine}) {finding.rule}\n")
            self._append_log(f"    {finding.detail}\n")
        # Berkas berbahaya yang baru muncul langsung ditawarkan untuk
        # dikarantina, atau dipindahkan sendiri bila pengguna memintanya.
        if event.severity == SEV_MALWARE:
            self._handle_rtp_malware(event)
        self._update_rtp_status()

    def _handle_rtp_malware(self, event: RtEvent) -> None:
        temuan = event.findings[0] if event.findings else None
        if self.settings.rtp_auto_quarantine:
            ok, pesan = self.quarantine.quarantine_file(
                event.path,
                engine=temuan.engine if temuan else "RTP",
                rule=temuan.rule if temuan else "Pemantauan waktu nyata",
                detail=temuan.detail if temuan else "",
                severity=event.severity or SEV_NOTE,
            )
            if ok:
                self._append_log(f"    Dipindahkan ke karantina. {pesan}\n", TAG_OK)
            else:
                self._append_log(
                    f"    Gagal memindahkan ke karantina: {pesan}\n",
                    SEVERITY_TAGS[SEV_NOTE],
                )
            return
        jawab = messagebox.askyesno(
            f"{APP_NAME} - berkas berbahaya",
            f"Berkas ini baru muncul dan terdeteksi berbahaya:\n\n"
            f"{event.path}\n\n"
            f"Pindahkan ke karantina sekarang?",
            parent=self.root,
        )
        if jawab:
            self._quarantine_paths([event.path], None)

    def _update_rtp_status(self) -> None:
        """Perbarui label status RTP di kartu utama."""
        if self.rtp is not None and self.rtp.running:
            tambahan = " (dijeda)" if self.rtp.paused else ""
            self.rtp_var.set(
                f"Perlindungan waktu nyata: AKTIF{tambahan} - "
                f"{self.rtp.checked} berkas diperiksa, {self.rtp.found} mencurigakan"
            )
        else:
            jumlah = len(self.settings.rtp_folders)
            self.rtp_var.set(
                "Perlindungan waktu nyata: mati"
                + (f" - {jumlah} folder siap dipantau" if jumlah else "")
            )

    def _render_error(self, message: str) -> None:
        self.scanning = False
        self.scan_btn.configure(state="normal")
        self.choose_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._append_log(f"\nTerjadi kesalahan saat memindai:\n{message}\n", SEVERITY_TAGS[SEV_MALWARE])
        self.status_var.set("Pemindaian gagal. Lihat log untuk keterangannya.")
        messagebox.showerror(
            "Pemindaian gagal",
            "Terjadi kesalahan saat memindai. Keterangan lengkap ada di area log.",
        )

    # ---------------------------------------------------------- karantina -- #

    def _offer_quarantine(self, summary) -> None:
        """Tawarkan memindahkan temuan malware ke karantina."""
        malware = [f for f in summary.findings if f.severity == SEV_MALWARE]
        if not malware:
            return
        paths = []
        for finding in malware:
            if finding.path not in paths:
                paths.append(finding.path)

        auto = self.settings.auto_quarantine
        if auto:
            answer = True
        else:
            preview = "\n".join(f"  - {p}" for p in paths[:8])
            if len(paths) > 8:
                preview += f"\n  ... dan {len(paths) - 8} berkas lain"
            answer = messagebox.askyesno(
                "Pindahkan ke karantina?",
                f"{len(paths)} berkas dinyatakan berbahaya:\n\n{preview}\n\n"
                "Berkas akan dipindahkan ke karantina (isinya diacak sehingga "
                "tidak bisa dijalankan, tetapi masih bisa dipulihkan nanti).\n\n"
                "Pindahkan sekarang?",
            )
        if answer:
            self._quarantine_paths(paths, summary)

    def _quarantine_paths(self, paths: list[str], summary) -> None:
        """Karantina berkas di thread terpisah agar jendela tidak membeku."""
        self.status_var.set("Memindahkan berkas ke karantina...")
        self.log_line("\nMemindahkan ke karantina...")

        # Ambil temuan terberat untuk setiap berkas, untuk dicatat.
        by_path: dict[str, Finding] = {}
        for finding in summary.findings:
            if finding.path in paths:
                current = by_path.get(finding.path)
                if current is None or finding.severity == SEV_MALWARE:
                    by_path[finding.path] = finding

        def worker() -> None:
            moved = failed = 0
            for path in paths:
                finding = by_path.get(path)
                ok, message = self.quarantine.quarantine_file(
                    path,
                    engine=finding.engine if finding else "-",
                    rule=finding.rule if finding else "-",
                    detail=finding.detail if finding else "",
                    severity=finding.severity if finding else SEV_NOTE,
                )
                if ok:
                    moved += 1
                    self.queue.put(("log", (f"  dikarantina: {path}\n", TAG_OK)))
                else:
                    failed += 1
                    self.queue.put(
                        ("log", (f"  gagal: {path} - {message}\n", SEVERITY_TAGS[SEV_NOTE]))
                    )
            self.queue.put(
                (
                    "log",
                    (
                        f"Selesai. {moved} berkas dikarantina, {failed} gagal.\n"
                        f"Buka jendela Karantina untuk memeriksa atau memulihkan.\n",
                        TAG_INFO,
                    ),
                )
            )
            self.queue.put(("status", f"Karantina selesai: {moved} berkas dipindahkan."))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------- laporan -- #

    def save_report(self) -> None:
        if not self.last_summary:
            messagebox.showinfo(
                "Belum ada hasil",
                "Jalankan pemindaian lebih dulu, baru laporan bisa disimpan.",
            )
            return
        default = f"laporan_scanguard_{self.last_summary.finished_at:%Y%m%d_%H%M%S}.txt"
        path = filedialog.asksaveasfilename(
            title="Simpan laporan",
            defaultextension=".txt",
            initialfile=default,
            filetypes=[("Berkas teks", "*.txt"), ("Semua berkas", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(build_report(self.last_summary, self.engine_status))
        except OSError as error:
            messagebox.showerror("Gagal menyimpan", f"Laporan tidak bisa disimpan: {error}")
            return
        self.log_line(f"Laporan disimpan: {path}", TAG_OK)
        messagebox.showinfo("Laporan disimpan", f"Laporan tersimpan di:\n\n{path}")

    # ------------------------------------------------------------ jendela -- #

    def open_settings(self) -> None:
        SettingsWindow(self.root, self)

    def open_update(self) -> None:
        UpdateWindow(self.root, self)

    def open_quarantine(self) -> None:
        QuarantineWindow(self.root, self)

    def apply_settings(self) -> None:
        """Bangun ulang mesin setelah pengaturan berubah."""
        self.engine = self._make_engine()
        self.refresh_database_label()
        # Pengaturan AI bisa berubah, jadi klien lama tidak boleh dipakai lagi.
        self.assistant = Assistant()
        # Pemantauan memakai objek mesin yang lama. Kalau pengaturan mesin
        # berubah, pemantauan harus dihentikan dan dijalankan ulang dengan mesin
        # yang baru; kalau tidak, ia memeriksa dengan pengaturan yang usang.
        if self.rtp is not None and self.rtp.running:
            self.rtp.stop()
            self.rtp = None
            self.start_rtp()
        else:
            self._update_rtp_status()

    # ------------------------------------------------------- kecerdasan AI -- #

    def ai_client(self):
        """Klien AI sesuai pengaturan saat ini, atau None bila belum siap."""
        if not self.settings.ai_explain:
            return None
        client = build_client_from_settings(self.settings)
        return client if client.ready else None

    def make_assistant(self) -> Assistant:
        """Asisten siap pakai: memakai model bila ada, pengetahuan bawaan bila tidak.

        Asisten selalu bisa dibuka, walaupun kunci API belum diisi. Jendela yang
        menolak terbuka hanya membuat pengguna mengira fiturnya rusak.
        """
        client = self.ai_client()
        if client is None:
            return Assistant(analyst=None)
        analyst = AiAnalyst(client, cache=self.ai_cache)
        return Assistant(analyst=analyst)

    def open_assistant(self) -> None:
        AssistantWindow(self.root, self)

    def explain_file_with_ai(self, path: str) -> None:
        """Minta AI menjelaskan satu berkas yang ada di log.

        Dijalankan di thread terpisah karena panggilan ke model bisa memakan
        waktu beberapa detik. Menjalankannya di main thread akan membekukan
        jendela - persis masalah yang dihindari di seluruh program ini.
        """
        client = self.ai_client()
        if client is None:
            messagebox.showinfo(
                "Fitur AI belum aktif",
                "Penjelasan dengan AI memerlukan model bahasa.\n\n"
                "Buka Pengaturan lalu isi bagian Kecerdasan Buatan. Kalau tidak "
                "ingin memakai layanan berbayar, pasang Ollama (ollama.com) agar "
                "model berjalan di komputer Anda sendiri.",
            )
            return
        if not os.path.exists(path):
            messagebox.showwarning(
                "Berkas tidak ditemukan",
                "Berkas itu sudah tidak ada di lokasi asalnya. Kemungkinan sudah "
                "dipindahkan ke karantina.",
            )
            return

        AssistantWindow(self.root, self, explain_path=path)

    def refresh_database_label(self) -> None:
        stats = self.db.stats()
        text = f"Basis data hash: {stats['total']} entri"
        if stats.get("last_update_text"):
            text += f"\nPembaruan terakhir: {stats['last_update_text']}"
        else:
            text += "\nBelum pernah diperbarui"
        self.db_label.configure(text=text)

    def on_close(self) -> None:
        # Penutupan harus aman dipanggil lebih dari sekali: pengguna bisa
        # menutup jendela saat pemindaian berjalan, dan pengelola jendela bisa
        # mengirim permintaan tutup lagi.
        if self._closed:
            return
        self._closed = True

        # Hentikan pengosongan antrean sebelum jendela dihancurkan.
        if self._pump_job is not None:
            try:
                self.root.after_cancel(self._pump_job)
            except (tk.TclError, ValueError):
                pass
            self._pump_job = None

        if self.scanning:
            if not messagebox.askyesno(
                "Pemindaian sedang berjalan",
                "Pemindaian belum selesai. Tutup program sekarang?",
            ):
                return
            self.stop_event.set()
        if self.rtp is not None:
            # Thread pemantau harus benar-benar berhenti sebelum basis data
            # ditutup, kalau tidak ia bisa menulis ke basis data yang sudah
            # ditutup dan mencetak kesalahan saat program keluar.
            self.rtp.stop()
        try:
            self.db.close()
        except Exception:  # noqa: BLE001 - penutupan tidak boleh menghalangi keluar
            pass
        try:
            self.ai_cache.close()
        except Exception:  # noqa: BLE001 - penutupan tidak boleh menghalangi keluar
            pass
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    # Jendela utama disembunyikan sampai siap. Menampilkannya lebih dulu lalu
    # mengisinya membuat pengguna melihat jendela kosong yang berkedip.
    root.withdraw()

    splash = SplashScreen(root, COLORS)
    root.update()  # gambar layar pembuka sebelum pekerjaan berat dimulai
    splash.set_status("Menyiapkan basis data hash...")
    root.update()

    app = ScanGuardApp(root)

    splash.set_status("Mesin siap dipakai.")
    root.update()
    # Layar pembuka ditahan sampai waktu tampil paling singkat terpenuhi;
    # kalau tidak, ia hanya berkedip satu bingkai di komputer cepat.
    while splash.remaining_ms() > 0:
        root.update()
        time.sleep(0.02)
    splash.close()

    root.deiconify()
    root.mainloop()
