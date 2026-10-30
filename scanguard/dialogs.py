"""Jendela tambahan: pengaturan, pembaruan basis data, dan manajer karantina."""

from __future__ import annotations

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .ai.analyst import AiAnalyst, check_connection
from .ai.assistant import answer_from_knowledge, suggested_questions
from .ai.base import PROVIDERS, FileReport, build_client_from_settings
from . import autostart
from .background import log_path
from .config import APP_NAME, MAX_WATCHED_FOLDERS, APP_VERSION, data_dir
from .core import format_size, hash_file
from .hashes import HashUpdater


class _BaseWindow(tk.Toplevel):
    """Jendela tambahan dengan gaya yang sama seperti jendela utama."""

    def __init__(self, parent, app, title: str, geometry: str) -> None:
        super().__init__(parent)
        self.app = app
        self.colors = app.colors
        self.title(title)
        self.geometry(geometry)
        self.minsize(520, 360)
        self.configure(bg=self.colors["bg"])
        self.transient(parent)
        self.resizable(True, True)

    def _label(self, parent, text: str, **kwargs) -> tk.Label:
        options = {
            "bg": self.colors["panel"],
            "fg": self.colors["text"],
            "font": ("Segoe UI", 10),
        }
        options.update(kwargs)
        return tk.Label(parent, text=text, **options)

    def _panel(self, parent, **kwargs) -> tk.Frame:
        options = {"bg": self.colors["panel"], "padx": 14, "pady": 12}
        options.update(kwargs)
        return tk.Frame(parent, **options)

    def _button(self, parent, text: str, command, primary: bool = False) -> tk.Button:
        """Tombol dengan warna yang sudah lolos uji kontras WCAG AA."""
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


class _ScrollArea(tk.Frame):
    """Wadah yang isinya bisa digulir bila lebih tinggi daripada jendela.

    Diperlukan karena jendela pengaturan sudah lebih tinggi daripada layar
    laptop kecil. Tanpa gulir, pilihan di bagian bawah tidak bisa dijangkau sama
    sekali - bukan sekadar tidak rapi, tetapi tidak bisa dipakai.
    """

    def __init__(self, parent, colors) -> None:
        super().__init__(parent, bg=colors["bg"])
        self.colors = colors
        self.canvas = tk.Canvas(
            self, bg=colors["bg"], highlightthickness=0, bd=0
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.body = tk.Frame(self.canvas, bg=colors["bg"])
        self._window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")

        self.body.bind("<Configure>", self._on_body_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        # Roda tetikus: Windows memakai <MouseWheel>, Linux memakai Button-4/5.
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)
        self.canvas.bind_all("<Button-4>", self._on_wheel)
        self.canvas.bind_all("<Button-5>", self._on_wheel)

    def _on_body_configure(self, _event=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event) -> None:
        # Lebarkan isi agar mengikuti lebar jendela, bukan tetap selebar aslinya.
        self.canvas.itemconfigure(self._window, width=event.width)

    def _on_wheel(self, event) -> None:
        if event.num == 4:
            delta = -1
        elif event.num == 5:
            delta = 1
        else:
            delta = -1 if event.delta > 0 else 1
        self.canvas.yview_scroll(delta, "units")


class SettingsWindow(_BaseWindow):
    """Pengaturan: kunci API, ClamAV, mesin, pengecualian, dan kecerdasan buatan."""

    def __init__(self, parent, app) -> None:
        super().__init__(parent, app, f"Pengaturan {APP_NAME}", "660x720")
        self.minsize(560, 420)
        self.settings = app.settings
        self._build()

    def _build(self) -> None:
        area = _ScrollArea(self, self.colors)
        area.pack(fill="both", expand=True)
        # Disimpan agar bisa digulir dari luar - dipakai skrip tangkapan layar
        # untuk memperlihatkan bagian kecerdasan buatan.
        self.scroll_area = area
        outer = tk.Frame(area.body, bg=self.colors["bg"])
        outer.pack(fill="both", expand=True, padx=14, pady=12)

        # --- Pembaruan basis data hash ------------------------------------- #
        panel = self._panel(outer)
        panel.pack(fill="x")
        self._label(
            panel,
            "Kunci API MalwareBazaar",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w")
        self._label(
            panel,
            "Sejak 30 Juni 2025, abuse.ch mewajibkan Auth-Key untuk semua "
            "permintaan API.\nKuncinya gratis: buat di https://auth.abuse.ch/ "
            "lalu tempelkan di sini.\nTanpa kunci, basis data tetap bisa "
            "diperbarui lewat impor berkas CSV/TXT.",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", pady=(4, 8))

        self.key_var = tk.StringVar(value=self.settings.malwarebazaar_key)
        entry = tk.Entry(
            panel,
            textvariable=self.key_var,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Consolas", 10),
        )
        entry.pack(fill="x", ipady=6)

        # --- ClamAV --------------------------------------------------------- #
        panel2 = self._panel(outer)
        panel2.pack(fill="x", pady=(10, 0))
        self._label(
            panel2,
            "Lokasi clamscan (opsional)",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w")
        self._label(
            panel2,
            "Biarkan kosong bila clamscan sudah ada di PATH. ClamAV adalah mesin "
            "signature sungguhan\n(opsional); tanpa ClamAV, mesin hash, YARA, "
            "dan analisis PE tetap bekerja.",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", pady=(4, 8))

        row = tk.Frame(panel2, bg=self.colors["panel"])
        row.pack(fill="x")
        self.clam_var = tk.StringVar(value=self.settings.clamav_path)
        tk.Entry(
            row,
            textvariable=self.clam_var,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Consolas", 10),
        ).pack(side="left", fill="x", expand=True, ipady=6)
        self._button(row, "Cari...", self._pick_clamav).pack(side="left", padx=(8, 0))

        # --- Pilihan mesin -------------------------------------------------- #
        panel3 = self._panel(outer)
        panel3.pack(fill="x", pady=(10, 0))
        self._label(
            panel3,
            "Mesin yang dipakai",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w", pady=(0, 6))

        self.use_yara = tk.BooleanVar(value=self.settings.use_yara)
        self.use_pe = tk.BooleanVar(value=self.settings.use_pe)
        self.use_clamav = tk.BooleanVar(value=self.settings.use_clamav)
        self.use_decode = tk.BooleanVar(value=self.settings.use_decode)
        self.auto_quarantine = tk.BooleanVar(value=self.settings.auto_quarantine)
        self.log_clean = tk.BooleanVar(value=self.settings.log_clean_files)

        for text, var in (
            ("Aturan YARA (pencocokan pola perilaku)", self.use_yara),
            ("Analisis PE (struktur program Windows)", self.use_pe),
            ("ClamAV (basis data signature, bila tersedia)", self.use_clamav),
            (
                "Dekode muatan (bongkar base64, hex, gzip, kode karakter)",
                self.use_decode,
            ),
            ("Pindahkan temuan MALWARE ke karantina otomatis", self.auto_quarantine),
            ("Tampilkan berkas bersih satu per satu di log", self.log_clean),
        ):
            tk.Checkbutton(
                panel3,
                text=text,
                variable=var,
                bg=self.colors["panel"],
                fg=self.colors["text"],
                selectcolor=self.colors["bg"],
                activebackground=self.colors["panel"],
                activeforeground=self.colors["text"],
                font=("Segoe UI", 9),
                anchor="w",
            ).pack(anchor="w")

        # --- Perlindungan waktu nyata (RTP) --------------------------------- #
        panel_rtp = self._panel(outer)
        panel_rtp.pack(fill="x", pady=(10, 0))
        self._label(
            panel_rtp,
            "Perlindungan waktu nyata",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w")
        self._label(
            panel_rtp,
            "Memantau folder dan memeriksa berkas yang baru muncul. Berkas yang "
            "sudah ada sebelum pemantauan dinyalakan tidak diperiksa lagi.\n"
            "Ini memeriksa berkas yang sudah ada di disk, bukan memblokir "
            "pemasangannya seperti antivirus komersial.",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
            wraplength=560,
        ).pack(anchor="w", pady=(0, 6))

        self.rtp_report_clean = tk.BooleanVar(value=self.settings.rtp_report_clean)
        self.rtp_auto_quarantine = tk.BooleanVar(
            value=self.settings.rtp_auto_quarantine
        )
        for text, var in (
            ("Tampilkan berkas bersih di log pemantauan", self.rtp_report_clean),
            (
                "Pindahkan temuan MALWARE dari pemantauan ke karantina sendiri",
                self.rtp_auto_quarantine,
            ),
        ):
            tk.Checkbutton(
                panel_rtp,
                text=text,
                variable=var,
                bg=self.colors["panel"],
                fg=self.colors["text"],
                selectcolor=self.colors["bg"],
                activebackground=self.colors["panel"],
                activeforeground=self.colors["text"],
                font=("Segoe UI", 9),
                anchor="w",
            ).pack(anchor="w")

        baris_jeda = tk.Frame(panel_rtp, bg=self.colors["panel"])
        baris_jeda.pack(fill="x", pady=(6, 0))
        self._label(
            baris_jeda,
            "Jeda antar pemeriksaan (detik)",
            bg=self.colors["panel"],
            font=("Segoe UI", 9),
        ).pack(side="left")
        self.rtp_interval_var = tk.StringVar(value=f"{self.settings.rtp_interval:g}")
        tk.Spinbox(
            baris_jeda,
            from_=1,
            to=60,
            increment=1,
            width=5,
            textvariable=self.rtp_interval_var,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            buttonbackground=self.colors["secondary"],
            font=("Segoe UI", 9),
        ).pack(side="left", padx=(8, 0))

        self.rtp_folders_text = tk.Text(
            panel_rtp,
            height=4,
            wrap="none",
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            font=("Consolas", 9),
        )
        self.rtp_folders_text.pack(fill="x", pady=(6, 0))
        if self.settings.rtp_folders:
            self.rtp_folders_text.insert("1.0", "\n".join(self.settings.rtp_folders))
        self._label(
            panel_rtp,
            "Satu folder per baris. Paling banyak "
            f"{MAX_WATCHED_FOLDERS} folder; setiap folder menambah satu "
            "penelusuran penuh tiap putaran.",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 8),
            justify="left",
            wraplength=560,
        ).pack(anchor="w", pady=(2, 0))

        # Mulai otomatis saat Windows menyala. Hanya ditampilkan bila sistemnya
        # memang punya registry Windows - di Linux/macOS pilihan ini tidak akan
        # berpengaruh apa pun, jadi menampilkannya hanya membingungkan.
        if autostart.is_supported():
            self.rtp_autostart = tk.BooleanVar(value=autostart.is_enabled())
            tk.Checkbutton(
                panel_rtp,
                text="Jalankan pemantauan otomatis saat Windows menyala",
                variable=self.rtp_autostart,
                bg=self.colors["panel"],
                fg=self.colors["text"],
                selectcolor=self.colors["bg"],
                activebackground=self.colors["panel"],
                activeforeground=self.colors["text"],
                font=("Segoe UI", 9),
                anchor="w",
            ).pack(anchor="w", pady=(6, 0))
            self._label(
                panel_rtp,
                "Dijalankan tanpa jendela: hanya pemantauannya yang bekerja di "
                "latar belakang. Temuannya dicatat ke "
                f"{os.path.basename(log_path())} di folder data, karena tidak ada "
                "jendela untuk menampilkannya.",
                bg=self.colors["panel"],
                fg=self.colors["muted"],
                font=("Segoe UI", 8),
                justify="left",
                wraplength=560,
            ).pack(anchor="w")
        else:
            self.rtp_autostart = None

        # --- Pengecualian --------------------------------------------------- #
        panel4 = self._panel(outer)
        panel4.pack(fill="both", expand=True, pady=(10, 0))
        self._label(
            panel4,
            "Pengecualian",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w")
        self._label(
            panel4,
            "Satu potongan path per baris. Berkas yang path-nya mengandung "
            "teks ini tidak akan dipindai.\nContoh: C:\\Windows atau folder "
            "proyek yang isinya memang berisi alat uji.",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", pady=(4, 8))
        self.excl_text = tk.Text(
            panel4,
            height=6,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Consolas", 9),
        )
        self.excl_text.pack(fill="both", expand=True)
        self.excl_text.insert("1.0", "\n".join(self.settings.exclusions))

        # --- Kecerdasan buatan ---------------------------------------------- #
        panel5 = self._panel(outer)
        panel5.pack(fill="x", pady=(10, 0))
        self._label(
            panel5,
            "Kecerdasan Buatan",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w")
        self._label(
            panel5,
            "Deteksi anomali memakai model yang dilatih di komputer Anda sendiri. "
            "Tidak butuh internet, tidak butuh kunci API, dan tidak menimbulkan "
            "biaya. Penjelasan temuan dengan model bahasa\nmemerlukan kunci API, "
            "dan pemakaiannya ditagih ke akun Anda.",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", pady=(4, 8))

        self.ai_anomaly = tk.BooleanVar(value=self.settings.ai_anomaly)
        self.ai_explain = tk.BooleanVar(value=self.settings.ai_explain)
        self.ai_snippet = tk.BooleanVar(value=self.settings.ai_send_snippet)

        for text, var in (
            ("Deteksi anomali dengan AI lokal (gratis, tanpa internet)", self.ai_anomaly),
            ("Aktifkan penjelasan temuan dan tanya-jawab dengan model bahasa", self.ai_explain),
            ("Sertakan cuplikan isi berkas ke model (data keluar dari komputer)", self.ai_snippet),
        ):
            tk.Checkbutton(
                panel5,
                text=text,
                variable=var,
                bg=self.colors["panel"],
                fg=self.colors["text"],
                selectcolor=self.colors["bg"],
                activebackground=self.colors["panel"],
                activeforeground=self.colors["text"],
                font=("Segoe UI", 9),
                anchor="w",
            ).pack(anchor="w")

        row_ai = tk.Frame(panel5, bg=self.colors["panel"])
        row_ai.pack(fill="x", pady=(8, 0))
        self._label(row_ai, "Penyedia", bg=self.colors["panel"], font=("Segoe UI", 9)).pack(side="left")
        self.ai_provider = tk.StringVar(value=self.settings.ai_provider)
        provider_box = ttk.Combobox(
            row_ai,
            textvariable=self.ai_provider,
            values=list(PROVIDERS.keys()),
            state="readonly",
            width=14,
            font=("Segoe UI", 9),
        )
        provider_box.pack(side="left", padx=(8, 12))
        self._label(row_ai, "Model", bg=self.colors["panel"], font=("Segoe UI", 9)).pack(side="left")
        self.ai_model = tk.StringVar(value=self.settings.ai_model)
        tk.Entry(
            row_ai,
            textvariable=self.ai_model,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Consolas", 9),
        ).pack(side="left", fill="x", expand=True, ipady=4)

        self._label(
            panel5,
            "Kunci API (kosongkan bila memakai Ollama; kunci juga bisa diberikan "
            "lewat variabel\nlingkungan SCANGUARD_AI_KEY agar tidak tersimpan di "
            "disk)",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", pady=(8, 4))
        self.ai_key = tk.StringVar(value=self.settings.ai_api_key)
        tk.Entry(
            panel5,
            textvariable=self.ai_key,
            show="\u2022",
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Consolas", 9),
        ).pack(fill="x", ipady=5)

        row_ai2 = tk.Frame(panel5, bg=self.colors["panel"])
        row_ai2.pack(fill="x", pady=(8, 0))
        self._button(row_ai2, "Uji Koneksi", self._test_ai).pack(side="left")
        self._button(row_ai2, "Lihat Pemakaian Kuota", self._show_usage).pack(
            side="left", padx=(8, 0)
        )

        # --- Tombol --------------------------------------------------------- #
        footer = tk.Frame(outer, bg=self.colors["bg"])
        footer.pack(fill="x", pady=(12, 0))
        self._button(footer, "Simpan", self._save, primary=True).pack(side="right")
        self._button(footer, "Batal", self.destroy).pack(side="right", padx=(0, 8))
        self._button(footer, "Buka folder data", self._open_data_dir).pack(side="left")

    def _current_client(self):
        """Klien AI dari isian di jendela ini, bukan dari pengaturan tersimpan.

        Pengguna perlu bisa menguji pengaturannya sebelum menyimpan. Kalau
        pengujian memakai pengaturan lama, hasilnya menyesatkan.
        """
        self.settings.ai_provider = self.ai_provider.get()
        self.settings.ai_model = self.ai_model.get().strip()
        self.settings.ai_api_key = self.ai_key.get().strip()
        return build_client_from_settings(self.settings)

    def _test_ai(self) -> None:
        """Uji koneksi ke penyedia AI, dijalankan di thread terpisah.

        Panggilan jaringan bisa memakan waktu puluhan detik. Menjalankannya di
        main thread akan membekukan jendela pengaturan.
        """
        client = self._current_client()
        if not client.ready:
            messagebox.showwarning(
                "Kunci API belum diisi",
                "Isi kunci API lebih dulu. Kalau tidak ingin memakai layanan "
                "berbayar, pilih penyedia Ollama: modelnya berjalan di komputer "
                "Anda sendiri dan tidak butuh kunci.",
                parent=self,
            )
            return

        result: dict = {}

        def job() -> None:
            ok, message = check_connection(client)
            result["ok"] = ok
            result["message"] = message

        thread = threading.Thread(target=job, daemon=True)
        thread.start()
        # Tampilkan status sementara supaya pengguna tahu prosesnya berjalan.
        messagebox.showinfo(
            "Menguji koneksi",
            f"Sedang menghubungi:\n{client.describe()}\n\n"
            "Jendela ini akan menampilkan hasilnya setelah pengujian selesai.",
            parent=self,
        )
        self.after(200, lambda: self._finish_test(thread, result))

    def _finish_test(self, thread: threading.Thread, result: dict) -> None:
        if thread.is_alive():
            self.after(200, lambda: self._finish_test(thread, result))
            return
        if result.get("ok"):
            messagebox.showinfo("Berhasil", result.get("message", ""), parent=self)
        else:
            messagebox.showerror(
                "Gagal terhubung", result.get("message", "Penyebab tidak diketahui."),
                parent=self,
            )

    def _show_usage(self) -> None:
        """Tampilkan berapa banyak kuota yang sudah terpakai."""
        cache = getattr(self.app, "ai_cache", None)
        if cache is None:
            messagebox.showinfo("Pemakaian kuota", "Belum ada pemakaian.", parent=self)
            return
        usage = cache.usage_summary()
        messagebox.showinfo(
            "Pemakaian kuota AI",
            f"Panggilan ke model: {usage['calls']}\n"
            f"Token masuk: {usage['prompt_tokens']}\n"
            f"Token keluar: {usage['completion_tokens']}\n"
            f"Jumlah token: {usage['total_tokens']}\n\n"
            f"Hasil analisis tersimpan: {cache.size()} berkas.\n"
            "Berkas yang sudah pernah dianalisis tidak memanggil model lagi, "
            "jadi tidak menambah biaya.",
            parent=self,
        )

    def _pick_clamav(self) -> None:
        path = filedialog.askopenfilename(
            title="Pilih clamscan",
            filetypes=[("Program", "*.exe"), ("Semua berkas", "*.*")],
        )
        if path:
            self.clam_var.set(path)

    def _open_data_dir(self) -> None:
        folder = data_dir()
        os.makedirs(folder, exist_ok=True)
        messagebox.showinfo(
            "Folder data",
            f"Basis data, karantina, dan pengaturan disimpan di:\n\n{folder}",
            parent=self,
        )

    def _terapkan_mulai_otomatis(self) -> None:
        """Daftarkan atau hapus pendaftaran mulai otomatis.

        Hasilnya dilaporkan ke log, bukan ke kotak pesan: kegagalan menulis
        registry tidak boleh membatalkan penyimpanan pengaturan yang lain.
        """
        if self.rtp_autostart is None:
            return
        ingin = self.rtp_autostart.get()
        sudah = autostart.is_enabled()
        if ingin == sudah:
            return
        ok, pesan = autostart.enable() if ingin else autostart.disable()
        self.app.log_line(pesan if ok else f"Gagal: {pesan}", "info" if ok else "note")

    def _save(self) -> None:
        self.settings.malwarebazaar_key = self.key_var.get().strip()
        self.settings.clamav_path = self.clam_var.get().strip()
        self.settings.use_yara = self.use_yara.get()
        self.settings.use_pe = self.use_pe.get()
        self.settings.use_clamav = self.use_clamav.get()
        self.settings.use_decode = self.use_decode.get()
        self.settings.auto_quarantine = self.auto_quarantine.get()
        self.settings.log_clean_files = self.log_clean.get()
        self.settings.rtp_report_clean = self.rtp_report_clean.get()
        self.settings.rtp_auto_quarantine = self.rtp_auto_quarantine.get()
        self._terapkan_mulai_otomatis()
        try:
            jeda = float(self.rtp_interval_var.get().replace(",", "."))
        except ValueError:
            # Nilai yang tidak masuk akal diganti bawaan, bukan membuat gagal.
            jeda = 2.0
        self.settings.rtp_interval = max(1.0, min(60.0, jeda))
        self.settings.rtp_folders = [
            baris.strip()
            for baris in self.rtp_folders_text.get("1.0", "end").splitlines()
            if baris.strip()
        ][:MAX_WATCHED_FOLDERS]
        self.settings.ai_anomaly = self.ai_anomaly.get()
        self.settings.ai_explain = self.ai_explain.get()
        self.settings.ai_send_snippet = self.ai_snippet.get()
        self.settings.ai_provider = self.ai_provider.get()
        self.settings.ai_model = self.ai_model.get().strip()
        self.settings.ai_api_key = self.ai_key.get().strip()
        self.settings.exclusions = [
            line.strip()
            for line in self.excl_text.get("1.0", "end").splitlines()
            if line.strip()
        ]
        self.settings.save()
        self.app.apply_settings()
        self.app.log_line("Pengaturan disimpan.", "info")
        self.destroy()


class UpdateWindow(_BaseWindow):
    """Memperbarui basis data hash dari MalwareBazaar, berkas lokal, atau URL."""

    def __init__(self, parent, app) -> None:
        super().__init__(parent, app, "Perbarui Basis Data Hash", "640x480")
        self._build()
        self._refresh_stats()

    def _build(self) -> None:
        outer = tk.Frame(self, bg=self.colors["bg"])
        outer.pack(fill="both", expand=True, padx=14, pady=12)

        panel = self._panel(outer)
        panel.pack(fill="x")
        self._label(
            panel, "Isi basis data", font=("Segoe UI", 10, "bold"), bg=self.colors["panel"]
        ).pack(anchor="w")
        self.stats_label = self._label(
            panel,
            "-",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
        )
        self.stats_label.pack(anchor="w", pady=(4, 0))

        panel2 = self._panel(outer)
        panel2.pack(fill="x", pady=(10, 0))
        self._label(
            panel2,
            "Cara memperbarui",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w", pady=(0, 8))

        row = tk.Frame(panel2, bg=self.colors["panel"])
        row.pack(fill="x")
        self._button(
            row, "Ambil dari MalwareBazaar", self._update_online, primary=True
        ).pack(side="left")
        self._button(row, "Impor berkas CSV/TXT...", self._import_file).pack(
            side="left", padx=(8, 0)
        )
        self._button(row, "Unduh dari URL...", self._import_url).pack(
            side="left", padx=(8, 0)
        )

        self._label(
            panel2,
            "MalwareBazaar memerlukan Auth-Key (isi di Pengaturan). Impor berkas "
            "dan URL tidak\nmemerlukan kunci, jadi keduanya bisa dipakai untuk "
            "daftar hash internal organisasi.",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", pady=(10, 0))

        panel3 = self._panel(outer)
        panel3.pack(fill="both", expand=True, pady=(10, 0))
        self._label(
            panel3, "Catatan proses", font=("Segoe UI", 10, "bold"), bg=self.colors["panel"]
        ).pack(anchor="w")
        self.log = tk.Text(
            panel3,
            height=8,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            relief="flat",
            font=("Consolas", 9),
            state="disabled",
        )
        self.log.pack(fill="both", expand=True, pady=(6, 0))

        footer = tk.Frame(outer, bg=self.colors["bg"])
        footer.pack(fill="x", pady=(12, 0))
        self._button(footer, "Tutup", self.destroy).pack(side="right")
        self._button(footer, "Kosongkan hasil cache", self._clear_cache).pack(side="left")

    def _write(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _refresh_stats(self) -> None:
        stats = self.app.engine.db.stats()
        lines = [f"Total hash: {stats['total']}"]
        for source, count in (stats.get("by_source") or {}).items():
            lines.append(f"  - {source}: {count}")
        lines.append(
            "Pembaruan terakhir: " + (stats.get("last_update_text") or "belum pernah")
        )
        self.stats_label.configure(text="\n".join(lines))

    # --- tindakan --------------------------------------------------------- #

    def _run_async(self, job, label: str) -> None:
        """Jalankan pekerjaan jaringan di thread terpisah.

        Pekerjaan ini bisa memakan waktu puluhan detik. Menjalankannya di main
        thread akan membuat jendela membeku, jadi hasilnya dikembalikan lewat
        self.after().
        """
        self._write(f"[{label}] dimulai...")

        def worker() -> None:
            result = job()
            self.after(0, lambda: self._finish(result, label))

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, result: dict, label: str) -> None:
        mark = "OK" if result.get("ok") else "GAGAL"
        self._write(f"[{label}] {mark}: {result.get('message', '')}")
        self._refresh_stats()
        self.app.refresh_database_label()
        self.app.log_line(f"Pembaruan basis data: {result.get('message','')}", "info")

    def _update_online(self) -> None:
        key = self.app.settings.malwarebazaar_key
        if not key:
            messagebox.showwarning(
                "Auth-Key belum diisi",
                "MalwareBazaar mewajibkan Auth-Key sejak 30 Juni 2025.\n\n"
                "Buat kunci gratis di https://auth.abuse.ch/ lalu isikan di "
                "jendela Pengaturan.\n\n"
                "Sebagai alternatif tanpa kunci, pakai Impor berkas CSV/TXT.",
                parent=self,
            )
            return
        updater = HashUpdater(self.app.engine.db)
        self._run_async(
            lambda: updater.update_from_malwarebazaar(key), "MalwareBazaar"
        )

    def _import_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Pilih berkas daftar hash",
            filetypes=[("CSV/TXT", "*.csv *.txt"), ("Semua berkas", "*.*")],
        )
        if not path:
            return
        updater = HashUpdater(self.app.engine.db)
        self._run_async(lambda: updater.update_from_file(path), "Impor berkas")

    def _import_url(self) -> None:
        dialog = _TextPrompt(self, self.app, "Unduh daftar hash", "Alamat URL berkas CSV/TXT:")
        self.wait_window(dialog)
        if not dialog.result:
            return
        updater = HashUpdater(self.app.engine.db)
        self._run_async(lambda: updater.update_from_url(dialog.result), "Unduh dari URL")

    def _clear_cache(self) -> None:
        count = self.app.engine.db.clear_cache()
        self._write(f"Hasil cache dikosongkan: {count} baris dihapus.")
        self._write(
            "Pemindaian berikutnya akan memeriksa ulang semua berkas dari awal."
        )


class _TextPrompt(tk.Toplevel):
    """Dialog kecil untuk meminta satu baris teks."""

    def __init__(self, parent, app, title: str, prompt: str) -> None:
        super().__init__(parent)
        self.result = ""
        self.title(title)
        self.configure(bg=app.colors["bg"])
        self.transient(parent)
        self.resizable(False, False)
        self.grab_set()

        frame = tk.Frame(self, bg=app.colors["bg"], padx=16, pady=14)
        frame.pack(fill="both", expand=True)
        tk.Label(
            frame,
            text=prompt,
            bg=app.colors["bg"],
            fg=app.colors["text"],
            font=("Segoe UI", 10),
        ).pack(anchor="w")
        self.var = tk.StringVar()
        entry = tk.Entry(
            frame,
            textvariable=self.var,
            width=60,
            bg=app.colors["panel"],
            fg=app.colors["text"],
            insertbackground=app.colors["text"],
            relief="flat",
            font=("Consolas", 9),
        )
        entry.pack(fill="x", pady=(8, 12), ipady=5)
        entry.focus_set()
        row = tk.Frame(frame, bg=app.colors["bg"])
        row.pack(fill="x")
        tk.Button(
            row,
            text="OK",
            command=self._ok,
            bg=app.colors["fill"],
            fg="#ffffff",
            activebackground=app.colors["fill_active"],
            activeforeground="#ffffff",
            relief="flat",
            padx=14,
            pady=6,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="right")
        self.bind("<Return>", lambda _e: self._ok())

    def _ok(self) -> None:
        self.result = self.var.get().strip()
        self.destroy()


class QuarantineWindow(_BaseWindow):
    """Daftar berkas yang dikarantina, dengan pemulihan dan penghapusan."""

    def __init__(self, parent, app) -> None:
        super().__init__(parent, app, "Karantina", "820x520")
        self._build()
        self.refresh()

    def _build(self) -> None:
        outer = tk.Frame(self, bg=self.colors["bg"])
        outer.pack(fill="both", expand=True, padx=14, pady=12)

        self.info_label = self._label(
            outer,
            "",
            bg=self.colors["bg"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
        )
        self.info_label.pack(anchor="w", pady=(0, 8))

        # Tema ttk disetel agar tabel menyatu dengan tampilan gelap.
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "SG.Treeview",
            background=self.colors["panel"],
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            rowheight=24,
            borderwidth=0,
        )
        style.configure(
            "SG.Treeview.Heading",
            background=self.colors["secondary"],
            foreground=self.colors["text"],
            relief="flat",
        )
        style.map(
            "SG.Treeview",
            background=[("selected", self.colors["fill"])],
            foreground=[("selected", "#ffffff")],
        )

        columns = ("when", "name", "size", "severity", "engine")
        self.tree = ttk.Treeview(
            outer, columns=columns, show="headings", style="SG.Treeview", height=12
        )
        headings = {
            "when": ("Waktu", 130),
            "name": ("Berkas asli", 300),
            "size": ("Ukuran", 80),
            "severity": ("Tingkat", 120),
            "engine": ("Mesin", 130),
        }
        for key, (text, width) in headings.items():
            self.tree.heading(key, text=text)
            self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)

        footer = tk.Frame(outer, bg=self.colors["bg"])
        footer.pack(fill="x", pady=(12, 0))
        self._button(footer, "Pulihkan berkas terpilih", self._restore, primary=True).pack(
            side="left"
        )
        self._button(footer, "Hapus permanen", self._delete).pack(side="left", padx=(8, 0))
        self._button(footer, "Periksa keutuhan", self._verify).pack(side="left", padx=(8, 0))
        self._button(footer, "Tutup", self.destroy).pack(side="right")

        self.detail = self._label(
            outer,
            "",
            bg=self.colors["bg"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
            wraplength=760,
        )
        self.detail.pack(anchor="w", pady=(10, 0))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_detail())

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._entries = {}
        for entry in self.app.engine.quarantine.entries():
            if entry.restored:
                continue
            item = self.tree.insert(
                "",
                "end",
                values=(
                    entry.when,
                    entry.original_path,
                    format_size(entry.size),
                    entry.severity,
                    entry.engine,
                ),
            )
            self._entries[item] = entry
        count = len(self._entries)
        total = self.app.engine.quarantine.total_size()
        self.info_label.configure(
            text=f"{count} berkas dikarantina, total {format_size(total)}. "
            f"Berkas di karantina sudah diacak isinya sehingga tidak bisa "
            f"dijalankan, tetapi masih bisa dipulihkan utuh."
        )

    def _selected(self):
        selection = self.tree.selection()
        return self._entries.get(selection[0]) if selection else None

    def _show_detail(self) -> None:
        entry = self._selected()
        if not entry:
            return
        self.detail.configure(
            text=(
                f"Aturan: {entry.rule}  |  Mesin: {entry.engine}\n"
                f"SHA-256: {entry.sha256}\n"
                f"Keterangan: {entry.detail}"
            )
        )

    def _restore(self) -> None:
        entry = self._selected()
        if not entry:
            messagebox.showinfo("Belum dipilih", "Pilih satu berkas lebih dulu.", parent=self)
            return
        if not messagebox.askyesno(
            "Pulihkan berkas",
            "Berkas ini pernah dinyatakan berbahaya. Memulihkannya berarti "
            "mengembalikannya ke komputer Anda.\n\n"
            f"{entry.original_path}\n\nLanjutkan?",
            parent=self,
        ):
            return
        ok, message = self.app.engine.quarantine.restore(entry.id)
        messagebox.showinfo("Pemulihan", message, parent=self)
        self.app.log_line(f"Karantina: {message}", "info")
        self.refresh()

    def _delete(self) -> None:
        entry = self._selected()
        if not entry:
            messagebox.showinfo("Belum dipilih", "Pilih satu berkas lebih dulu.", parent=self)
            return
        if not messagebox.askyesno(
            "Hapus permanen",
            "Berkas akan dihapus permanen dan tidak bisa dikembalikan.\n\n"
            f"{entry.original_path}",
            parent=self,
        ):
            return
        ok, message = self.app.engine.quarantine.delete(entry.id)
        self.app.log_line(f"Karantina: {message}", "info")
        self.refresh()

    def _verify(self) -> None:
        problems = self.app.engine.quarantine.verify()
        if not problems:
            messagebox.showinfo(
                "Keutuhan karantina",
                "Semua berkas di karantina utuh dan bisa dipulihkan dengan isi "
                "yang persis sama seperti saat dikarantina.",
                parent=self,
            )
        else:
            messagebox.showwarning(
                "Ada masalah di karantina",
                "Ditemukan masalah berikut:\n\n" + "\n".join(problems[:10]),
                parent=self,
            )

class AssistantWindow(_BaseWindow):
    """Jendela tanya-jawab dan penjelasan temuan dengan AI.

    Jendela ini selalu bisa dibuka. Tanpa kunci API, ia menjawab dari
    pengetahuan bawaan program; dengan kunci API, pertanyaan bebas diteruskan ke
    model. Jendela yang menolak terbuka hanya membuat pengguna mengira fiturnya
    rusak, padahal sebagian besar pertanyaannya tetap bisa dijawab.
    """

    def __init__(self, parent, app, explain_path: str = "") -> None:
        super().__init__(parent, app, "Asisten AI", "760x640")
        self.minsize(600, 460)
        self.explain_path = explain_path
        self.summary = getattr(app, "last_summary", None)
        self.assistant = app.make_assistant()
        self.busy = False
        self._build()
        if explain_path:
            self.after(100, lambda: self.explain_file(explain_path))

    # ------------------------------------------------------------- tata -- #

    def _build(self) -> None:
        outer = tk.Frame(self, bg=self.colors["bg"])
        outer.pack(fill="both", expand=True, padx=14, pady=12)

        # Keadaan AI harus terlihat sejak awal, supaya pengguna tidak mengira
        # jawaban bawaan berasal dari model.
        status = self._panel(outer)
        status.pack(fill="x")
        if self.assistant.ai_ready:
            self._label(
                status,
                "Model bahasa aktif",
                font=("Segoe UI", 10, "bold"),
                bg=self.colors["panel"],
            ).pack(anchor="w")
            self._label(
                status,
                "Pertanyaan yang tidak ada di penjelasan bawaan akan dikirim ke "
                "model.\nYang dikirim hanya ringkasan temuan: nama berkas, ukuran, "
                "hash, dan jenis temuan.\nIsi berkas tidak ikut kecuali Anda "
                "menyalakannya di Pengaturan.",
                bg=self.colors["panel"],
                fg=self.colors["muted"],
                font=("Segoe UI", 9),
                justify="left",
            ).pack(anchor="w", pady=(4, 0))
        else:
            self._label(
                status,
                "Mode tanpa model bahasa",
                font=("Segoe UI", 10, "bold"),
                bg=self.colors["panel"],
            ).pack(anchor="w")
            self._label(
                status,
                "Pertanyaan tentang cara kerja program, karantina, EICAR, dan "
                "batas pemindaian tetap\nbisa dijawab dari penjelasan bawaan. "
                "Untuk pertanyaan bebas, aktifkan model bahasa\ndi Pengaturan, "
                "atau pasang Ollama agar model berjalan di komputer sendiri.",
                bg=self.colors["panel"],
                fg=self.colors["muted"],
                font=("Segoe UI", 9),
                justify="left",
            ).pack(anchor="w", pady=(4, 0))

        if self.summary is not None:
            self._label(
                status,
                f"Bahan jawaban: hasil pemindaian {self.summary.root} "
                f"({len(self.summary.findings)} temuan).",
                bg=self.colors["panel"],
                fg=self.colors["muted"],
                font=("Segoe UI", 9),
                justify="left",
            ).pack(anchor="w", pady=(4, 0))

        # Tombol pertanyaan saran: kotak tanya-jawab yang kosong jarang dipakai.
        saran = self._panel(outer)
        saran.pack(fill="x", pady=(10, 0))
        self._label(
            saran,
            "Pertanyaan yang sering diajukan",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w", pady=(0, 6))
        grid = tk.Frame(saran, bg=self.colors["panel"])
        grid.pack(fill="x")
        for index, question in enumerate(suggested_questions()):
            self._button(
                grid, question, lambda q=question: self.ask(q)
            ).grid(row=index // 2, column=index % 2, sticky="ew", padx=(0, 8), pady=3)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        # Riwayat tanya-jawab.
        percakapan = self._panel(outer)
        percakapan.pack(fill="both", expand=True, pady=(10, 0))
        self._label(
            percakapan,
            "Percakapan",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["panel"],
        ).pack(anchor="w", pady=(0, 4))

        holder = tk.Frame(percakapan, bg=self.colors["panel"])
        holder.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(holder, orient="vertical")
        scrollbar.pack(side="right", fill="y")
        self.chat = tk.Text(
            holder,
            wrap="word",
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 10),
            padx=10,
            pady=8,
            yscrollcommand=scrollbar.set,
        )
        scrollbar.configure(command=self.chat.yview)
        self.chat.pack(side="left", fill="both", expand=True)
        self.chat.configure(state="disabled")
        # Tag warna memakai nama tanpa spasi: Tk memecah nama bertanda spasi
        # menjadi beberapa tag dan warnanya tidak terpakai.
        self.chat.tag_configure("tanya", foreground=self.colors["accent"],
                                font=("Segoe UI", 10, "bold"))
        self.chat.tag_configure("jawab", foreground=self.colors["text"])
        self.chat.tag_configure("catatan", foreground=self.colors["muted"],
                                font=("Segoe UI", 9))

        # Kotak pertanyaan.
        tanya = tk.Frame(outer, bg=self.colors["bg"])
        tanya.pack(fill="x", pady=(10, 0))
        self.question_var = tk.StringVar()
        entry = tk.Entry(
            tanya,
            textvariable=self.question_var,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 10),
        )
        entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        entry.bind("<Return>", lambda _event: self.ask(self.question_var.get()))
        self.ask_btn = self._button(
            tanya, "Tanya", lambda: self.ask(self.question_var.get()), primary=True
        )
        self.ask_btn.pack(side="left")
        self.force_btn = self._button(
            tanya, "Tanya AI", lambda: self.ask(self.question_var.get(), force_ai=True)
        )
        self.force_btn.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="")
        self._label(
            outer, "", textvariable=self.status_var,
            bg=self.colors["bg"], fg=self.colors["muted"], font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))

        self._write(
            "Tanyakan apa saja tentang hasil pemindaian, atau tekan salah satu "
            "pertanyaan di atas.\n"
        )

    # --------------------------------------------------------- percakapan -- #

    def _write(self, text: str, tag: str = "jawab") -> None:
        self.chat.configure(state="normal")
        self.chat.insert("end", text + "\n", tag)
        self.chat.configure(state="disabled")
        self.chat.see("end")

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        for button in (self.ask_btn, self.force_btn):
            button.configure(state=state)
        self.status_var.set(message)

    def ask(self, question: str, force_ai: bool = False) -> None:
        question = (question or "").strip()
        if not question or self.busy:
            return

        self._write("Anda: " + question, "tanya")
        self.question_var.set("")

        # Pertanyaan bawaan dijawab langsung: tidak perlu menunggu jaringan, dan
        # jawabannya pasti benar karena tidak dikarang model.
        if not force_ai:
            builtin = answer_from_knowledge(question)
            if builtin is not None:
                self._write("Asisten: " + builtin.text)
                self._write("(dijawab dari penjelasan bawaan program)", "catatan")
                return

        if not self.assistant.ai_ready:
            answer = self.assistant.ask(question, summary=self.summary, force_ai=True)
            self._write("Asisten: " + answer.text)
            return

        self._set_busy(True, "Menunggu jawaban dari model...")

        def job() -> None:
            try:
                answer = self.assistant.ask(
                    question, summary=self.summary, force_ai=True
                )
                self.after(0, lambda: self._show_answer(answer))
            except Exception as error:  # noqa: BLE001 - apa pun harus terlihat
                self.after(0, lambda: self._show_error(error))

        threading.Thread(target=job, daemon=True).start()

    def _show_answer(self, answer) -> None:
        self._set_busy(False)
        self._write("Asisten: " + answer.text)
        note = f"(dari {answer.source}"
        if answer.usage_note:
            note += " - " + answer.usage_note
        note += ")"
        self._write(note, "catatan")

    def _show_error(self, error: Exception) -> None:
        self._set_busy(False)
        self._write("Gagal mendapat jawaban: " + str(error))

    # ------------------------------------------------- penjelasan berkas -- #

    def explain_file(self, path: str) -> None:
        """Minta penjelasan satu berkas, dijalankan di thread terpisah."""
        if self.busy:
            return
        if not self.assistant.ai_ready:
            self._write(
                "Penjelasan satu berkas memerlukan model bahasa. Aktifkan di "
                "Pengaturan, atau pakai Ollama agar model berjalan di komputer "
                "sendiri."
            )
            return

        self._write("Meminta penjelasan untuk: " + os.path.basename(path), "tanya")
        self._set_busy(True, "Mengirim ringkasan berkas ke model...")

        summary = self.summary
        settings = self.app.settings

        def job() -> None:
            try:
                report = build_file_report(path, summary, settings)
                analyst = AiAnalyst(self.assistant.analyst.client, cache=self.app.ai_cache)
                hasil = analyst.explain_file(report)
                self.after(0, lambda: self._show_explanation(hasil.result))
            except Exception as error:  # noqa: BLE001 - apa pun harus terlihat
                self.after(0, lambda: self._show_error(error))

        threading.Thread(target=job, daemon=True).start()

    def _show_explanation(self, result) -> None:
        self._set_busy(False)
        header = f"Penilaian: {result.verdict} (keyakinan {result.confidence})"
        if result.from_cache:
            header += " - dari cache, tidak memanggil model lagi"
        self._write(header, "catatan")
        self._write(result.explanation)
        if result.actions:
            self._write("Yang sebaiknya dilakukan:", "catatan")
            for step in result.actions:
                self._write("  - " + step)
        if result.flags:
            self._write("Dasar penilaian:", "catatan")
            for flag in result.flags:
                self._write("  - " + flag)


def build_file_report(path: str, summary, settings):
    """Susun keterangan satu berkas dari hasil pemindaian yang sudah ada.

    Data temuan diambil dari hasil pemindaian, bukan dengan memindai ulang
    berkasnya. Memindai ulang berarti menunggu ClamAV memuat basis datanya lagi
    hanya untuk menjelaskan satu berkas.
    """
    findings = []
    if summary is not None:
        for finding in summary.findings:
            if finding.path == path:
                findings.append(
                    {
                        "severity": finding.severity,
                        "engine": finding.engine,
                        "rule": finding.rule,
                        "detail": finding.detail,
                    }
                )

    sha256 = ""
    try:
        sha256, _sha1, _md5 = hash_file(path)
    except OSError:
        pass

    snippet = ""
    if getattr(settings, "ai_send_snippet", False):
        try:
            with open(path, "rb") as handle:
                raw = handle.read(1024)
            # Hanya tampilkan bila isinya memang teks. Mengirim potongan biner
            # tidak berguna bagi model dan hanya memboroskan kuota.
            snippet = raw.decode("utf-8", "ignore")
        except OSError:
            snippet = ""

    return FileReport(
        name=os.path.basename(path),
        size=os.path.getsize(path) if os.path.exists(path) else 0,
        sha256=sha256,
        extension=os.path.splitext(path)[1].lower(),
        findings=findings,
        snippet=snippet,
    )
