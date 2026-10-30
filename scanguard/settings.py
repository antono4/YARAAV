"""Pengaturan yang bisa disimpan pengguna (JSON di folder data).

Yang disimpan di sini adalah hal-hal yang memang perlu diketik pengguna, bukan
bagian dari program:

* `clamav_path`    - lokasi clamscan bila tidak ada di PATH
* `malwarebazaar_key` - Auth-Key gratis dari abuse.ch untuk memperbarui basis
                        data hash. **Disimpan di berkas milik pengguna, bukan di
                        dalam kode**, dan tidak pernah dicatat ke log.
* `exclusions`     - daftar potongan path yang tidak ingin dipindai
* `auto_quarantine` - memindahkan temuan MALWARE ke karantina secara otomatis
* `ai_*`           - pengaturan kecerdasan buatan: penyedia, model, dan kunci
                     API. **Disimpan di berkas milik pengguna dengan izin baca
                     terbatas, dan tidak pernah dicatat ke log.** Kunci juga bisa
                     diberikan lewat variabel lingkungan (SCANGUARD_AI_KEY atau
                     kunci resmi penyedia), dan itu lebih aman karena tidak
                     tersimpan di disk sama sekali.

Berkas ini ditaruh di folder data pengguna dengan izin terbatas, karena berisi
kunci API.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field

from .config import data_dir, ensure_data_dir


@dataclass
class Settings:
    clamav_path: str = ""
    malwarebazaar_key: str = ""
    exclusions: list[str] = field(default_factory=list)
    auto_quarantine: bool = False
    # Mesin mana yang dipakai saat memindai.
    use_yara: bool = True
    use_pe: bool = True
    use_clamav: bool = True
    # Tampilkan berkas bersih satu per satu di log (biasanya terlalu ramai).
    log_clean_files: bool = False

    # --- Kecerdasan buatan ------------------------------------------------- #
    # Deteksi anomali memakai model lokal: tanpa internet, tanpa kunci, tanpa
    # biaya. Dinyalakan secara bawaan karena berguna untuk semua orang.
    ai_anomaly: bool = True
    # Penjelasan temuan dengan model bahasa memerlukan kunci API berbayar, jadi
    # bawaannya dimatikan. Fitur yang mengeluarkan biaya tanpa diminta bukan
    # fitur yang baik.
    ai_explain: bool = False
    ai_provider: str = "openai"
    ai_model: str = ""
    ai_base_url: str = ""
    ai_api_key: str = ""
    ai_timeout: float = 60.0
    # Isi berkas ikut dikirim ke model. Bawaannya mati: menyalakannya berarti
    # isi berkas pengguna keluar dari komputernya.
    ai_send_snippet: bool = False

    @classmethod
    def load(cls) -> "Settings":
        path = cls.path()
        if not os.path.exists(path):
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            # Berkas rusak: kembali ke pengaturan bawaan daripada gagal jalan.
            return cls()
        known = {f for f in cls().__dataclass_fields__}
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self) -> None:
        ensure_data_dir()
        path = self.path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(asdict(self), handle, indent=2, ensure_ascii=False)
        # Batasi izin baca: berkas ini bisa berisi Auth-Key.
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(tmp, path)

    @staticmethod
    def path() -> str:
        return os.path.join(data_dir(), "settings.json")
