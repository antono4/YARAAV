"""Karantina: memindahkan berkas berbahaya ke tempat yang tidak bisa dijalankan.

Prinsip karantina yang benar ada tiga, dan ketiganya mudah salah:

1. **Berkas harus benar-benar tidak bisa dijalankan lagi.** Hanya mengganti nama
   menjadi `virus.txt` tidak cukup: pengguna bisa mengubah namanya kembali, dan
   beberapa program masih bisa dijalankan dari nama apa pun. Karena itu isi
   berkasnya diacak (di-XOR) dengan kunci yang disimpan terpisah.
2. **Berkas tidak boleh hilang tanpa jejak.** Karantina harus bisa dipulihkan,
   dan bila pemulihan gagal, isi aslinya tidak boleh rusak. Karena itu berkas
   asli disalin dulu ke karantina, dan baru dihapus setelah salinannya utuh.
3. **Berkas tidak boleh menimpa berkas lain di karantina.** Nama di karantina
   memakai UUID, bukan nama aslinya, sehingga dua berkas bernama sama tidak
   saling menghapus.

Yang di-XOR bukan enkripsi sungguhan (kuncinya ada di berkas yang sama), tetapi
cukup untuk tujuan ini: berkas tidak lagi bisa dijalankan atau dikenali, dan
pengguna tidak bisa "menjalankan" berkas karantina secara tidak sengaja.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field

from .config import ensure_data_dir, data_dir
from .core import format_size, hash_file

# Ukuran bagian yang di-XOR sekali jalan.
XOR_CHUNK = 1024 * 1024
# Kunci pengacak. Bukan rahasia - ini hanya mencegah berkas bisa dijalankan.
SCRAMBLE_KEY = b"ScanGuard-quarantine-v2"


@dataclass
class QuarantineEntry:
    """Catatan satu berkas yang dikarantina."""

    id: str
    original_path: str
    stored_name: str
    size: int
    sha256: str
    engine: str
    rule: str
    detail: str
    severity: str
    quarantined_at: float
    restored: bool = False

    @property
    def when(self) -> str:
        return time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(self.quarantined_at))


class Quarantine:
    """Folder karantina beserta catatannya."""

    def __init__(self, root: str | None = None) -> None:
        ensure_data_dir()
        self.root = root or os.path.join(data_dir(), "quarantine")
        self.files_dir = os.path.join(self.root, "files")
        self.index_path = os.path.join(self.root, "index.json")
        os.makedirs(self.files_dir, exist_ok=True)
        self._entries: dict[str, QuarantineEntry] = {}
        self._load()

    # ------------------------------------------------------------ catatan -- #

    def _load(self) -> None:
        if not os.path.exists(self.index_path):
            return
        try:
            with open(self.index_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            return  # catatan rusak: mulai dari kosong, berkas karantina tetap ada
        for item in raw.get("entries", []):
            try:
                entry = QuarantineEntry(**item)
            except TypeError:
                continue
            self._entries[entry.id] = entry

    def _save(self) -> None:
        payload = {"entries": [e.__dict__ for e in self._entries.values()]}
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        # Ganti berkas secara atomik supaya catatan tidak rusak bila program
        # tertutup di tengah penulisan.
        os.replace(tmp, self.index_path)

    # ----------------------------------------------------------- tindakan -- #

    def quarantine_file(
        self, path: str, engine: str, rule: str, detail: str, severity: str
    ) -> tuple[bool, str]:
        """Pindahkan satu berkas ke karantina.

        Kembalikan (berhasil, pesan). Urutannya sengaja seperti ini:
        salin -> periksa salinan -> acak -> hapus asli. Kalau ada langkah yang
        gagal, berkas asli tidak pernah disentuh.
        """
        if not os.path.isfile(path):
            return False, "Berkas tidak ditemukan."

        try:
            size = os.path.getsize(path)
            sha256, _, _ = hash_file(path)
        except OSError as error:
            return False, f"Tidak bisa membaca berkas: {error}"

        entry_id = uuid.uuid4().hex
        stored_name = f"{entry_id}.qtn"
        stored_path = os.path.join(self.files_dir, stored_name)

        # 1. Salin dulu. Berkas asli belum diapa-apakan.
        try:
            shutil.copy2(path, stored_path)
        except OSError as error:
            return False, f"Gagal menyalin ke karantina: {error}"

        # 2. Pastikan salinannya utuh sebelum menghapus yang asli.
        try:
            copied_hash, _, _ = hash_file(stored_path)
        except OSError as error:
            self._safe_remove(stored_path)
            return False, f"Salinan karantina tidak bisa dibaca: {error}"
        if copied_hash != sha256:
            self._safe_remove(stored_path)
            return False, "Salinan karantina tidak sama dengan berkas asli; dibatalkan."

        # 3. Acak isinya supaya tidak bisa dijalankan.
        try:
            self._scramble(stored_path)
        except OSError as error:
            self._safe_remove(stored_path)
            return False, f"Gagal mengacak isi karantina: {error}"

        # 4. Baru hapus berkas asli.
        try:
            os.remove(path)
        except OSError as error:
            # Karantina sudah aman, tetapi berkas asli masih ada. Beri tahu
            # apa adanya, jangan berpura-pura berhasil.
            self._safe_remove(stored_path)
            return False, f"Berkas asli tidak bisa dihapus (mungkin sedang dipakai): {error}"

        entry = QuarantineEntry(
            id=entry_id,
            original_path=os.path.abspath(path),
            stored_name=stored_name,
            size=size,
            sha256=sha256,
            engine=engine,
            rule=rule,
            detail=detail,
            severity=severity,
            quarantined_at=time.time(),
        )
        self._entries[entry_id] = entry
        self._save()
        return True, f"Dipindahkan ke karantina ({format_size(size)})."

    def restore(self, entry_id: str, destination: str | None = None) -> tuple[bool, str]:
        """Kembalikan berkas ke lokasi asalnya (atau lokasi lain bila diminta)."""
        entry = self._entries.get(entry_id)
        if not entry:
            return False, "Catatan karantina tidak ditemukan."

        stored_path = os.path.join(self.files_dir, entry.stored_name)
        if not os.path.exists(stored_path):
            return False, "Berkas karantina sudah tidak ada."

        target = destination or entry.original_path
        if os.path.exists(target):
            # Jangan menimpa berkas yang sudah ada di tujuan.
            base, ext = os.path.splitext(target)
            target = f"{base}.dipulihkan{ext}"

        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            # Salin dulu, baru buka acaknya, supaya berkas karantina tidak
            # rusak kalau proses gagal di tengah.
            shutil.copy2(stored_path, target)
            self._unscramble(target)
        except OSError as error:
            self._safe_remove(target)
            return False, f"Gagal memulihkan berkas: {error}"

        try:
            restored_hash, _, _ = hash_file(target)
        except OSError:
            restored_hash = ""
        if entry.sha256 and restored_hash != entry.sha256:
            return False, (
                "Berkas dipulihkan tetapi isinya tidak sama dengan aslinya. "
                f"Periksa: {target}"
            )

        self._safe_remove(stored_path)
        entry.restored = True
        self._save()
        return True, f"Dipulihkan ke: {target}"

    def delete(self, entry_id: str) -> tuple[bool, str]:
        """Hapus berkas dari karantina secara permanen."""
        entry = self._entries.get(entry_id)
        if not entry:
            return False, "Catatan karantina tidak ditemukan."
        stored_path = os.path.join(self.files_dir, entry.stored_name)
        self._safe_remove(stored_path)
        self._entries.pop(entry_id, None)
        self._save()
        return True, "Berkas dihapus permanen dari karantina."

    def delete_all(self) -> int:
        count = 0
        for entry_id in list(self._entries):
            ok, _ = self.delete(entry_id)
            if ok:
                count += 1
        return count

    def entries(self) -> list[QuarantineEntry]:
        return sorted(self._entries.values(), key=lambda e: e.quarantined_at, reverse=True)

    def active_entries(self) -> list[QuarantineEntry]:
        return [e for e in self.entries() if not e.restored]

    def total_size(self) -> int:
        total = 0
        for entry in self.active_entries():
            path = os.path.join(self.files_dir, entry.stored_name)
            try:
                total += os.path.getsize(path)
            except OSError:
                continue
        return total

    def verify(self) -> list[str]:
        """Periksa keutuhan karantina: kembalikan daftar masalah yang ditemukan.

        Fungsi ini berguna untuk membuktikan bahwa karantina benar-benar bisa
        dipulihkan, bukan hanya mengklaim bisa.
        """
        problems = []
        for entry in self.active_entries():
            stored_path = os.path.join(self.files_dir, entry.stored_name)
            if not os.path.exists(stored_path):
                problems.append(f"{entry.id}: berkas karantina hilang")
                continue
            # Buka acak di salinan sementara, lalu hitung hash-nya.
            temp = stored_path + ".verify"
            try:
                shutil.copy2(stored_path, temp)
                self._unscramble(temp)
                digest, _, _ = hash_file(temp)
                if entry.sha256 and digest != entry.sha256:
                    problems.append(
                        f"{entry.id}: isi tidak cocok dengan catatan "
                        f"({digest[:12]} != {entry.sha256[:12]})"
                    )
            except OSError as error:
                problems.append(f"{entry.id}: gagal diperiksa ({error})")
            finally:
                self._safe_remove(temp)
        return problems

    # ------------------------------------------------------------ bantuan -- #

    def _scramble(self, path: str) -> None:
        self._xor_in_place(path)

    def _unscramble(self, path: str) -> None:
        # XOR adalah operasi yang membalik dirinya sendiri: menerapkan kunci
        # yang sama dua kali mengembalikan isi aslinya.
        self._xor_in_place(path)

    def _xor_in_place(self, path: str) -> None:
        key_len = len(SCRAMBLE_KEY)
        with open(path, "r+b") as handle:
            offset = 0
            while True:
                chunk = handle.read(XOR_CHUNK)
                if not chunk:
                    break
                scrambled = bytes(
                    byte ^ SCRAMBLE_KEY[(offset + i) % key_len]
                    for i, byte in enumerate(chunk)
                )
                handle.seek(offset)
                handle.write(scrambled)
                offset += len(chunk)

    @staticmethod
    def _safe_remove(path: str) -> None:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    @staticmethod
    def fingerprint(path: str) -> str:
        """Hitung sidik jari singkat sebuah berkas, untuk ditampilkan."""
        try:
            return hashlib.sha256(path.encode()).hexdigest()[:12]
        except Exception:  # noqa: BLE001
            return ""
