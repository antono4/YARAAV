"""Basis data hash malware (SQLite) dan jalur pembaruannya.

Ini bagian yang membuat deteksi menjadi sungguhan, bukan simulasi: berkas
dikenali dari **sidik jari SHA-256-nya**, sama seperti cara kerja antivirus
komersial. Sebuah berkas dengan hash yang persis sama dengan sampel malware
yang sudah dikonfirmasi adalah berkas itu - tidak ada tebak-tebakan.

Isi basis data berasal dari tiga sumber:

1. Bawaan (seed)    - EICAR dan beberapa hash uji, supaya program langsung
                      berguna setelah dipasang tanpa perlu internet.
2. MalwareBazaar    - API publik abuse.ch. Sejak 30 Juni 2025 API ini WAJIB
                      memakai header `Auth-Key`. Kuncinya gratis dan bisa
                      dibuat di https://auth.abuse.ch/ . Kunci disimpan di
                      berkas konfigurasi milik pengguna, bukan di dalam kode.
3. Berkas lokal     - CSV/TXT berisi daftar hash. Jalur ini tidak butuh
                      internet dan selalu bisa dipakai, misalnya untuk daftar
                      hash internal organisasi atau ekspor dari alat lain.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .config import SEV_MALWARE, data_dir, ensure_data_dir

MALWAREBAZAAR_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
USER_AGENT = "ScanGuard/2.0 (alat edukasi pemindai hash)"

SCHEMA = """
CREATE TABLE IF NOT EXISTS hashes (
    sha256    TEXT PRIMARY KEY,
    sha1      TEXT,
    md5       TEXT,
    name      TEXT,
    threat    TEXT,
    source    TEXT,
    added_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_hashes_sha1 ON hashes(sha1);
CREATE INDEX IF NOT EXISTS idx_hashes_md5  ON hashes(md5);

CREATE TABLE IF NOT EXISTS scanned_cache (
    path      TEXT PRIMARY KEY,
    size      INTEGER,
    mtime     REAL,
    sha256    TEXT,
    verdict   TEXT,
    findings  TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Hash EICAR. Berkas uji standar industri antivirus - isinya tidak berbahaya,
# tetapi setiap antivirus asli mengenalinya, jadi cocok untuk memastikan
# mesin hash benar-benar bekerja setelah pemasangan.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"

SEED_RECORDS = [
    (EICAR_SHA256, EICAR_SHA1, EICAR_MD5, "eicar.com",
     "EICAR-Test-File", "bawaan"),
]


@dataclass
class HashMatch:
    """Hasil pencarian hash di basis data."""

    sha256: str
    name: str
    threat: str
    source: str

    def detail(self) -> str:
        label = self.threat or self.name or "nama tidak diketahui"
        return f"Cocok dengan basis data malware: {label} (sumber: {self.source})"


class HashDatabase:
    """Basis data hash malware berbasis SQLite.

    Aman dipakai dari beberapa thread: satu koneksi dengan pengunci, karena
    pemindaian berjalan di thread terpisah dari antarmuka.
    """

    def __init__(self, path: str | None = None) -> None:
        ensure_data_dir()
        self.path = path or os.path.join(data_dir(), "hashes.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()
        self.seed_if_empty()

    def _migrate(self) -> None:
        """Tambahkan kolom yang belum ada pada basis data versi lama.

        Tanpa langkah ini, pengguna yang memperbarui program akan mendapat
        error "no such column" saat cache dipakai.
        """
        columns = {
            row[1] for row in self._conn.execute("PRAGMA table_info(scanned_cache)")
        }
        if "findings" not in columns:
            self._conn.execute("ALTER TABLE scanned_cache ADD COLUMN findings TEXT")

    # ------------------------------------------------------------ dasar -- #

    def seed_if_empty(self) -> int:
        """Isi basis data dengan hash bawaan bila masih kosong."""
        with self._lock:
            count = self._conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        if count:
            return 0
        return self.add_many(SEED_RECORDS, source="bawaan")

    def add_many(self, records, source: str = "impor") -> int:
        """Tambahkan banyak hash. Kembalikan jumlah baris yang benar-benar baru.

        records: iterable berisi (sha256, sha1, md5, name, threat)
        """
        now = int(time.time())
        rows = []
        for record in records:
            sha256, sha1, md5 = (record[0] or "").lower(), (record[1] or "").lower(), (record[2] or "").lower()
            name = record[3] if len(record) > 3 else ""
            threat = record[4] if len(record) > 4 else ""
            if len(sha256) != 64:
                continue  # hanya SHA-256 yang bisa jadi kunci utama
            rows.append((sha256, sha1, md5, name, threat, source, now))
        if not rows:
            return 0
        with self._lock:
            before = self._conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            self._conn.executemany(
                "INSERT OR IGNORE INTO hashes "
                "(sha256, sha1, md5, name, threat, source, added_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            self._conn.commit()
            after = self._conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        return after - before

    def lookup(self, sha256: str = "", sha1: str = "", md5: str = "") -> HashMatch | None:
        """Cari berkas di basis data memakai hash mana pun yang tersedia."""
        queries = []
        if sha256:
            queries.append(("sha256 = ?", sha256.lower()))
        if sha1:
            queries.append(("sha1 = ?", sha1.lower()))
        if md5:
            queries.append(("md5 = ?", md5.lower()))
        with self._lock:
            for where, value in queries:
                row = self._conn.execute(
                    f"SELECT sha256, name, threat, source FROM hashes WHERE {where} LIMIT 1",
                    (value,),
                ).fetchone()
                if row:
                    return HashMatch(*row)
        return None

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]

    def stats(self) -> dict:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            rows = self._conn.execute(
                "SELECT source, COUNT(*) FROM hashes GROUP BY source ORDER BY 2 DESC"
            ).fetchall()
            updated = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'last_update'"
            ).fetchone()
            updated_text = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'last_update_text'"
            ).fetchone()
        return {
            "total": total,
            "by_source": dict(rows),
            "last_update": updated[0] if updated else None,
            "last_update_text": updated_text[0] if updated_text else None,
        }

    # ------------------------------------------------------------- cache -- #

    def get_cached(
        self, path: str, size: int, mtime: float
    ) -> tuple[str, str, list[dict]] | None:
        """Ambil hasil pemindaian lama untuk berkas yang tidak berubah.

        Yang dikembalikan bukan hanya kesimpulannya, tetapi juga **daftar
        temuannya**. Tanpa itu, pemindaian ulang yang memakai cache akan
        melaporkan "ada malware" tanpa bisa menjelaskan apa temuannya - laporan
        yang menyesatkan.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT sha256, verdict, findings FROM scanned_cache "
                "WHERE path = ? AND size = ? AND mtime = ?",
                (path, size, mtime),
            ).fetchone()
        if not row:
            return None
        try:
            findings = json.loads(row[2]) if row[2] else []
        except (ValueError, TypeError):
            findings = []
        return row[0], row[1], findings

    def put_cached(
        self,
        path: str,
        size: int,
        mtime: float,
        sha256: str,
        verdict: str,
        findings: list[dict] | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO scanned_cache "
                "(path, size, mtime, sha256, verdict, findings) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    path,
                    size,
                    mtime,
                    sha256,
                    verdict,
                    json.dumps(findings or [], ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def clear_cache(self) -> int:
        with self._lock:
            before = self._conn.execute("SELECT COUNT(*) FROM scanned_cache").fetchone()[0]
            self._conn.execute("DELETE FROM scanned_cache")
            self._conn.commit()
        return before

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value)
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# --------------------------------------------------------------------------- #
# Pembaruan basis data
# --------------------------------------------------------------------------- #


def _http_post(url: str, data: dict, headers: dict, timeout: float) -> bytes:
    body = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _http_get(url: str, headers: dict, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def parse_malwarebazaar_response(payload: bytes) -> list[tuple]:
    """Ubah jawaban JSON MalwareBazaar menjadi baris hash.

    Dipisah dari fungsi jaringan supaya bisa diuji dengan data contoh tanpa
    perlu internet maupun API key.
    """
    try:
        data = json.loads(payload.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return []
    if data.get("query_status") not in ("ok", "no_results"):
        return []
    rows = []
    for item in data.get("data") or []:
        if not isinstance(item, dict):
            continue
        tags = item.get("tags") or []
        threat = item.get("signature") or (tags[0] if tags else "")
        rows.append(
            (
                item.get("sha256_hash", ""),
                item.get("sha1_hash", ""),
                item.get("md5_hash", ""),
                item.get("file_name") or "",
                threat,
            )
        )
    return rows


def parse_hash_list(text: str) -> list[tuple]:
    """Baca daftar hash dari teks biasa, CSV, atau ekspor CSV abuse.ch.

    Mendukung beberapa bentuk yang umum:
      * satu hash per baris
      * `hash,nama` atau `hash,nama,tingkat`
      * CSV abuse.ch dengan baris komentar `#` dan banyak kolom
    """
    rows: list[tuple] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # CSV abuse.ch memakai kutip dan koma; pakai csv.reader agar aman.
        try:
            fields = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration):
            continue
        fields = [f.strip().strip('"') for f in fields]
        if not fields:
            continue
        for field in fields:
            candidate = field.lower()
            if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                if candidate not in seen:
                    seen.add(candidate)
                    name = fields[1] if len(fields) > 1 and fields[1] != field else ""
                    threat = fields[2] if len(fields) > 2 else ""
                    rows.append((candidate, "", "", name, threat))
                break
    return rows


class HashUpdater:
    """Mengunduh dan mengimpor daftar hash malware."""

    def __init__(self, database: HashDatabase, timeout: float = 45.0) -> None:
        self.db = database
        self.timeout = timeout

    def update_from_malwarebazaar(self, auth_key: str, hours: int = 48) -> dict:
        """Ambil deteksi terbaru dari MalwareBazaar.

        Butuh Auth-Key gratis dari https://auth.abuse.ch/ . Tanpa kunci, API
        menjawab `no_api_key` dan fungsi ini mengembalikan pesan yang jelas
        supaya pengguna tahu apa yang harus dilakukan.
        """
        if not auth_key:
            return {
                "ok": False,
                "added": 0,
                "message": (
                    "MalwareBazaar memerlukan Auth-Key (gratis) sejak 30 Juni 2025. "
                    "Buat di https://auth.abuse.ch/ lalu tempelkan di kolom Auth-Key."
                ),
            }
        try:
            payload = _http_post(
                MALWAREBAZAAR_ENDPOINT,
                {"query": "recent_detections", "hours": str(hours)},
                {"Auth-Key": auth_key, "User-Agent": USER_AGENT},
                self.timeout,
            )
        except urllib.error.HTTPError as error:
            return {"ok": False, "added": 0, "message": f"Server menolak permintaan: HTTP {error.code}"}
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return {"ok": False, "added": 0, "message": f"Tidak bisa menghubungi server: {error}"}

        try:
            status = json.loads(payload.decode("utf-8", "replace")).get("query_status")
        except (ValueError, UnicodeDecodeError):
            status = None
        if status == "no_api_key":
            return {"ok": False, "added": 0, "message": "Auth-Key tidak diterima. Periksa kembali kuncinya."}
        if status == "user_blacklisted":
            return {"ok": False, "added": 0, "message": "Auth-Key diblokir oleh abuse.ch."}

        rows = parse_malwarebazaar_response(payload)
        added = self.db.add_many(rows, source="MalwareBazaar")
        self._stamp(added, len(rows))
        return {
            "ok": True,
            "added": added,
            "received": len(rows),
            "message": f"{added} hash baru dari {len(rows)} deteksi terbaru MalwareBazaar.",
        }

    def update_from_text(self, text: str, source: str = "berkas lokal") -> dict:
        """Impor daftar hash dari teks (isi berkas CSV/TXT)."""
        rows = parse_hash_list(text)
        added = self.db.add_many(rows, source=source)
        self._stamp(added, len(rows))
        return {
            "ok": True,
            "added": added,
            "received": len(rows),
            "message": f"{added} hash baru dari {len(rows)} baris yang dibaca.",
        }

    def update_from_file(self, path: str) -> dict:
        """Impor daftar hash dari berkas CSV/TXT di komputer pengguna."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as error:
            return {"ok": False, "added": 0, "message": f"Gagal membaca berkas: {error}"}
        return self.update_from_text(text, source=os.path.basename(path))

    def update_from_url(self, url: str) -> dict:
        """Impor daftar hash dari URL yang menyajikan CSV/TXT biasa.

        Berguna untuk daftar hash internal atau cermin feed yang tidak
        memerlukan autentikasi.
        """
        try:
            payload = _http_get(url, {"User-Agent": USER_AGENT}, self.timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as error:
            return {"ok": False, "added": 0, "message": f"Gagal mengunduh: {error}"}
        return self.update_from_text(payload.decode("utf-8", "replace"), source=url)

    def _stamp(self, added: int, received: int) -> None:
        self.db.set_meta("last_update", str(int(time.time())))
        self.db.set_meta(
            "last_update_text",
            time.strftime("%d-%m-%Y %H:%M:%S") + f" ({added} baru dari {received})",
        )
