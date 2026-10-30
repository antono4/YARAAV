"""Penyimpanan hasil analisis AI agar tidak memanggil model berulang kali.

Analisis AI memakan kuota berbayar (atau waktu, bila memakai model lokal), dan
jawaban untuk berkas yang sama tidak akan berubah. Karena itu hasilnya disimpan.

Kuncinya adalah **hash berkas**, bukan path. Berkas yang dipindahkan atau
berganti nama tetap dianggap sudah pernah dianalisis, sedangkan berkas yang
isinya berubah otomatis dianalisis ulang. Ini sama dengan cara cache pemindaian
bekerja, dan alasannya sama: hasilnya harus tetap dapat dipercaya.

Penyimpanan memakai SQLite karena basis data itu sudah dipakai program ini untuk
hal lain, sehingga tidak ada ketergantungan baru.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

from ..config import data_dir, ensure_data_dir
from .base import AnalysisResult, Usage

SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_cache (
    key         TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    explanation TEXT NOT NULL,
    actions     TEXT NOT NULL,
    flags       TEXT NOT NULL,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_usage (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    provider          TEXT NOT NULL,
    model             TEXT NOT NULL,
    prompt_tokens     INTEGER NOT NULL,
    completion_tokens INTEGER NOT NULL,
    at                REAL NOT NULL
);
"""


class AiCache:
    """Cache hasil analisis AI dan catatan pemakaian kuota."""

    def __init__(self, path: str | None = None) -> None:
        ensure_data_dir()
        self.path = path or os.path.join(data_dir(), "ai_cache.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------ cache -- #

    def get(self, key: str, provider: str, model: str) -> AnalysisResult | None:
        """Ambil hasil lama, bila ada dan dibuat oleh model yang sama."""
        with self._lock:
            row = self._conn.execute(
                "SELECT verdict, confidence, explanation, actions, flags, "
                "prompt_tokens, completion_tokens FROM ai_cache "
                "WHERE key = ? AND provider = ? AND model = ?",
                (key, provider, model),
            ).fetchone()
        if row is None:
            return None
        try:
            actions = json.loads(row[3])
            flags = json.loads(row[4])
        except ValueError:
            # Baris rusak: anggap tidak ada, lalu model akan ditanya ulang.
            return None
        return AnalysisResult(
            verdict=row[0],
            confidence=row[1],
            explanation=row[2],
            actions=actions,
            flags=flags,
            model=model,
            usage=Usage(row[5], row[6]),
            from_cache=True,
        )

    def put(self, key: str, provider: str, model: str, result: AnalysisResult) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO ai_cache "
                "(key, provider, model, verdict, confidence, explanation, actions, "
                " flags, prompt_tokens, completion_tokens, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    key,
                    provider,
                    model,
                    result.verdict,
                    result.confidence,
                    result.explanation,
                    json.dumps(result.actions, ensure_ascii=False),
                    json.dumps(result.flags, ensure_ascii=False),
                    result.usage.prompt_tokens,
                    result.usage.completion_tokens,
                    time.time(),
                ),
            )
            self._conn.commit()

    def clear(self) -> int:
        with self._lock:
            count = self._conn.execute("SELECT COUNT(*) FROM ai_cache").fetchone()[0]
            self._conn.execute("DELETE FROM ai_cache")
            self._conn.commit()
        return int(count)

    def size(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM ai_cache").fetchone()[0])

    # ----------------------------------------------------- pemakaian -- #

    def record_usage(self, provider: str, model: str, usage: Usage) -> None:
        """Catat pemakaian kuota, supaya pengguna bisa mengawasi biayanya.

        Tanpa catatan ini, pengguna baru sadar kuotanya habis setelah
        penagihan datang.
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO ai_usage (provider, model, prompt_tokens, "
                "completion_tokens, at) VALUES (?,?,?,?,?)",
                (provider, model, usage.prompt_tokens, usage.completion_tokens, time.time()),
            )
            self._conn.commit()

    def usage_summary(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(prompt_tokens),0), "
                "COALESCE(SUM(completion_tokens),0) FROM ai_usage"
            ).fetchone()
        return {
            "calls": int(row[0]),
            "prompt_tokens": int(row[1]),
            "completion_tokens": int(row[2]),
            "total_tokens": int(row[1]) + int(row[2]),
        }

    def reset_usage(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM ai_usage")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
