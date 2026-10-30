"""Bentuk data bersama dan cara bicara ke model bahasa.

Seluruh program hanya bicara ke model lewat satu pintu: `LlmClient`. Dengan
begitu penyedia mana pun (OpenAI, Anthropic, server lokal) bisa dipakai tanpa
mengubah kode analisis, dan pengujian bisa memakai klien palsu tanpa jaringan.

Pemanggilan HTTP ditulis dengan `urllib` dari pustaka standar, bukan dengan
pustaka tambahan. Alasannya: program ini harus bisa dikompilasi menjadi satu
berkas .exe, dan setiap pustaka tambahan menambah ukuran serta satu titik
kegagalan lagi saat pembungkusan.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

# Batas panjang teks yang dikirim ke model. Tanpa batas ini, folder dengan
# puluhan ribu berkas akan menghasilkan permintaan yang ditolak penyedia karena
# terlalu panjang, dan pengguna hanya melihat pesan error tanpa penjelasan.
MAX_CONTEXT_CHARS = 12000


class LlmError(RuntimeError):
    """Kegagalan yang bisa dijelaskan kepada pengguna.

    Pesan kesalahan dari penyedia AI sering tidak jelas ("400 Bad Request").
    Kelas ini menyimpan keterangan yang bisa ditampilkan apa adanya, beserta
    saran apa yang harus dilakukan.
    """

    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.hint = hint


@dataclass
class Usage:
    """Berapa banyak teks yang dipakai. Berguna untuk mengawasi biaya."""

    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def as_text(self) -> str:
        if not self.total:
            return "tidak dilaporkan penyedia"
        return f"{self.prompt_tokens} masuk + {self.completion_tokens} keluar = {self.total} token"


@dataclass
class LlmReply:
    """Jawaban model beserta keterangan pemakaiannya."""

    text: str
    model: str = ""
    usage: Usage = field(default_factory=Usage)


@dataclass
class FileReport:
    """Ringkasan satu berkas untuk dikirim ke model.

    Sengaja hanya berisi hal-hal yang tidak bersifat pribadi: nama, ukuran,
    hash, dan temuan. Isi berkas tidak ikut kecuali pengguna mengizinkannya
    secara sadar.
    """

    name: str
    size: int
    sha256: str
    extension: str
    findings: list[dict] = field(default_factory=list)
    section_summary: str = ""
    snippet: str = ""


@dataclass
class AnalysisResult:
    """Hasil analisis AI atas satu berkas atau satu folder."""

    verdict: str = "TIDAK DIKETAHUI"
    confidence: str = "rendah"
    explanation: str = ""
    actions: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    from_cache: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.explanation)


def _post_json(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    """Kirim permintaan JSON dan kembalikan jawabannya.

    Kesalahan jaringan dan kesalahan penyedia diubah menjadi LlmError dengan
    keterangan yang bisa dibaca pengguna. Kunci API tidak pernah ikut ke dalam
    pesan kesalahan.
    """
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for name, value in headers.items():
        request.add_header(name, value)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        detail = ""
        try:
            detail = error.read().decode("utf-8", "replace")[:400]
        except Exception:  # noqa: BLE001 - badan kesalahan tidak selalu bisa dibaca
            pass
        hint = ""
        if error.code == 401:
            hint = "Kunci API ditolak. Periksa kembali kuncinya di Pengaturan."
        elif error.code == 429:
            hint = "Permintaan terlalu sering atau kuota habis. Coba lagi nanti."
        elif error.code in (402, 403):
            hint = "Kunci API tidak punya akses ke model ini, atau saldo habis."
        elif error.code == 404:
            hint = "Nama model tidak dikenali penyedia. Periksa nama model di Pengaturan."
        elif error.code >= 500:
            hint = "Server penyedia sedang bermasalah. Coba lagi nanti."
        raise LlmError(f"Penyedia menolak permintaan (HTTP {error.code}). {detail}", hint)
    except urllib.error.URLError as error:
        raise LlmError(
            f"Tidak bisa menghubungi penyedia AI: {error.reason}",
            "Periksa koneksi internet, atau pakai model lokal (Ollama) agar "
            "tidak perlu internet.",
        )
    except TimeoutError:
        raise LlmError(
            f"Penyedia tidak menjawab dalam {timeout:.0f} detik.",
            "Coba lagi, atau pakai model yang lebih kecil/cepat.",
        )

    try:
        return json.loads(raw)
    except ValueError:
        raise LlmError(
            "Jawaban penyedia bukan JSON yang sah.",
            "Biasanya karena alamat API salah. Periksa Pengaturan.",
        )


# --------------------------------------------------------------------------- #
# Penyedia yang didukung
# --------------------------------------------------------------------------- #

# Bentuk permintaan berbeda-beda antar penyedia, jadi setiap penyedia punya
# fungsi sendiri. Menambah penyedia baru = menambah satu fungsi di sini.
PROVIDERS = {
    "openai": {
        "label": "OpenAI (juga untuk server yang meniru API OpenAI)",
        "default_url": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-4o-mini",
        "needs_key": True,
    },
    "anthropic": {
        "label": "Anthropic (Claude)",
        "default_url": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-3-5-haiku-latest",
        "needs_key": True,
    },
    "ollama": {
        "label": "Ollama - model lokal di komputer sendiri (tidak butuh internet)",
        "default_url": "http://localhost:11434/v1/chat/completions",
        "default_model": "llama3.2",
        "needs_key": False,
    },
}


class LlmClient:
    """Pintu tunggal ke model bahasa.

    Contoh pemakaian:

        client = LlmClient(provider="ollama", model="llama3.2")
        print(client.ask("Jelaskan apa itu ransomware."))

    Klien ini tidak menyimpan apa pun ke disk dan tidak menulis log. Kunci API
    hanya hidup di dalam memori selama program berjalan.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "",
        api_key: str = "",
        base_url: str = "",
        timeout: float = 60.0,
        max_tokens: int = 900,
        temperature: float = 0.2,
    ) -> None:
        if provider not in PROVIDERS:
            raise LlmError(
                f"Penyedia '{provider}' tidak dikenal.",
                "Pilih salah satu: " + ", ".join(PROVIDERS),
            )
        self.provider = provider
        info = PROVIDERS[provider]
        self.model = model or info["default_model"]
        self.api_key = api_key
        self.base_url = base_url or info["default_url"]
        self.timeout = timeout
        self.max_tokens = max_tokens
        # Suhu rendah: analisis keamanan butuh jawaban yang stabil dan bisa
        # diulang, bukan jawaban yang berubah-ubah setiap kali dijalankan.
        self.temperature = temperature

    # ---------------------------------------------------------------- sifat -- #

    @property
    def ready(self) -> bool:
        """Apakah klien ini siap dipakai (kunci ada bila memang diperlukan)?"""
        if PROVIDERS[self.provider]["needs_key"]:
            return bool(self.api_key)
        return bool(self.base_url)

    def describe(self) -> str:
        return f"{PROVIDERS[self.provider]['label']} - model {self.model}"

    # ----------------------------------------------------------- pemakaian -- #

    def ask(self, prompt: str, system: str = "") -> LlmReply:
        """Kirim satu pertanyaan dan kembalikan jawabannya."""
        if not self.ready:
            raise LlmError(
                f"Kunci API untuk {PROVIDERS[self.provider]['label']} belum diisi.",
                "Isi di Pengaturan > Kecerdasan Buatan.",
            )
        prompt = prompt[:MAX_CONTEXT_CHARS]
        if self.provider == "anthropic":
            return self._ask_anthropic(prompt, system)
        return self._ask_openai_compatible(prompt, system)

    def _ask_openai_compatible(self, prompt: str, system: str) -> LlmReply:
        """OpenAI, Ollama, dan server lain yang memakai bentuk yang sama.

        Ollama memang menyediakan titik akhir yang cocok dengan API OpenAI, jadi
        satu fungsi ini melayani penyedia lokal maupun awan.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = _post_json(self.base_url, payload, headers, self.timeout)
        return LlmReply(
            text=_extract_openai_text(data),
            model=data.get("model", self.model),
            usage=_extract_openai_usage(data),
        )

    def _ask_anthropic(self, prompt: str, system: str) -> LlmReply:
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        headers = {
            "x-api-key": self.api_key,
            # Wajib diisi Anthropic; tanpa ini permintaan ditolak.
            "anthropic-version": "2023-06-01",
        }

        data = _post_json(self.base_url, payload, headers, self.timeout)
        blocks = data.get("content") or []
        text = "".join(
            block.get("text", "") for block in blocks if isinstance(block, dict)
        )
        raw_usage = data.get("usage") or {}
        return LlmReply(
            text=text,
            model=data.get("model", self.model),
            usage=Usage(
                prompt_tokens=int(raw_usage.get("input_tokens", 0) or 0),
                completion_tokens=int(raw_usage.get("output_tokens", 0) or 0),
            ),
        )


def _extract_openai_text(data: dict) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    content = message.get("content", "")
    # Sebagian penyedia mengirim daftar potongan, bukan teks tunggal.
    if isinstance(content, list):
        return "".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    return content or ""


def _extract_openai_usage(data: dict) -> Usage:
    raw = data.get("usage") or {}
    return Usage(
        prompt_tokens=int(raw.get("prompt_tokens", 0) or 0),
        completion_tokens=int(raw.get("completion_tokens", 0) or 0),
    )


def build_client_from_settings(settings) -> LlmClient:
    """Buat klien dari pengaturan pengguna.

    Kunci API diambil dari variabel lingkungan bila ada, dan itu lebih aman
    daripada menyimpannya di berkas pengaturan. Urutan: variabel lingkungan
    lebih diutamakan.
    """
    provider = getattr(settings, "ai_provider", "openai")
    env_names = {
        "openai": ("SCANGUARD_AI_KEY", "OPENAI_API_KEY"),
        "anthropic": ("SCANGUARD_AI_KEY", "ANTHROPIC_API_KEY"),
        "ollama": ("SCANGUARD_AI_KEY",),
    }
    key = ""
    for name in env_names.get(provider, ("SCANGUARD_AI_KEY",)):
        key = os.environ.get(name, "")
        if key:
            break
    if not key:
        key = getattr(settings, "ai_api_key", "") or ""

    return LlmClient(
        provider=provider,
        model=getattr(settings, "ai_model", "") or "",
        api_key=key,
        base_url=getattr(settings, "ai_base_url", "") or "",
        timeout=float(getattr(settings, "ai_timeout", 60.0) or 60.0),
    )
