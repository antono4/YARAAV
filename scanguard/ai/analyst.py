"""Penjelasan temuan dengan model bahasa.

Dipakai untuk menjawab pertanyaan yang tidak bisa dijawab aturan tetap:
"Kenapa berkas ini ditandai?", "Apakah temuan ini berbahaya sungguhan?", dan
"Apa yang sebaiknya saya lakukan?"

**Batas kewenangan AI di sini, dan alasannya.** Model bahasa bisa salah dengan
sangat percaya diri. Kalau AI diizinkan menentukan tingkat bahaya, pengguna akan
menerima tuduhan yang tidak bisa diperiksa ulang - dan itu lebih buruk daripada
tidak ada tuduhan sama sekali. Karena itu:

* Tingkat MALWARE / MENCURIGAKAN / PERLU DIPERIKSA hanya datang dari mesin
  deteksi yang hasilnya bisa diperiksa (hash cocok, aturan YARA, struktur PE,
  tanda tangan ClamAV).
* AI memberi `penilaian` ("kemungkinan positif palsu", "perlu diperiksa") yang
  bersifat keterangan. Penilaian itu tidak pernah mengubah tingkat temuan.

Hasilnya disimpan di cache berdasarkan hash berkas, sehingga bertanya ulang
tidak memakai kuota API lagi.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .base import AnalysisResult, FileReport, LlmClient, LlmError, Usage
from .cache import AiCache
from .privacy import build_context, build_file_context

# Peran yang diberikan ke model. Ditulis tegas supaya model tidak "menghakimi"
# berkas dan tidak menjanjikan kepastian yang tidak dimilikinya.
SYSTEM_PROMPT = """Anda membantu pengguna memahami hasil pemindaian malware.

Aturan yang wajib Anda pegang:
1. Anda TIDAK menentukan tingkat bahaya. Tingkat MALWARE, MENCURIGAKAN, dan
   PERLU DIPERIKSA sudah ditentukan oleh mesin pemindai (pencocokan hash,
   aturan YARA, analisis struktur program, tanda tangan antivirus). Jangan
   mengubahnya dan jangan mengarang tingkat baru.
2. Anda tidak bisa memastikan sebuah berkas aman. Jangan pernah menulis
   "berkas ini pasti aman".
3. Kalau buktinya lemah, katakan lemah. Jangan mengarang bukti.
4. Jawab dalam bahasa Indonesia, singkat dan jelas, untuk pengguna yang tidak
   paham istilah teknis. Istilah teknis yang terpaksa dipakai harus dijelaskan
   dengan kalimat pendek.
5. Selalu kembalikan jawaban sebagai JSON dengan bentuk yang diminta. Jangan
   menambahkan penjelasan di luar JSON."""

# Bentuk jawaban yang diminta dari model.
_JSON_SPEC = """Kembalikan JSON dengan bentuk persis seperti ini:
{
  "penilaian": "salah satu: kemungkinan positif palsu | perlu diperiksa | kemungkinan berbahaya | tidak dapat ditentukan",
  "keyakinan": "salah satu: rendah | sedang | tinggi",
  "penjelasan": "2 sampai 4 kalimat bahasa Indonesia yang menjelaskan temuan ini",
  "tindakan": ["langkah praktis pertama", "langkah kedua"],
  "catatan": ["hal teknis yang membuat Anda menilai demikian"]
}"""


@dataclass
class AnalisisBerkas:
    """Hasil analisis satu berkas, beserta keterangan pemakaian kuota."""

    result: AnalysisResult
    file_hash: str = ""


def _extract_json(text: str) -> dict:
    """Ambil objek JSON dari jawaban model.

    Model sering membungkus JSON dengan penanda markdown (```json ... ```) atau
    menambahkan kalimat pembuka, walaupun sudah diminta tidak. Penguraian yang
    kaku akan gagal pada jawaban yang sebenarnya benar.
    """
    if not text:
        return {}

    # Buang penanda blok kode bila ada.
    fenced = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)

    try:
        return json.loads(text)
    except ValueError:
        pass

    # Cari objek JSON pertama yang seimbang kurungnya.
    start = text.find("{")
    if start == -1:
        return {}
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : index + 1])
                except ValueError:
                    return {}
    return {}


def _to_list(value) -> list[str]:
    """Ubah apa pun menjadi daftar teks yang aman ditampilkan."""
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [line.strip(" -•\t") for line in value.splitlines() if line.strip()]
    return []


def _to_result(data: dict, reply) -> AnalysisResult:
    return AnalysisResult(
        verdict=str(data.get("penilaian", "tidak dapat ditentukan")),
        confidence=str(data.get("keyakinan", "rendah")),
        explanation=str(data.get("penjelasan", "")).strip(),
        actions=_to_list(data.get("tindakan")),
        flags=_to_list(data.get("catatan")),
        model=reply.model,
        usage=reply.usage,
    )


class AiAnalyst:
    """Menjelaskan temuan dengan model bahasa, dengan cache agar hemat kuota."""

    def __init__(self, client: LlmClient, cache: AiCache | None = None) -> None:
        self.client = client
        self.cache = cache if cache is not None else AiCache()

    # ------------------------------------------------------ satu berkas -- #

    def explain_file(
        self,
        report: FileReport,
        use_cache: bool = True,
    ) -> AnalisisBerkas:
        """Jelaskan satu berkas dan temuannya."""
        cache_key = f"berkas:{report.sha256}:{report.extension}"
        if use_cache:
            cached = self.cache.get(cache_key, self.client.provider, self.client.model)
            if cached is not None:
                cached.from_cache = True
                return AnalisisBerkas(result=cached, file_hash=report.sha256)

        prompt = (
            build_file_context(report)
            + "\n\n"
            + _JSON_SPEC
            + "\n\nTulis penjelasan untuk pengguna biasa. Sebutkan kalau buktinya "
            "lemah, dan jangan menyimpulkan lebih jauh daripada bukti yang ada."
        )
        reply = self.client.ask(prompt, system=SYSTEM_PROMPT)
        result = _to_result(_extract_json(reply.text), reply)

        if not result.explanation:
            # Model menjawab dengan teks biasa, bukan JSON. Jawabannya masih
            # berguna bagi pengguna, jadi tetap ditampilkan apa adanya daripada
            # dibuang karena bentuknya tidak sesuai.
            result = AnalysisResult(
                verdict="tidak dapat ditentukan",
                confidence="rendah",
                explanation=reply.text.strip()[:2000],
                model=reply.model,
                usage=reply.usage,
            )

        if use_cache and result.ok:
            self.cache.put(cache_key, self.client.provider, self.client.model, result)
        return AnalisisBerkas(result=result, file_hash=report.sha256)

    # --------------------------------------------------------- folder -- #

    def explain_scan(self, summary, use_cache: bool = False) -> AnalysisResult:
        """Beri gambaran menyeluruh atas satu kali pemindaian.

        Hasilnya tidak di-cache: setiap pemindaian punya isi berbeda, jadi
        kuncinya tidak bisa dipakai ulang.
        """
        prompt = (
            build_context(summary)
            + "\n\n"
            + _JSON_SPEC
            + "\n\nIni hasil satu kali pemindaian folder. Jelaskan gambaran "
            "umumnya: apa yang paling perlu diperhatikan lebih dulu, dan apa "
            "yang bisa diabaikan. Sebutkan juga kalau tidak ada temuan berarti "
            "tidak menjamin berkas aman."
        )
        reply = self.client.ask(prompt, system=SYSTEM_PROMPT)
        result = _to_result(_extract_json(reply.text), reply)
        if not result.explanation:
            result = AnalysisResult(
                verdict="tidak dapat ditentukan",
                explanation=reply.text.strip()[:2000],
                model=reply.model,
                usage=reply.usage,
            )
        return result

    def answer_question(self, summary, question: str) -> AnalysisResult:
        """Jawab pertanyaan bebas pengguna tentang hasil pemindaian."""
        prompt = (
            build_context(summary, max_files=25)
            + "\n\nPERTANYAAN PENGGUNA:\n"
            + question
            + "\n\nJawab pertanyaan itu berdasarkan ringkasan di atas. Kalau "
            "ringkasannya tidak memuat informasi yang dibutuhkan, katakan terus "
            "terang bahwa informasinya tidak ada, jangan mengarang."
        )
        reply = self.client.ask(prompt, system=SYSTEM_PROMPT)
        return AnalysisResult(
            verdict="jawaban",
            explanation=reply.text.strip()[:4000],
            model=reply.model,
            usage=reply.usage,
        )


def check_connection(client: LlmClient) -> tuple[bool, str]:
    """Uji apakah pengaturan AI benar-benar bisa dipakai.

    Pengguna perlu cara memastikan pengaturannya benar sebelum menekan tombol
    analisis. Tanpa ini, kesalahan kunci API baru terlihat setelah pemindaian
    panjang selesai.
    """
    if not client.ready:
        return False, (
            "Kunci API belum diisi. Isi di Pengaturan, atau pakai Ollama untuk "
            "model lokal yang tidak butuh kunci."
        )
    try:
        reply = client.ask(
            "Balas dengan satu kata: SIAP",
            system="Balas sangat singkat.",
        )
    except LlmError as error:
        message = str(error)
        if error.hint:
            message += " " + error.hint
        return False, message
    except Exception as error:  # noqa: BLE001 - kesalahan apa pun harus terlihat
        return False, f"Gagal menghubungi penyedia AI: {error}"

    text = (reply.text or "").strip()
    if not text:
        return False, "Penyedia menjawab, tetapi jawabannya kosong."
    return True, f"Terhubung. Jawaban uji: {text[:60]}"
