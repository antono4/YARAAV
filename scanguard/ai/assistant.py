"""Asisten tanya-jawab tentang hasil pemindaian.

Asisten ini punya dua lapis, dan itu disengaja:

1. **Pengetahuan bawaan (selalu bekerja).** Pertanyaan yang sering diajukan
   dijawab langsung dari penjelasan yang ditulis di dalam program. Tidak butuh
   internet, tidak butuh kunci API, dan jawabannya pasti benar karena tidak
   dikarang oleh model.
2. **Model bahasa (bila diaktifkan).** Pertanyaan bebas yang tidak ada di
   pengetahuan bawaan dikirim ke model, bersama ringkasan hasil pemindaian.

Alasannya sederhana: fitur AI yang hanya bekerja setelah pengguna mendaftar dan
membayar kunci API jarang dipakai. Dengan dua lapis, asisten ini berguna sejak
detik pertama program dibuka.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .analyst import AiAnalyst
from .base import AnalysisResult, LlmError

# Pengetahuan bawaan: daftar kata kunci dan jawabannya.
#
# Ditulis dalam bahasa Indonesia sederhana, tanpa istilah teknis yang tidak
# dijelaskan. Ini bukan tempat menaruh nasihat keamanan yang bisa berubah -
# hanya penjelasan tentang cara kerja program ini.
KNOWLEDGE: list[tuple[tuple[str, ...], str]] = [
    (
        ("eicar", "berkas uji", "test file"),
        "EICAR adalah berkas uji standar industri antivirus. Isinya bukan malware "
        "sungguhan - berkas itu sengaja dibuat supaya antivirus punya sesuatu yang "
        "aman untuk diuji. Kalau ScanGuard menandainya sebagai MALWARE, itu berarti "
        "pemindaiannya bekerja dengan benar. Berkas ini hanya muncul di komputer "
        "Anda kalau Anda sendiri yang membuatnya, misalnya saat menguji program ini.",
    ),
    (
        ("positif palsu", "false positive", "salah tuduh"),
        "Positif palsu berarti program yang sah ditandai sebagai berbahaya. Ini bisa "
        "terjadi karena beberapa sebab: program itu memang memakai cara kerja yang "
        "mirip malware (misalnya memuat dirinya sendiri agar kecil), atau ada "
        "petunjuk lemah yang kebetulan terkumpul. Yang perlu dilakukan: periksa "
        "tingkat temuannya. Tingkat PERLU DIPERIKSA biasanya paling sering keliru, "
        "karena itu sengaja dibuat paling ringan. Kalau Anda yakin berkas itu aman "
        "dan Anda tahu asalnya, berkas itu tidak perlu dikarantina.",
    ),
    (
        ("karantina", "quarantine"),
        "Karantina memindahkan berkas dari tempat asalnya ke folder aman, dan "
        "mengacak isinya sehingga tidak bisa dijalankan lagi. Berkas asli tetap "
        "tersimpan utuh di dalam karantina, jadi bisa dipulihkan persis seperti "
        "semula kapan saja. Ini sengaja dibuat begitu: kalau ternyata salah tuduh, "
        "Anda tidak kehilangan berkasnya.",
    ),
    (
        ("hash", "sha-256", "sha256", "sidik jari"),
        "Hash adalah sidik jari berkas: deretan huruf dan angka yang dihitung dari "
        "isinya. Berkas yang isinya sama persis selalu menghasilkan hash yang sama, "
        "dan mengubah satu huruf saja mengubah hash-nya sepenuhnya. ScanGuard "
        "membandingkan hash berkas dengan daftar hash malware yang sudah "
        "dikonfirmasi. Ini cara deteksi paling pasti - tetapi hanya mengenali "
        "malware yang sudah pernah tercatat.",
    ),
    (
        ("yara", "aturan", "pola"),
        "YARA adalah cara mencocokkan isi berkas dengan pola yang sudah ditulis. "
        "Misalnya pola perintah untuk menghapus cadangan sistem, atau PowerShell "
        "yang dijalankan tersembunyi. Cara ini bisa mengenali keluarga malware baru "
        "yang mirip dengan yang lama, walaupun hash-nya berbeda. Kelemahannya: "
        "malware yang benar-benar berbeda dari pola yang ditulis tidak akan "
        "dikenali.",
    ),
    (
        ("analisis pe", "pefile", "struktur program", "impor"),
        "Program Windows disimpan dalam bentuk yang disebut PE. ScanGuard membaca "
        "strukturnya: fungsi Windows apa saja yang dipanggil program itu, apakah ada "
        "bagian yang bisa ditulis sekaligus dijalankan, dan apakah isinya terlihat "
        "sudah dipadatkan. Fungsi seperti menyuntikkan kode ke program lain adalah "
        "petunjuk kuat, tetapi banyak program sah juga memakainya - karena itu "
        "penilaiannya digabung dari beberapa petunjuk, tidak dari satu saja.",
    ),
    (
        ("clamav", "clamscan", "tanda tangan"),
        "ClamAV adalah antivirus sumber terbuka dengan basis data tanda tangan virus "
        "yang besar. ScanGuard memakainya bila ClamAV terpasang di komputer Anda. "
        "Tanpa ClamAV, mesin lain tetap bekerja - hanya deteksinya berkurang.",
    ),
    (
        ("anomali", "menyimpang", "ai", "mencurigakan", "ditandai", "kenapa"),
        "Deteksi anomali adalah bagian AI yang bekerja tanpa internet. Modelnya "
        "belajar dari berkas-berkas di folder yang sedang Anda pindai, lalu mencari "
        "berkas yang paling berbeda dari yang lain. Cara ini bisa menyorot malware "
        "baru yang belum ada di basis data mana pun. Tetapi hasilnya selalu hanya "
        "PERLU DIPERIKSA, karena berbeda bukan berarti berbahaya - berkas cadangan "
        "atau basis data sering terlihat menyimpang padahal wajar.",
    ),
    (
        ("aman", "pasti bersih", "tidak ada temuan", "bersih", "dipercaya", "percaya", "akurat", "yakin"),
        "Tidak ada temuan bukan berarti berkas pasti aman. Semua mesin di ScanGuard "
        "mengenali apa yang sudah diketahui: hash yang tercatat, pola yang sudah "
        "ditulis, tanda tangan yang sudah dibuat. Malware yang baru dibuat atau "
        "diubah sedikit tidak akan dikenali. Karena itu tetap gunakan Windows "
        "Defender atau antivirus resmi sebagai pertahanan utama.",
    ),
    (
        ("update", "perbarui", "pembaruan", "basis data", "malwarebazaar"),
        "Basis data hash perlu diperbarui supaya mesin hash berguna. Buka tombol "
        "Perbarui Basis Data. Ada tiga cara: mengambil langsung dari MalwareBazaar "
        "(butuh Auth-Key gratis dari auth.abuse.ch), mengimpor berkas CSV atau TXT, "
        "atau mengunduh dari alamat URL. Dua cara terakhir tidak butuh kunci.",
    ),
    (
        ("kunci api", "api key", "biaya", "kuota", "token"),
        "Fitur AI memakai kunci API yang Anda isi sendiri, dan pemakaiannya "
        "ditagih ke akun Anda. Agar tidak boros, ScanGuard menyimpan hasil analisis "
        "berkas di cache berdasarkan hash - bertanya ulang tentang berkas yang sama "
        "tidak memanggil model lagi. Pemakaian kuota bisa Anda lihat di jendela "
        "Asisten AI. Kalau tidak ingin memakai layanan berbayar sama sekali, pasang "
        "Ollama: modelnya berjalan di komputer Anda sendiri, gratis dan tanpa "
        "internet.",
    ),
    (
        ("ollama", "lokal", "offline", "tanpa internet"),
        "Ollama menjalankan model bahasa langsung di komputer Anda. Tidak ada data "
        "yang keluar dari komputer, dan tidak ada biaya. Pasang dari ollama.com, "
        "lalu jalankan perintah seperti 'ollama pull llama3.2'. Sesudah itu pilih "
        "'Ollama' sebagai penyedia di Pengaturan dan biarkan alamatnya apa adanya.",
    ),
    (
        ("privasi", "data keluar", "unggah", "kirim", "dikirim", "internet", "online"),
        "ScanGuard tidak mengunggah isi berkas Anda. Untuk fitur AI, yang dikirim ke "
        "model hanya ringkasan: nama berkas, ukuran, hash, dan jenis temuan. Nama "
        "pengguna Windows, alamat email, nomor telepon, dan alamat IP diganti lebih "
        "dulu. Isi berkas hanya ikut bila Anda sendiri menyalakan pilihan itu di "
        "Pengaturan. Kalau Anda ingin tidak ada data yang keluar sama sekali, pakai "
        "Ollama.",
    ),
    (
        ("lambat", "lama", "berat", "cepat"),
        "Pemindaian bisa terasa lambat karena beberapa sebab. ClamAV memerlukan "
        "waktu sekitar tujuh detik hanya untuk memuat basis datanya, dan itu "
        "terjadi sekali per pemindaian. Berkas besar memerlukan waktu untuk dihitung "
        "hash-nya. Kabar baiknya: hasil pemindaian disimpan, jadi pemindaian kedua "
        "atas folder yang sama hampir seketika - hanya berkas yang berubah yang "
        "diperiksa ulang.",
    ),
    (
        ("heuristik", "skor", "nilai"),
        "Skor heuristik adalah nilai dugaan yang dihitung dari beberapa petunjuk "
        "sekaligus, misalnya fungsi Windows yang dipanggil dan ciri bagian dalam "
        "program. Satu petunjuk lemah tidak cukup untuk menuduh. Bukti kuat seperti "
        "daftar fungsi penyuntik kode ditambah bagian yang sudah dipadatkan akan "
        "menaikkan skornya. Skor 60 ke atas dianggap MALWARE.",
    ),
]

# Pertanyaan yang terlalu pendek atau hanya sapaan tidak perlu dikirim ke model.
_MIN_QUESTION_LENGTH = 3


@dataclass
class Answer:
    """Jawaban asisten, beserta asalnya."""

    text: str
    source: str  # "bawaan" atau nama penyedia AI
    from_cache: bool = False
    usage_note: str = ""


def _normalise(text: str) -> str:
    """Ubah teks menjadi bentuk sederhana untuk dicocokkan."""
    return re.sub(r"[^a-z0-9\s-]", " ", text.lower())


# Kata kunci harus cocok sebagai kata utuh, bukan sebagai potongan kata.
# Tanpa batas kata, kata kunci pendek seperti "ai" cocok di dalam "ditandai",
# "bagaimana", dan "saya" - sehingga pertanyaan yang sama sekali tidak
# berkaitan dijawab dengan topik yang salah.
_WORD_CACHE: dict[str, "re.Pattern[str]"] = {}


def _keyword_pattern(keyword: str) -> "re.Pattern[str]":
    """Pola pencocokan untuk satu kata kunci, dengan batas kata di kedua sisi."""
    pattern = _WORD_CACHE.get(keyword)
    if pattern is None:
        # "\b" tidak berfungsi baik di sebelah tanda hubung (mis. "sha-256"),
        # jadi batasnya ditulis manual: sebelum kata kunci harus awal teks atau
        # bukan huruf/angka, dan sesudahnya juga demikian.
        pattern = re.compile(r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])")
        _WORD_CACHE[keyword] = pattern
    return pattern


def answer_from_knowledge(question: str) -> Answer | None:
    """Cari jawaban di pengetahuan bawaan.

    Pencocokan memilih entri dengan kata kunci paling banyak muncul, bukan yang
    pertama ditemukan. Tanpa itu, pertanyaan "apa itu karantina dan apakah
    berkasnya hilang" akan terjawab hanya oleh entri pertama yang cocok.
    """
    normalised = _normalise(question)
    if len(normalised.strip()) < _MIN_QUESTION_LENGTH:
        return None

    best: tuple[int, str] | None = None
    for keywords, answer in KNOWLEDGE:
        score = 0
        for keyword in keywords:
            if _keyword_pattern(keyword).search(normalised):
                # Kata kunci yang lebih panjang lebih khusus, jadi diberi bobot
                # lebih besar daripada kata umum yang pendek.
                score += len(keyword)
        if score and (best is None or score > best[0]):
            best = (score, answer)
    if best is None:
        return None
    return Answer(text=best[1], source="bawaan")


class Assistant:
    """Asisten tanya-jawab: pengetahuan bawaan dulu, model bahasa bila perlu."""

    def __init__(self, analyst: AiAnalyst | None = None) -> None:
        self.analyst = analyst

    @property
    def ai_ready(self) -> bool:
        return bool(
            self.analyst
            and self.analyst.client.ready
        )

    def ask(self, question: str, summary=None, force_ai: bool = False) -> Answer:
        """Jawab satu pertanyaan.

        `force_ai=True` memaksa memakai model, dipakai saat pengguna menekan
        tombol "Tanya AI" secara sadar walaupun pertanyaannya ada di pengetahuan
        bawaan.
        """
        question = (question or "").strip()
        if len(question) < _MIN_QUESTION_LENGTH:
            return Answer(
                text="Tulis pertanyaannya lebih lengkap dulu, ya. Contoh: "
                "\"apa itu karantina?\" atau \"kenapa berkas ini ditandai?\"",
                source="bawaan",
            )

        if not force_ai:
            builtin = answer_from_knowledge(question)
            if builtin is not None:
                return builtin

        if not self.ai_ready:
            return Answer(
                text=(
                    "Pertanyaan itu tidak ada di penjelasan bawaan program, dan "
                    "fitur AI belum diaktifkan.\n\n"
                    "Untuk mengaktifkannya, buka Pengaturan lalu isi bagian "
                    "Kecerdasan Buatan. Kalau tidak ingin memakai layanan "
                    "berbayar, pasang Ollama (ollama.com) agar model berjalan di "
                    "komputer Anda sendiri."
                ),
                source="bawaan",
            )

        if summary is None:
            return Answer(
                text=(
                    "Belum ada hasil pemindaian untuk dijadikan bahan. Jalankan "
                    "pemindaian lebih dulu, lalu tanyakan lagi."
                ),
                source="bawaan",
            )

        try:
            result = self.analyst.answer_question(summary, question)
        except LlmError as error:
            message = str(error)
            if error.hint:
                message += "\n\n" + error.hint
            return Answer(text=message, source="bawaan")

        note = ""
        if result.usage.total:
            note = f"Pemakaian: {result.usage.as_text()}"
        return Answer(
            text=result.explanation,
            source=result.model or "AI",
            usage_note=note,
        )


def suggested_questions() -> list[str]:
    """Pertanyaan contoh untuk ditampilkan di antarmuka.

    Ditampilkan sebagai tombol supaya pengguna tidak perlu menebak apa yang bisa
    ditanyakan. Kotak tanya-jawab yang kosong jarang dipakai orang.
    """
    return [
        "Apa itu karantina dan apakah berkasnya hilang?",
        "Kenapa berkas saya ditandai mencurigakan?",
        "Apa itu EICAR?",
        "Apakah hasil pemindaian ini bisa dipercaya?",
        "Bagaimana cara memperbarui basis data?",
        "Apakah data saya dikirim ke internet?",
    ]
