"""Pengujian bagian kecerdasan buatan.

Seluruh pengujian di sini berjalan tanpa internet dan tanpa kunci API. Model
bahasa diganti dengan klien palsu yang mengembalikan jawaban yang sudah
disiapkan, sedangkan model anomali diuji sungguhan karena ia memang berjalan
lokal dan hasilnya pasti.

Yang paling penting untuk diuji di sini bukan "apakah jawabannya bagus" -
kualitas jawaban model bukan sesuatu yang bisa diuji secara otomatis. Yang
diuji adalah **janji-janji yang dibuat program ini**:

* AI tidak boleh mengubah tingkat bahaya temuan.
* Data pribadi tidak boleh ikut terkirim.
* Hasil lama tidak boleh dipakai untuk model yang berbeda.
* Program harus tetap bekerja saat AI mati atau gagal.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanguard.ai.analyst import AiAnalyst, _extract_json, check_connection
from scanguard.ai.anomaly import (
    MIN_FILES,
    anomalies_to_findings,
    extract_features,
    find_anomalies,
)
from scanguard.ai.assistant import (
    Assistant,
    answer_from_knowledge,
    suggested_questions,
)
from scanguard.ai.base import (
    PROVIDERS,
    AnalysisResult,
    FileReport,
    LlmClient,
    LlmError,
    LlmReply,
    Usage,
    build_client_from_settings,
)
from scanguard.ai.cache import AiCache
from scanguard.ai.privacy import (
    build_context,
    build_file_context,
    detect_personal_data,
    redact_text,
    summarise_findings,
)
from scanguard.config import SEV_MALWARE, SEV_NOTE, SEV_SUSPICIOUS
from scanguard.core import Finding, ScanSummary
from scanguard.settings import Settings


class FakeClient(LlmClient):
    """Klien palsu: menjawab dengan teks yang sudah disiapkan.

    Mencatat setiap prompt yang diterima, sehingga pengujian bisa memeriksa apa
    yang sebenarnya akan terkirim ke penyedia AI.
    """

    def __init__(self, text: str = "{}", provider: str = "openai", api_key: str = "uji"):
        super().__init__(provider=provider, api_key=api_key, timeout=5.0)
        self._text = text
        self.prompts: list[str] = []

    def ask(self, prompt: str, system: str = "") -> LlmReply:
        self.prompts.append(prompt)
        return LlmReply(text=self._text, model=self.model, usage=Usage(100, 40))

    @property
    def calls(self) -> int:
        return len(self.prompts)


class FailingClient(FakeClient):
    def ask(self, prompt: str, system: str = "") -> LlmReply:
        self.prompts.append(prompt)
        raise LlmError("Penyedia menolak permintaan (HTTP 401).", "Kunci API ditolak.")


# --------------------------------------------------------------------------- #
# 1. Penguraian jawaban model
# --------------------------------------------------------------------------- #


class TestJsonExtraction(unittest.TestCase):
    """Model sering membungkus JSON dengan cara yang tidak diminta.

    Penguraian yang kaku akan menolak jawaban yang sebenarnya benar, dan
    pengguna hanya melihat pesan "gagal" padahal modelnya menjawab dengan baik.
    """

    def test_clean_json(self) -> None:
        hasil = _extract_json('{"penjelasan": "halo"}')
        self.assertEqual(hasil["penjelasan"], "halo")

    def test_markdown_fenced(self) -> None:
        hasil = _extract_json('```json\n{"penjelasan": "halo"}\n```')
        self.assertEqual(hasil["penjelasan"], "halo")

    def test_fenced_without_language(self) -> None:
        hasil = _extract_json('```\n{"penjelasan": "halo"}\n```')
        self.assertEqual(hasil["penjelasan"], "halo")

    def test_prose_around_json(self) -> None:
        hasil = _extract_json('Tentu, ini hasilnya:\n{"penjelasan": "halo"}\nSemoga membantu.')
        self.assertEqual(hasil["penjelasan"], "halo")

    def test_nested_object(self) -> None:
        hasil = _extract_json('{"a": {"b": 1}, "penjelasan": "x"}')
        self.assertEqual(hasil["a"]["b"], 1)

    def test_brace_inside_string_does_not_confuse(self) -> None:
        """Kurung di dalam teks tidak boleh dihitung sebagai struktur JSON."""
        hasil = _extract_json('{"penjelasan": "pakai { dan } di teks"}')
        self.assertEqual(hasil["penjelasan"], "pakai { dan } di teks")

    def test_plain_prose_returns_empty(self) -> None:
        self.assertEqual(_extract_json("ini bukan json"), {})

    def test_empty_returns_empty(self) -> None:
        self.assertEqual(_extract_json(""), {})


# --------------------------------------------------------------------------- #
# 2. Penyamaran data pribadi
# --------------------------------------------------------------------------- #


class TestPrivacy(unittest.TestCase):
    """Data pribadi tidak boleh ikut terkirim ke penyedia AI."""

    def test_email_is_redacted(self) -> None:
        self.assertNotIn("budi@mail.com", redact_text("kirim ke budi@mail.com"))

    def test_windows_username_is_redacted(self) -> None:
        hasil = redact_text(r"berkas di C:\Users\Budi\Dokumen\rahasia.txt")
        self.assertNotIn("Budi", hasil)
        self.assertIn("<pengguna>", hasil)

    def test_linux_username_is_redacted(self) -> None:
        hasil = redact_text("/home/siti/proyek/berkas.py")
        self.assertNotIn("siti", hasil)

    def test_ip_address_is_redacted(self) -> None:
        self.assertNotIn("192.168.1.7", redact_text("hubungi 192.168.1.7"))

    def test_phone_number_is_redacted(self) -> None:
        self.assertNotIn("081234567890", redact_text("telepon 081234567890"))

    def test_ordinary_text_is_untouched(self) -> None:
        asli = "Berkas ini berukuran 1024 byte dan berisi teks biasa."
        self.assertEqual(redact_text(asli), asli)

    def test_detect_reports_what_was_found(self) -> None:
        jenis = detect_personal_data("email budi@mail.com dari 10.0.0.1")
        self.assertIn("alamat email", jenis)
        self.assertIn("alamat IP", jenis)

    def test_file_context_redacts_findings_detail(self) -> None:
        """BUG YANG PERNAH TERJADI: hanya nama berkas yang disamarkan.

        Detail temuan bisa memuat path lengkap dan alamat email - misalnya
        "ditemukan di C:\\Users\\Budi\\... dan dikirim ke budi@mail.com".
        Menyamarkan sebagian saja membuat data pengguna tetap terkirim.
        """
        report = FileReport(
            name="a.txt",
            size=10,
            sha256="x" * 64,
            extension=".txt",
            findings=[
                {
                    "severity": SEV_SUSPICIOUS,
                    "engine": "YARA",
                    "rule": "R",
                    "detail": r"ditemukan di C:\Users\Budi\rahasia, kirim ke budi@mail.com",
                }
            ],
        )
        teks = build_file_context(report)
        self.assertNotIn("budi@mail.com", teks)
        self.assertNotIn("Budi", teks)
        self.assertIn("<pengguna>", teks)

    def test_scan_context_redacts_root_path(self) -> None:
        summary = ScanSummary(root=r"C:\Users\Budi\Unduhan")
        self.assertNotIn("Budi", build_context(summary))


# --------------------------------------------------------------------------- #
# 3. Klien model
# --------------------------------------------------------------------------- #


class TestLlmClient(unittest.TestCase):
    def test_unknown_provider_is_rejected_with_hint(self) -> None:
        """Pesan kesalahan harus menyebutkan pilihan yang tersedia.

        "Penyedia tidak dikenal" saja tidak memberi tahu pengguna apa yang harus
        diisi, jadi daftar pilihannya ikut disertakan di keterangan tambahan.
        """
        with self.assertRaises(LlmError) as ctx:
            LlmClient(provider="tidak-ada")
        self.assertIn("tidak-ada", str(ctx.exception))
        self.assertIn("openai", ctx.exception.hint)

    def test_provider_without_key_is_not_ready(self) -> None:
        self.assertFalse(LlmClient(provider="openai", api_key="").ready)

    def test_provider_with_key_is_ready(self) -> None:
        self.assertTrue(LlmClient(provider="openai", api_key="abc").ready)

    def test_ollama_needs_no_key(self) -> None:
        """Model lokal tidak boleh menuntut kunci API.

        Kalau menuntut, satu-satunya cara memakai AI tanpa biaya menjadi tidak
        mungkin.
        """
        self.assertFalse(PROVIDERS["ollama"]["needs_key"])
        self.assertTrue(LlmClient(provider="ollama").ready)

    def test_default_model_used_when_empty(self) -> None:
        client = LlmClient(provider="openai", model="")
        self.assertEqual(client.model, PROVIDERS["openai"]["default_model"])

    def test_ask_without_key_raises_explained_error(self) -> None:
        client = LlmClient(provider="openai", api_key="")
        with self.assertRaises(LlmError) as ctx:
            client.ask("halo")
        self.assertIn("Kunci API", str(ctx.exception))

    def test_client_from_settings_uses_environment_key(self) -> None:
        """Kunci dari variabel lingkungan lebih diutamakan daripada di berkas.

        Kunci yang tidak tersimpan di disk lebih aman.
        """
        settings = Settings(ai_provider="openai", ai_api_key="dari-berkas")
        with mock.patch.dict(os.environ, {"SCANGUARD_AI_KEY": "dari-lingkungan"}):
            client = build_client_from_settings(settings)
        self.assertEqual(client.api_key, "dari-lingkungan")

    def test_client_from_settings_falls_back_to_file(self) -> None:
        settings = Settings(ai_provider="openai", ai_api_key="dari-berkas")
        with mock.patch.dict(os.environ, {}, clear=True):
            client = build_client_from_settings(settings)
        self.assertEqual(client.api_key, "dari-berkas")

    def test_error_message_never_contains_the_key(self) -> None:
        """Kunci API tidak boleh muncul di pesan kesalahan.

        Pesan kesalahan ditampilkan di layar dan bisa ikut tersalin ke laporan
        atau tangkapan layar.
        """
        rahasia = "kunci-sangat-rahasia-12345"
        client = LlmClient(provider="openai", api_key=rahasia)
        with mock.patch(
            "scanguard.ai.base._post_json",
            side_effect=LlmError("Penyedia menolak permintaan (HTTP 401)."),
        ):
            with self.assertRaises(LlmError) as ctx:
                client.ask("halo")
        self.assertNotIn(rahasia, str(ctx.exception))

    def test_anthropic_requires_version_header(self) -> None:
        """Anthropic menolak permintaan tanpa header versi.

        Kesalahan ini mudah terjadi dan pesan dari penyedia tidak menjelaskan
        penyebabnya, jadi bentuk permintaannya diuji langsung.
        """
        terkirim: dict = {}

        def fake_post(url, payload, headers, timeout):
            terkirim.update(headers)
            return {"content": [{"text": "ok"}], "usage": {}}

        client = LlmClient(provider="anthropic", api_key="k")
        with mock.patch("scanguard.ai.base._post_json", side_effect=fake_post):
            client.ask("halo")
        self.assertIn("anthropic-version", terkirim)
        self.assertIn("x-api-key", terkirim)

    def test_openai_payload_shape(self) -> None:
        terkirim: dict = {}

        def fake_post(url, payload, headers, timeout):
            terkirim.update(payload)
            return {"choices": [{"message": {"content": "ok"}}], "usage": {}}

        client = LlmClient(provider="openai", api_key="k")
        with mock.patch("scanguard.ai.base._post_json", side_effect=fake_post):
            client.ask("halo", system="sistem")
        self.assertEqual(terkirim["messages"][0]["role"], "system")
        self.assertEqual(terkirim["messages"][1]["content"], "halo")

    def test_usage_extracted_from_reply(self) -> None:
        def fake_post(url, payload, headers, timeout):
            return {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 12},
            }

        client = LlmClient(provider="openai", api_key="k")
        with mock.patch("scanguard.ai.base._post_json", side_effect=fake_post):
            reply = client.ask("halo")
        self.assertEqual(reply.usage.total, 42)

    def test_long_prompt_is_truncated(self) -> None:
        """Prompt raksasa ditolak penyedia, dan pengguna hanya melihat error.

        Memotongnya lebih awal lebih baik daripada gagal setelah menunggu.
        """
        terkirim: dict = {}

        def fake_post(url, payload, headers, timeout):
            terkirim.update(payload)
            return {"choices": [{"message": {"content": "ok"}}], "usage": {}}

        client = LlmClient(provider="openai", api_key="k")
        with mock.patch("scanguard.ai.base._post_json", side_effect=fake_post):
            client.ask("x" * 50000)
        self.assertLessEqual(len(terkirim["messages"][-1]["content"]), 12000)


# --------------------------------------------------------------------------- #
# 4. Cache hasil analisis
# --------------------------------------------------------------------------- #


class TestAiCache(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.cache = AiCache(path=os.path.join(self.tmp, "ai.db"))

    def tearDown(self) -> None:
        self.cache.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_key_returns_none(self) -> None:
        self.assertIsNone(self.cache.get("tidak-ada", "openai", "m"))

    def test_roundtrip_keeps_all_fields(self) -> None:
        hasil = AnalysisResult(
            verdict="perlu diperiksa",
            confidence="sedang",
            explanation="penjelasan",
            actions=["satu", "dua"],
            flags=["dasar"],
            usage=Usage(10, 5),
        )
        self.cache.put("k", "openai", "m", hasil)
        lagi = self.cache.get("k", "openai", "m")
        self.assertEqual(lagi.verdict, "perlu diperiksa")
        self.assertEqual(lagi.actions, ["satu", "dua"])
        self.assertEqual(lagi.flags, ["dasar"])
        self.assertEqual(lagi.usage.total, 15)
        self.assertTrue(lagi.from_cache)

    def test_result_not_reused_for_different_model(self) -> None:
        """Hasil dari model lain tidak boleh dipakai.

        Jawaban model berbeda bisa berbeda jauh, jadi hasil lama akan
        menyesatkan.
        """
        self.cache.put("k", "openai", "gpt-4o-mini", AnalysisResult(explanation="x"))
        self.assertIsNone(self.cache.get("k", "openai", "gpt-4o"))
        self.assertIsNone(self.cache.get("k", "anthropic", "claude"))

    def test_corrupt_row_is_ignored(self) -> None:
        """Baris rusak dianggap tidak ada, bukan membuat program berhenti."""
        self.cache.put("k", "openai", "m", AnalysisResult(explanation="x"))
        self.cache._conn.execute(
            "UPDATE ai_cache SET actions = 'bukan json' WHERE key = 'k'"
        )
        self.cache._conn.commit()
        self.assertIsNone(self.cache.get("k", "openai", "m"))

    def test_usage_is_accumulated(self) -> None:
        self.cache.record_usage("openai", "m", Usage(100, 50))
        self.cache.record_usage("openai", "m", Usage(20, 10))
        ringkas = self.cache.usage_summary()
        self.assertEqual(ringkas["calls"], 2)
        self.assertEqual(ringkas["total_tokens"], 180)

    def test_clear_empties_cache_but_keeps_usage(self) -> None:
        self.cache.put("k", "openai", "m", AnalysisResult(explanation="x"))
        self.cache.record_usage("openai", "m", Usage(10, 5))
        self.assertEqual(self.cache.clear(), 1)
        self.assertEqual(self.cache.size(), 0)
        self.assertEqual(self.cache.usage_summary()["calls"], 1)


# --------------------------------------------------------------------------- #
# 5. Analis: penjelasan temuan
# --------------------------------------------------------------------------- #


class TestAnalyst(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.cache = AiCache(path=os.path.join(self.tmp, "ai.db"))

    def tearDown(self) -> None:
        self.cache.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _report(self, sha: str = "a" * 64) -> FileReport:
        return FileReport(
            name="suspek.exe",
            size=115024,
            sha256=sha,
            extension=".exe",
            findings=[
                {
                    "severity": SEV_MALWARE,
                    "engine": "Analisis PE",
                    "rule": "Skor 85/100",
                    "detail": "impor createremotethread",
                }
            ],
        )

    def test_explanation_is_parsed(self) -> None:
        client = FakeClient(
            json.dumps(
                {
                    "penilaian": "kemungkinan berbahaya",
                    "keyakinan": "tinggi",
                    "penjelasan": "Program ini menyuntikkan kode ke proses lain.",
                    "tindakan": ["Karantina berkasnya"],
                    "catatan": ["Impor CreateRemoteThread"],
                }
            )
        )
        analyst = AiAnalyst(client, cache=self.cache)
        hasil = analyst.explain_file(self._report())
        self.assertEqual(hasil.result.verdict, "kemungkinan berbahaya")
        self.assertEqual(hasil.result.actions, ["Karantina berkasnya"])
        self.assertTrue(hasil.result.ok)

    def test_non_json_answer_is_still_shown(self) -> None:
        """Model kadang menjawab dengan teks biasa.

        Jawabannya masih berguna bagi pengguna, jadi membuangnya hanya karena
        bentuknya tidak sesuai akan merugikan.
        """
        client = FakeClient("Berkas ini terlihat mencurigakan karena X dan Y.")
        analyst = AiAnalyst(client, cache=self.cache)
        hasil = analyst.explain_file(self._report())
        self.assertTrue(hasil.result.ok)
        self.assertIn("mencurigakan", hasil.result.explanation)

    def test_second_call_uses_cache(self) -> None:
        """Bertanya ulang tidak boleh memanggil model lagi.

        Setiap panggilan menambah biaya pengguna.
        """
        client = FakeClient('{"penjelasan": "x", "penilaian": "p", "keyakinan": "r"}')
        analyst = AiAnalyst(client, cache=self.cache)
        analyst.explain_file(self._report())
        self.assertEqual(client.calls, 1)
        analyst.explain_file(self._report())
        self.assertEqual(client.calls, 1)

    def test_different_file_calls_model_again(self) -> None:
        client = FakeClient('{"penjelasan": "x"}')
        analyst = AiAnalyst(client, cache=self.cache)
        analyst.explain_file(self._report("a" * 64))
        analyst.explain_file(self._report("b" * 64))
        self.assertEqual(client.calls, 2)

    def test_cache_can_be_bypassed(self) -> None:
        client = FakeClient('{"penjelasan": "x"}')
        analyst = AiAnalyst(client, cache=self.cache)
        analyst.explain_file(self._report())
        analyst.explain_file(self._report(), use_cache=False)
        self.assertEqual(client.calls, 2)

    def test_failed_result_is_not_cached(self) -> None:
        """Jawaban kosong tidak boleh disimpan.

        Kalau disimpan, pengguna tidak akan pernah mendapat jawaban yang benar
        untuk berkas itu - walaupun mencoba lagi berkali-kali.
        """
        client = FakeClient("")
        analyst = AiAnalyst(client, cache=self.cache)
        analyst.explain_file(self._report())
        self.assertEqual(self.cache.size(), 0)

    def test_prompt_tells_model_not_to_decide_severity(self) -> None:
        """Peran yang diberikan ke model harus melarangnya menghakimi.

        Model bahasa bisa salah dengan sangat percaya diri. Kalau ia menentukan
        tingkat bahaya, pengguna menerima tuduhan yang tidak bisa diperiksa.
        """
        client = FakeClient('{"penjelasan": "x"}')
        analyst = AiAnalyst(client, cache=self.cache)
        analyst.explain_file(self._report())
        prompt = client.prompts[0]
        self.assertIn("MALWARE", prompt)
        self.assertIn("jangan", prompt.lower())

    def test_scan_explanation_is_not_cached(self) -> None:
        """Gambaran satu pemindaian tidak boleh di-cache.

        Setiap pemindaian punya isi berbeda, jadi kuncinya tidak bisa dipakai
        ulang.
        """
        client = FakeClient('{"penjelasan": "ringkasan"}')
        analyst = AiAnalyst(client, cache=self.cache)
        summary = ScanSummary(root="/x", findings=[], total_files=3)
        analyst.explain_scan(summary)
        analyst.explain_scan(summary)
        self.assertEqual(client.calls, 2)

    def test_check_connection_reports_missing_key(self) -> None:
        ok, pesan = check_connection(LlmClient(provider="openai", api_key=""))
        self.assertFalse(ok)
        self.assertIn("Kunci API", pesan)

    def test_check_connection_success(self) -> None:
        ok, pesan = check_connection(FakeClient("SIAP"))
        self.assertTrue(ok)
        self.assertIn("SIAP", pesan)

    def test_check_connection_reports_failure_with_hint(self) -> None:
        ok, pesan = check_connection(FailingClient())
        self.assertFalse(ok)
        self.assertIn("Kunci API ditolak", pesan)


# --------------------------------------------------------------------------- #
# 6. Deteksi anomali (model lokal, diuji sungguhan)
# --------------------------------------------------------------------------- #


class TestAnomalyDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.normal_dir = os.path.join(self.tmp, "dokumen")
        os.makedirs(self.normal_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_documents(self, count: int = 30) -> list[str]:
        paths = []
        for index in range(count):
            path = os.path.join(self.normal_dir, f"catatan{index}.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("laporan bulanan, catatan rapat, agenda kerja\n" * 30)
            paths.append(path)
        return paths

    def _write_outlier(self) -> str:
        import random

        path = os.path.join(self.normal_dir, "penyusup.dll")
        random.seed(11)
        with open(path, "wb") as handle:
            handle.write(b"MZ" + bytes(random.randrange(256) for _ in range(400000)))
        return path

    def test_too_few_files_returns_nothing(self) -> None:
        """Folder kecil tidak punya pembanding, jadi tidak ada yang menyimpang.

        Melaporkan penyimpangan dari kelompok berisi lima berkas hanya
        menghasilkan kebisingan.
        """
        paths = []
        for index in range(MIN_FILES - 7):
            path = os.path.join(self.normal_dir, f"f{index}.txt")
            open(path, "w").write("biasa\n")
            paths.append(path)
        self.assertEqual(find_anomalies(paths), [])

    def test_outlier_is_found(self) -> None:
        paths = self._write_documents() + [self._write_outlier()]
        hasil = find_anomalies(paths)
        self.assertTrue(hasil, "berkas penyusup seharusnya terdeteksi")
        self.assertIn("penyusup.dll", os.path.basename(hasil[0].path))

    def test_outlier_has_explained_reasons(self) -> None:
        """Temuan yang tidak bisa dijelaskan alasannya tidak bisa ditindaklanjuti."""
        paths = self._write_documents() + [self._write_outlier()]
        hasil = find_anomalies(paths)
        self.assertTrue(hasil[0].reasons)
        self.assertTrue(all(isinstance(r, str) and r for r in hasil[0].reasons))

    def test_identical_files_produce_no_anomaly(self) -> None:
        """Berkas yang seragam tidak punya penyimpangan - dan itu harus benar.

        Tanpa pengaman pada perhitungan, pembagian dengan simpangan baku nol
        bisa menghasilkan nilai tak terhingga dan menandai semua berkas.
        """
        paths = []
        for index in range(25):
            path = os.path.join(self.normal_dir, f"sama{index}.txt")
            open(path, "w").write("isi yang sama persis\n" * 20)
            paths.append(path)
        self.assertEqual(find_anomalies(paths), [])

    def test_result_count_is_bounded(self) -> None:
        import random

        paths = []
        for index in range(40):
            path = os.path.join(self.normal_dir, f"berkas{index}.bin")
            random.seed(index)
            with open(path, "wb") as handle:
                handle.write(bytes(random.randrange(256) for _ in range(5000)))
            paths.append(path)
        hasil = find_anomalies(paths, max_results=5)
        self.assertLessEqual(len(hasil), 5)

    def test_severity_is_always_a_note(self) -> None:
        """Anomali TIDAK PERNAH menjadi MALWARE.

        Berbeda bukan berarti berbahaya. Berkas cadangan atau basis data sering
        terlihat menyimpang padahal wajar. Menaikkan tingkatnya akan membuat
        pengguna menerima tuduhan berat atas berkas yang tidak bersalah.
        """
        paths = self._write_documents() + [self._write_outlier()]
        findings = anomalies_to_findings(find_anomalies(paths))
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding.severity, SEV_NOTE)

    def test_finding_explains_it_is_a_hint_not_proof(self) -> None:
        paths = self._write_documents() + [self._write_outlier()]
        findings = anomalies_to_findings(find_anomalies(paths))
        self.assertIn("bukan bukti", findings[0].detail)

    def test_missing_file_is_skipped(self) -> None:
        paths = self._write_documents()
        paths.append(os.path.join(self.normal_dir, "sudah-hilang.txt"))
        hasil = find_anomalies(paths)  # tidak boleh melempar
        self.assertIsInstance(hasil, list)

    def test_features_cover_all_files(self) -> None:
        paths = self._write_documents(15)
        features = extract_features(paths)
        self.assertEqual(len(features), 15)

    def test_text_ratio_separates_text_from_binary(self) -> None:
        """Ciri rasio teks harus membedakan dokumen dari program.

        Kalau tidak, model tidak punya cara melihat perbedaan yang paling
        mendasar antara dua jenis berkas ini.
        """
        text_path = os.path.join(self.normal_dir, "teks.txt")
        bin_path = os.path.join(self.normal_dir, "biner.bin")
        open(text_path, "w").write("a" * 2000)
        with open(bin_path, "wb") as handle:
            handle.write(bytes(range(256)) * 20)
        features = {os.path.basename(f.path): f for f in extract_features([text_path, bin_path])}
        self.assertGreater(features["teks.txt"].text_ratio, 0.95)
        self.assertLess(features["biner.bin"].text_ratio, 0.5)


# --------------------------------------------------------------------------- #
# 7. Asisten tanya-jawab
# --------------------------------------------------------------------------- #


class TestAssistant(unittest.TestCase):
    def test_suggested_questions_all_answered(self) -> None:
        """Setiap pertanyaan yang disarankan sendiri harus bisa dijawab.

        Menampilkan tombol pertanyaan yang tidak terjawab membuat fitur ini
        terlihat rusak sejak menit pertama dipakai.
        """
        for question in suggested_questions():
            with self.subTest(question=question):
                self.assertIsNotNone(
                    answer_from_knowledge(question),
                    f"pertanyaan saran tidak terjawab: {question}",
                )

    def test_keywords_match_whole_words_only(self) -> None:
        """BUG YANG PERNAH TERJADI: kata kunci cocok di dalam kata lain.

        Kata kunci "ai" cocok di dalam "ditandai", "bagaimana", dan "saya" -
        sehingga pertanyaan tentang kopi dijawab dengan topik deteksi anomali.
        """
        self.assertIsNone(answer_from_knowledge("bagaimana cara membuat kopi?"))
        self.assertIsNone(answer_from_knowledge("siapa presiden pertama Indonesia?"))

    def test_off_topic_question_returns_none(self) -> None:
        self.assertIsNone(answer_from_knowledge("berapa tinggi gunung Everest?"))

    def test_short_question_is_rejected(self) -> None:
        self.assertIsNone(answer_from_knowledge("a"))

    def test_most_specific_entry_wins(self) -> None:
        """Pertanyaan yang menyebut dua topik dijawab oleh topik yang lebih khusus."""
        jawaban = answer_from_knowledge("apa itu eicar dan apakah berbahaya?")
        self.assertIsNotNone(jawaban)
        self.assertIn("EICAR", jawaban.text)

    def test_works_without_ai_configured(self) -> None:
        """Asisten harus berguna sejak detik pertama, tanpa kunci API."""
        asisten = Assistant(analyst=None)
        jawaban = asisten.ask("apa itu karantina?")
        self.assertEqual(jawaban.source, "bawaan")
        self.assertIn("Karantina", jawaban.text)

    def test_unknown_question_without_ai_explains_how_to_enable(self) -> None:
        asisten = Assistant(analyst=None)
        jawaban = asisten.ask("jelaskan arsitektur prosesor ARM")
        self.assertIn("Pengaturan", jawaban.text)
        self.assertIn("Ollama", jawaban.text)

    def test_ai_failure_is_reported_not_raised(self) -> None:
        """Kegagalan jaringan tidak boleh melempar ke antarmuka.

        Antarmuka harus menampilkan penjelasan, bukan jejak kesalahan.
        """
        analyst = AiAnalyst(FailingClient(), cache=None)
        asisten = Assistant(analyst=analyst)
        summary = ScanSummary(root="/x")
        jawaban = asisten.ask("jelaskan arsitektur prosesor ARM", summary=summary)
        self.assertIn("Kunci API ditolak", jawaban.text)

    def test_ai_used_for_unknown_question_when_configured(self) -> None:
        client = FakeClient("ARM adalah arsitektur prosesor.")
        analyst = AiAnalyst(client, cache=None)
        asisten = Assistant(analyst=analyst)
        summary = ScanSummary(root="/x")
        jawaban = asisten.ask("jelaskan arsitektur prosesor ARM", summary=summary)
        self.assertIn("ARM", jawaban.text)
        self.assertEqual(client.calls, 1)

    def test_force_ai_skips_builtin_knowledge(self) -> None:
        """Tombol "Tanya AI" harus benar-benar memanggil model.

        Tanpa ini, pengguna yang ingin jawaban model tetap mendapat jawaban
        bawaan dan mengira modelnya tidak bekerja.
        """
        client = FakeClient("jawaban dari model")
        analyst = AiAnalyst(client, cache=None)
        asisten = Assistant(analyst=analyst)
        summary = ScanSummary(root="/x")
        jawaban = asisten.ask("apa itu karantina?", summary=summary, force_ai=True)
        self.assertEqual(client.calls, 1)
        self.assertIn("jawaban dari model", jawaban.text)

    def test_question_without_scan_result_is_explained(self) -> None:
        client = FakeClient("x")
        analyst = AiAnalyst(client, cache=None)
        asisten = Assistant(analyst=analyst)
        jawaban = asisten.ask("jelaskan arsitektur prosesor ARM", summary=None)
        self.assertIn("pemindaian", jawaban.text.lower())
        self.assertEqual(client.calls, 0)


# --------------------------------------------------------------------------- #
# 8. Ringkasan untuk model
# --------------------------------------------------------------------------- #


class TestContextBuilding(unittest.TestCase):
    def _summary(self, findings: list[Finding]) -> ScanSummary:
        summary = ScanSummary(root="/tmp/x", total_files=10, scanned_files=10)
        summary.findings = findings
        for finding in findings:
            if finding.severity == SEV_MALWARE:
                summary.infected += 1
            elif finding.severity == SEV_SUSPICIOUS:
                summary.suspicious += 1
            else:
                summary.notes += 1
        return summary

    def test_empty_scan_is_stated_clearly(self) -> None:
        teks = build_context(self._summary([]))
        self.assertIn("Tidak ada temuan", teks)

    def test_findings_are_grouped_per_file(self) -> None:
        """Satu berkas dengan tiga temuan harus tampil sebagai satu kelompok.

        Kalau dipecah, model melihat tiga masalah terpisah padahal itu satu
        berkas - dan penjelasannya menjadi keliru.
        """
        findings = [
            Finding(path="/x/a.exe", engine=e, rule="r", detail="d", severity=SEV_MALWARE)
            for e in ("Hash", "YARA", "ClamAV")
        ]
        teks = build_context(self._summary(findings))
        self.assertEqual(teks.count("/x/a.exe"), 1)

    def test_most_dangerous_file_listed_first(self) -> None:
        findings = [
            Finding(path="/x/note.txt", engine="e", rule="r", detail="d", severity=SEV_NOTE),
            Finding(path="/x/bad.exe", engine="e", rule="r", detail="d", severity=SEV_MALWARE),
        ]
        teks = build_context(self._summary(findings))
        self.assertLess(teks.index("/x/bad.exe"), teks.index("/x/note.txt"))

    def test_file_limit_is_respected(self) -> None:
        findings = [
            Finding(
                path=f"/x/f{i}.exe", engine="e", rule="r", detail="d", severity=SEV_NOTE
            )
            for i in range(60)
        ]
        teks = build_context(self._summary(findings), max_files=10)
        self.assertIn("50 berkas lain", teks)

    def test_summarise_counts_by_engine_and_severity(self) -> None:
        findings = [
            Finding(path="/x/a", engine="YARA", rule="r", detail="d", severity=SEV_MALWARE),
            Finding(path="/x/b", engine="YARA", rule="r", detail="d", severity=SEV_NOTE),
            Finding(path="/x/c", engine="ClamAV", rule="r", detail="d", severity=SEV_MALWARE),
        ]
        ringkas = summarise_findings(self._summary(findings))
        self.assertEqual(ringkas["total"], 3)
        self.assertEqual(ringkas["by_engine"]["YARA"], 2)
        self.assertEqual(ringkas["by_severity"][SEV_MALWARE], 2)
        self.assertEqual(ringkas["files_with_findings"], 3)


# --------------------------------------------------------------------------- #
# 9. Janji keselamatan AI di dalam program
# --------------------------------------------------------------------------- #


class TestAiSafetyPromises(unittest.TestCase):
    """Janji yang dipegang program ini, diperiksa langsung dari kode."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, *parts: str) -> str:
        with open(os.path.join(self.ROOT, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_anomaly_engine_never_returns_malware(self) -> None:
        """Mesin AI tidak boleh punya cara mengembalikan MALWARE."""
        sumber = self._read("scanguard", "ai", "anomaly.py")
        self.assertIn("severity=SEV_NOTE", sumber)
        self.assertNotIn("SEV_MALWARE", sumber)

    def test_ai_is_off_by_default_for_paid_features(self) -> None:
        """Fitur berbayar tidak boleh menyala sendiri.

        Fitur yang mengeluarkan biaya tanpa diminta bukan fitur yang baik.
        """
        settings = Settings()
        self.assertFalse(settings.ai_explain)
        self.assertFalse(settings.ai_send_snippet)

    def test_local_anomaly_is_on_by_default(self) -> None:
        # Model lokal gratis dan tanpa internet, jadi tidak ada alasan mematikannya.
        self.assertTrue(Settings().ai_anomaly)

    def test_scan_survives_anomaly_failure(self) -> None:
        """Kalau deteksi anomali gagal, pemindaian tetap dianggap berhasil.

        AI bersifat tambahan. Membiarkannya menggagalkan seluruh pemindaian
        berarti pengguna kehilangan hasil dari mesin-mesin yang andal.
        """
        sumber = self._read("scanguard", "scanner.py")
        self.assertIn("Deteksi anomali dilewati", sumber)
        self.assertIn("except Exception", sumber)

    def test_settings_file_is_readable_only_by_owner(self) -> None:
        """Berkas pengaturan berisi kunci API, jadi izinnya dibatasi."""
        tmp = tempfile.mkdtemp()
        try:
            with mock.patch.dict(os.environ, {"SCANGUARD_DATA_DIR": tmp}):
                settings = Settings(ai_api_key="rahasia")
                settings.save()
                mode = os.stat(Settings.path()).st_mode & 0o777
            self.assertEqual(mode, 0o600, f"izin berkas terlalu longgar: {oct(mode)}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 10. Jalur jaringan sungguhan (memakai server tiruan di komputer sendiri)
# --------------------------------------------------------------------------- #


class TestHttpPath(unittest.TestCase):
    """Menguji pengiriman permintaan yang sungguhan, bukan klien palsu.

    Klien palsu melewati bagian yang paling sering salah: penyusunan permintaan,
    header, dan penguraian jawaban. Pengujian ini menjalankan server HTTP kecil
    di komputer sendiri, sehingga seluruh jalur itu benar-benar dilewati tanpa
    memerlukan internet maupun kunci API.
    """

    @classmethod
    def setUpClass(cls) -> None:
        import json as _json
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from threading import Thread

        cls.requests: list[dict] = []
        cls.reply_payload = {
            "penilaian": "perlu diperiksa",
            "keyakinan": "sedang",
            "penjelasan": "Berkas ini memanggil fungsi yang lazim dipakai malware.",
            "tindakan": ["Periksa asal berkas"],
            "catatan": ["Impor CreateRemoteThread"],
        }
        cls.status_code = 200
        permintaan = cls.requests
        balasan = cls.reply_payload
        kelas = cls

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                panjang = int(self.headers.get("Content-Length", 0))
                badan = self.rfile.read(panjang).decode("utf-8")
                permintaan.append(
                    {
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "version": self.headers.get("anthropic-version"),
                        "body": _json.loads(badan) if badan else {},
                    }
                )
                if kelas.status_code != 200:
                    self.send_response(kelas.status_code)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": {"message": "ditolak"}}')
                    return
                data = _json.dumps(
                    {
                        "model": "model-uji",
                        "choices": [{"message": {"content": _json.dumps(balasan)}}],
                        "usage": {"prompt_tokens": 210, "completion_tokens": 88},
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        # Port 0 meminta sistem memilih port yang bebas. Port tetap akan
        # bertabrakan bila pengujian dijalankan bersamaan.
        cls.port = cls.server.server_address[1]
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self.requests.clear()
        type(self).status_code = 200
        self.tmp = tempfile.mkdtemp()
        self.cache = AiCache(path=os.path.join(self.tmp, "ai.db"))
        self.settings = Settings(
            ai_provider="openai",
            ai_model="model-uji",
            ai_base_url=f"http://127.0.0.1:{self.port}/v1/chat/completions",
            ai_api_key="kunci-uji",
        )
        self.client = build_client_from_settings(self.settings)

    def tearDown(self) -> None:
        self.cache.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_connection_succeeds_against_real_server(self) -> None:
        ok, pesan = check_connection(self.client)
        self.assertTrue(ok, pesan)

    def test_request_reaches_the_right_address(self) -> None:
        check_connection(self.client)
        self.assertEqual(self.requests[-1]["path"], "/v1/chat/completions")

    def test_api_key_is_sent_as_header_not_in_body(self) -> None:
        """Kunci harus dikirim lewat header, bukan di dalam isi permintaan.

        Isi permintaan sering ikut tercatat di log penyedia; header tidak.
        """
        check_connection(self.client)
        catatan = self.requests[-1]
        self.assertIn("Bearer kunci-uji", catatan["auth"])
        self.assertNotIn("kunci-uji", json.dumps(catatan["body"]))

    def test_system_prompt_is_sent(self) -> None:
        check_connection(self.client)
        pesan = self.requests[-1]["body"]["messages"]
        self.assertEqual(pesan[0]["role"], "system")

    def test_system_prompt_forbids_deciding_severity(self) -> None:
        """Larangan itu harus benar-benar sampai ke penyedia, bukan hanya ada di kode.

        Diperiksa lewat permintaan analisis, bukan lewat uji koneksi - uji
        koneksi memakai peran yang sangat pendek karena hanya perlu memastikan
        jalurnya hidup.
        """
        analyst = AiAnalyst(self.client, cache=self.cache)
        analyst.explain_file(
            FileReport(name="a.exe", size=100, sha256="h" * 64, extension=".exe")
        )
        system = self.requests[-1]["body"]["messages"][0]["content"]
        self.assertIn("TIDAK menentukan tingkat bahaya", system)
        self.assertIn("tidak bisa memastikan", system.lower())

    def test_analysis_parses_reply_over_the_network(self) -> None:
        analyst = AiAnalyst(self.client, cache=self.cache)
        hasil = analyst.explain_file(
            FileReport(
                name="a.exe",
                size=100,
                sha256="e" * 64,
                extension=".exe",
                findings=[
                    {
                        "severity": SEV_MALWARE,
                        "engine": "Analisis PE",
                        "rule": "Skor 85/100",
                        "detail": "impor createremotethread",
                    }
                ],
            )
        )
        self.assertEqual(hasil.result.verdict, "perlu diperiksa")
        self.assertEqual(hasil.result.actions, ["Periksa asal berkas"])
        self.assertEqual(hasil.result.usage.total, 298)

    def test_prompt_includes_the_findings(self) -> None:
        analyst = AiAnalyst(self.client, cache=self.cache)
        analyst.explain_file(
            FileReport(
                name="a.exe",
                size=100,
                sha256="f" * 64,
                extension=".exe",
                findings=[
                    {
                        "severity": SEV_MALWARE,
                        "engine": "Analisis PE",
                        "rule": "Skor 85/100",
                        "detail": "impor createremotethread",
                    }
                ],
            )
        )
        prompt = self.requests[-1]["body"]["messages"][-1]["content"]
        self.assertIn("createremotethread", prompt)

    def test_second_request_is_served_from_cache(self) -> None:
        """Berkas yang sama tidak boleh memanggil model dua kali."""
        analyst = AiAnalyst(self.client, cache=self.cache)
        report = FileReport(name="a.exe", size=100, sha256="g" * 64, extension=".exe")
        analyst.explain_file(report)
        jumlah = len(self.requests)
        analyst.explain_file(report)
        self.assertEqual(len(self.requests), jumlah)

    def test_http_error_becomes_explained_message(self) -> None:
        """Kesalahan penyedia harus menjadi pesan yang bisa dipahami pengguna."""
        type(self).status_code = 401
        with self.assertRaises(LlmError) as ctx:
            self.client.ask("halo")
        self.assertIn("401", str(ctx.exception))
        self.assertIn("Kunci API ditolak", ctx.exception.hint)

    def test_http_error_does_not_leak_the_key(self) -> None:
        type(self).status_code = 403
        with self.assertRaises(LlmError) as ctx:
            self.client.ask("halo")
        self.assertNotIn("kunci-uji", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)

