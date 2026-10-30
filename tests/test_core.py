"""Uji otomatis ScanGuard.

Uji ini memakai berkas sungguhan di folder sementara, bukan tiruan: basis data
SQLite sungguhan, berkas PE sungguhan, karantina sungguhan, dan proses clamscan
sungguhan bila terpasang. Yang diganti hanya kotak dialog (modal) dan kecepatan
waktu, karena keduanya tidak bisa dipakai di lingkungan tanpa layar.

Jalankan:
    python -m unittest discover -s tests -v
    xvfb-run -a ./run_tests.sh        (di server Linux tanpa layar)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import build_minimal_pe  # noqa: E402

from scanguard import config  # noqa: E402
from scanguard.clamav_engine import ClamAVEngine, parse_clamscan_output  # noqa: E402
from scanguard.core import (  # noqa: E402
    Finding,
    format_size,
    hash_file,
    is_double_extension,
    shannon_entropy,
)
from scanguard.hashes import (  # noqa: E402
    EICAR_SHA256,
    HashDatabase,
    HashUpdater,
    parse_hash_list,
    parse_malwarebazaar_response,
)
from scanguard.pe_engine import PEEngine  # noqa: E402
from scanguard.quarantine import Quarantine  # noqa: E402
from scanguard.report import build_report  # noqa: E402
from scanguard.scanner import ScanEngine  # noqa: E402
from scanguard.settings import Settings  # noqa: E402
from scanguard.yara_engine import YaraEngine  # noqa: E402

EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Setiap uji memakai folder data sendiri supaya tidak saling mengganggu.
_DATA_DIR = tempfile.mkdtemp(prefix="scanguard-test-")
os.environ["SCANGUARD_DATA_DIR"] = _DATA_DIR


def tearDownModule() -> None:
    shutil.rmtree(_DATA_DIR, ignore_errors=True)


class TempCase(unittest.TestCase):
    """Kelas dasar yang menyiapkan folder sementara untuk setiap uji."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="sg-case-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name: str, data: bytes) -> str:
        # Semua berkas uji ditaruh di dalam subfolder "berkas" supaya pencarian
        # tidak ikut menemukan basis data SQLite atau folder karantina yang
        # dibuat pengujian lain di folder yang sama.
        path = os.path.join(self.tmp, "berkas", name)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path


# --------------------------------------------------------------------------- #
# 1. Fungsi bantu
# --------------------------------------------------------------------------- #


class TestHelpers(TempCase):
    def test_format_size(self) -> None:
        self.assertEqual(format_size(0), "0 B")
        self.assertEqual(format_size(999), "999 B")
        self.assertEqual(format_size(1024), "1.0 KB")
        self.assertEqual(format_size(20 * 1024 * 1024), "20.0 MB")

    def test_entropy_of_constant_data_is_zero(self) -> None:
        self.assertEqual(shannon_entropy(b"\x00" * 4096), 0.0)
        self.assertEqual(shannon_entropy(b"A" * 1000), 0.0)

    def test_entropy_of_random_data_is_high(self) -> None:
        self.assertGreater(shannon_entropy(os.urandom(65536)), 7.5)

    def test_entropy_of_text_is_moderate(self) -> None:
        text = b"belanja bulanan: telur, susu, kopi, gula, beras\n" * 200
        value = shannon_entropy(text)
        self.assertLess(value, 5.0)
        self.assertGreater(value, 2.0)

    def test_entropy_of_empty_data(self) -> None:
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_double_extension_detected(self) -> None:
        self.assertEqual(is_double_extension("Faktur.pdf.exe"), ".pdf")
        self.assertEqual(is_double_extension("gambar.jpg.scr"), ".jpg")

    def test_double_extension_not_flagged_for_normal_names(self) -> None:
        self.assertIsNone(is_double_extension("laporan.pdf"))
        self.assertIsNone(is_double_extension("program.exe"))
        self.assertIsNone(is_double_extension("arsip.tar.gz"))

    def test_hash_file_matches_hashlib(self) -> None:
        payload = b"isi berkas untuk diuji" * 100
        path = self.write("berkas.bin", payload)
        sha256, sha1, md5 = hash_file(path)
        self.assertEqual(sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(sha1, hashlib.sha1(payload).hexdigest())
        self.assertEqual(md5, hashlib.md5(payload).hexdigest())

    def test_finding_key_ignores_identical_duplicates(self) -> None:
        a = Finding("/x", "YARA", "R", "d", "MALWARE")
        b = Finding("/x", "YARA", "R", "d", "MALWARE")
        c = Finding("/x", "YARA", "R", "lain", "MALWARE")
        self.assertEqual(a.key, b.key)
        self.assertNotEqual(a.key, c.key)


# --------------------------------------------------------------------------- #
# 2. Basis data hash
# --------------------------------------------------------------------------- #


class TestHashDatabase(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.db = HashDatabase(os.path.join(self.tmp, "uji.db"))
        self.addCleanup(self.db.close)

    def test_seed_contains_eicar(self) -> None:
        match = self.db.lookup(sha256=EICAR_SHA256)
        self.assertIsNotNone(match)
        self.assertIn("EICAR", match.threat.upper())

    def test_lookup_by_sha1_and_md5(self) -> None:
        self.assertIsNotNone(self.db.lookup(sha1="3395856ce81f2b7382dee72602f798b642f14140"))
        self.assertIsNotNone(self.db.lookup(md5="44d88612fea8a8f36de82e1278abb02f"))

    def test_lookup_unknown_hash_returns_none(self) -> None:
        self.assertIsNone(self.db.lookup(sha256="a" * 64))

    def test_add_many_rejects_invalid_hash(self) -> None:
        self.assertEqual(self.db.add_many([("bukan-hash", "", "", "x", "y")]), 0)

    def test_add_many_counts_only_new_rows(self) -> None:
        record = (("f" * 64), "", "", "nama", "Trojan.Uji")
        self.assertEqual(self.db.add_many([record]), 1)
        self.assertEqual(self.db.add_many([record]), 0)

    def test_add_many_normalizes_case(self) -> None:
        self.db.add_many([("A" * 64, "B" * 40, "C" * 32, "x", "y")])
        self.assertIsNotNone(self.db.lookup(sha256="a" * 64))

    def test_stats_reports_sources(self) -> None:
        stats = self.db.stats()
        self.assertGreaterEqual(stats["total"], 1)
        self.assertIn("bawaan", stats["by_source"])

    def test_cache_roundtrip_stores_findings(self) -> None:
        payload = [
            {"path": "/x", "engine": "YARA", "rule": "R", "detail": "d", "severity": "MALWARE"}
        ]
        self.db.put_cached("/x", 10, 1.5, "a" * 64, "v2-h1:infeksi", payload)
        cached = self.db.get_cached("/x", 10, 1.5)
        self.assertIsNotNone(cached)
        sha256, verdict, findings = cached
        self.assertEqual(sha256, "a" * 64)
        self.assertEqual(verdict, "v2-h1:infeksi")
        self.assertEqual(findings, payload)

    def test_cache_miss_when_file_changed(self) -> None:
        self.db.put_cached("/x", 10, 1.5, "a" * 64, "v", [])
        self.assertIsNone(self.db.get_cached("/x", 11, 1.5))
        self.assertIsNone(self.db.get_cached("/x", 10, 2.5))

    def test_cache_tolerates_corrupt_json(self) -> None:
        self.db._conn.execute(
            "INSERT OR REPLACE INTO scanned_cache "
            "(path, size, mtime, sha256, verdict, findings) VALUES (?,?,?,?,?,?)",
            ("/rusak", 1, 1.0, "b" * 64, "v", "{bukan json"),
        )
        self.db._conn.commit()
        result = self.db.get_cached("/rusak", 1, 1.0)
        self.assertIsNotNone(result)
        self.assertEqual(result[2], [])

    def test_clear_cache(self) -> None:
        self.db.put_cached("/x", 10, 1.5, "a" * 64, "v", [])
        self.assertGreaterEqual(self.db.clear_cache(), 1)
        self.assertIsNone(self.db.get_cached("/x", 10, 1.5))


class TestHashListParsing(unittest.TestCase):
    def test_plain_list_one_per_line(self) -> None:
        self.assertEqual(len(parse_hash_list("\n".join(["a" * 64, "b" * 64]))), 2)

    def test_comments_and_blank_lines_ignored(self) -> None:
        self.assertEqual(len(parse_hash_list("# komentar\n\n" + "c" * 64 + "\n   \n")), 1)

    def test_csv_with_name_and_threat(self) -> None:
        rows = parse_hash_list("d" * 64 + ",laporan.pdf.exe,Trojan.Uji")
        self.assertEqual(rows[0][0], "d" * 64)
        self.assertEqual(rows[0][3], "laporan.pdf.exe")
        self.assertEqual(rows[0][4], "Trojan.Uji")

    def test_abusech_style_csv_with_quotes(self) -> None:
        line = '"' + "e" * 64 + '","2026-10-30 06:00:00","contoh.exe","exe"'
        rows = parse_hash_list(line)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "e" * 64)

    def test_duplicate_hashes_are_collapsed(self) -> None:
        self.assertEqual(len(parse_hash_list("\n".join(["f" * 64] * 5))), 1)

    def test_uppercase_hash_is_accepted(self) -> None:
        self.assertEqual(len(parse_hash_list("A" * 64)), 1)

    def test_invalid_lines_are_ignored(self) -> None:
        self.assertEqual(parse_hash_list("bukan hash\n12345\n"), [])

    def test_malwarebazaar_json_parsed(self) -> None:
        payload = json.dumps(
            {
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "1" * 64,
                        "sha1_hash": "2" * 40,
                        "md5_hash": "3" * 32,
                        "file_name": "jahat.exe",
                        "signature": "Trojan.Uji",
                    }
                ],
            }
        ).encode()
        rows = parse_malwarebazaar_response(payload)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "1" * 64)
        self.assertEqual(rows[0][4], "Trojan.Uji")

    def test_malwarebazaar_tags_used_when_no_signature(self) -> None:
        payload = json.dumps(
            {"query_status": "ok", "data": [{"sha256_hash": "4" * 64, "tags": ["ransomware"]}]}
        ).encode()
        self.assertEqual(parse_malwarebazaar_response(payload)[0][4], "ransomware")

    def test_malwarebazaar_error_status_returns_empty(self) -> None:
        payload = json.dumps({"query_status": "no_api_key"}).encode()
        self.assertEqual(parse_malwarebazaar_response(payload), [])

    def test_malwarebazaar_garbage_returns_empty(self) -> None:
        self.assertEqual(parse_malwarebazaar_response(b"bukan json"), [])
        self.assertEqual(parse_malwarebazaar_response(b""), [])


class TestHashUpdater(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.db = HashDatabase(os.path.join(self.tmp, "u.db"))
        self.addCleanup(self.db.close)
        self.updater = HashUpdater(self.db)

    def test_update_from_text(self) -> None:
        result = self.updater.update_from_text("9" * 64, "uji")
        self.assertTrue(result["ok"])
        self.assertEqual(result["added"], 1)
        self.assertIsNotNone(self.db.lookup(sha256="9" * 64))

    def test_update_from_file(self) -> None:
        path = self.write("daftar.csv", ("7" * 64 + ",contoh.exe,Trojan\n").encode())
        result = self.updater.update_from_file(path)
        self.assertTrue(result["ok"])
        self.assertEqual(result["added"], 1)

    def test_update_from_missing_file_reports_error(self) -> None:
        result = self.updater.update_from_file(os.path.join(self.tmp, "hantu"))
        self.assertFalse(result["ok"])
        self.assertIn("Gagal membaca", result["message"])

    def test_missing_auth_key_gives_clear_message(self) -> None:
        result = self.updater.update_from_malwarebazaar("")
        self.assertFalse(result["ok"])
        # Pesan harus menyebut apa yang harus dilakukan, bukan sekadar gagal.
        self.assertIn("Auth-Key", result["message"])
        self.assertIn("auth.abuse.ch", result["message"])

    def test_timestamp_recorded_after_update(self) -> None:
        self.updater.update_from_text("8" * 64)
        self.assertIsNotNone(self.db.stats()["last_update_text"])


# --------------------------------------------------------------------------- #
# 3. Mesin YARA
# --------------------------------------------------------------------------- #


class TestYaraEngine(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.engine = YaraEngine(config.default_rules_path())

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_rules_compile_and_load(self) -> None:
        status = self.engine.load()
        self.assertTrue(status.ok, status.message)
        self.assertGreaterEqual(status.rule_count, 10)

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_eicar_detected(self) -> None:
        path = self.write("eicar.txt", EICAR_BYTES)
        self.engine.load()
        self.assertIn("EICAR_Test_File", {f.rule for f in self.engine.scan_file(path)})

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_ransomware_shadow_copy_detected(self) -> None:
        path = self.write(
            "jahat.bat", b"@echo off\r\nvssadmin delete shadows /all /quiet\r\n"
        )
        self.engine.load()
        findings = self.engine.scan_file(path)
        self.assertTrue(any("Shadow_Copy" in f.rule for f in findings))
        self.assertEqual(findings[0].severity, "MALWARE")

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_powershell_obfuscation_detected(self) -> None:
        path = self.write("run.bat", b"powershell -enc SQBFAFgA -windowstyle hidden -noprofile")
        self.engine.load()
        self.assertTrue(any("PowerShell" in f.rule for f in self.engine.scan_file(path)))

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_credential_tool_detected(self) -> None:
        path = self.write("alat.exe", b"sekurlsa::logonpasswords")
        self.engine.load()
        self.assertTrue(
            any("Credential_Stealer" in f.rule for f in self.engine.scan_file(path))
        )

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_clean_files_produce_no_findings(self) -> None:
        self.engine.load()
        samples = [
            ("catatan.txt", b"belanja: telur, susu, kopi\n"),
            ("skrip.py", b"def tambah(a, b):\n    return a + b\n"),
            ("halaman.html", b"<html><body><h1>Halo</h1></body></html>"),
            ("data.json", b'{"nama": "ScanGuard", "versi": "2.0.0"}'),
            ("catatan.md", b"# Judul\n\nIni catatan biasa tanpa pola mencurigakan.\n"),
        ]
        for name, data in samples:
            with self.subTest(file=name):
                self.assertEqual(
                    self.engine.scan_file(self.write(name, data)),
                    [],
                    f"{name} seharusnya tidak diflag",
                )

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_binary_file_with_invalid_utf8_is_safe(self) -> None:
        path = self.write("biner.bin", bytes(range(256)) * 40)
        self.engine.load()
        self.assertEqual(self.engine.scan_file(path), [])

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_missing_file_does_not_raise(self) -> None:
        self.engine.load()
        self.assertEqual(self.engine.scan_file(os.path.join(self.tmp, "hantu")), [])

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_missing_rules_file_reports_error(self) -> None:
        status = YaraEngine(os.path.join(self.tmp, "tidak-ada.yar")).load()
        self.assertFalse(status.ok)
        self.assertIn("tidak ditemukan", status.message)

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_broken_rules_file_reports_error(self) -> None:
        path = self.write("rusak.yar", b"rule { ini bukan yara yang sah ")
        status = YaraEngine(path).load()
        self.assertFalse(status.ok)
        self.assertIn("gagal dikompilasi", status.message.lower())

    @unittest.skipUnless(YaraEngine().available, "yara-python tidak terpasang")
    def test_compile_cache_is_used_second_time(self) -> None:
        YaraEngine(config.default_rules_path()).load()
        status = YaraEngine(config.default_rules_path()).load()
        self.assertTrue(status.used_cache)


# --------------------------------------------------------------------------- #
# 4. Mesin analisis PE
# --------------------------------------------------------------------------- #


class TestPEEngine(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.engine = PEEngine()

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_reads_sections_and_imports(self) -> None:
        analysis = self.engine.analyze(self.write("program.exe", build_minimal_pe()))
        self.assertTrue(analysis.is_pe)
        self.assertEqual(analysis.section_count, 3)
        self.assertGreater(analysis.import_count, 10)

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_normal_program_is_not_reported(self) -> None:
        """Program biasa dengan impor lazim tidak boleh muncul di laporan.

        Ini uji paling penting untuk mesin PE: tanpa ambang yang benar, hampir
        setiap program Windows akan dituduh mencurigakan.
        """
        self.assertEqual(self.engine.scan_file(self.write("normal.exe", build_minimal_pe())), [])

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_code_injection_imports_are_malware(self) -> None:
        path = self.write(
            "inject.exe",
            build_minimal_pe(
                imports=[
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "URLDownloadToFileA",
                ]
            ),
        )
        self.assertGreaterEqual(self.engine.analyze(path).score, 60)
        self.assertTrue(any(f.severity == "MALWARE" for f in self.engine.scan_file(path)))

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_packer_section_names_are_malware(self) -> None:
        path = self.write(
            "packed.exe",
            build_minimal_pe(
                sections=[
                    (".text", 0x400, 0x20000020),
                    ("UPX0", 0x200, 0xE0000020),
                    ("UPX1", 0x200, 0xE0000020),
                ]
            ),
        )
        analysis = self.engine.analyze(path)
        self.assertIn("UPX0", analysis.packed_section_names)
        self.assertTrue(analysis.packed)
        self.assertTrue(any(f.severity == "MALWARE" for f in self.engine.scan_file(path)))

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_weak_evidence_alone_is_not_malware(self) -> None:
        """Satu-dua petunjuk lemah tidak boleh menghasilkan tuduhan berat."""
        path = self.write(
            "sedikit.exe",
            build_minimal_pe(imports=["IsDebuggerPresent", "TerminateProcess"]),
        )
        for finding in self.engine.scan_file(path):
            self.assertNotEqual(finding.severity, "MALWARE")

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_writable_executable_section_gets_note(self) -> None:
        path = self.write(
            "wx.exe",
            build_minimal_pe(
                sections=[(".text", 0x400, 0x20000020 | 0x80000000), (".data", 0x200, 0x40000040)]
            ),
        )
        findings = self.engine.scan_file(path)
        self.assertTrue(findings)
        self.assertIn(findings[0].severity, ("PERLU DIPERIKSA", "MENCURIGAKAN"))

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_high_entropy_section_detected(self) -> None:
        import random

        import pefile

        data = build_minimal_pe(
            sections=[(".text", 0x400, 0x20000020), (".packed", 0x8000, 0x40000040)]
        )
        pe = pefile.PE(data=data)
        offset = pe.sections[1].PointerToRawData
        # Seluruh isi section harus ditimpa. Menimpa sebagian saja menyisakan
        # banyak byte nol, sehingga entropinya tetap rendah.
        size = pe.sections[1].SizeOfRawData
        pe.close()

        random.seed(1234)
        raw = bytearray(data)
        raw[offset : offset + size] = bytes(random.randrange(256) for _ in range(size))
        analysis = self.engine.analyze(self.write("acak.exe", bytes(raw)))
        self.assertGreater(analysis.max_section_entropy, 7.0)
        # Section yang isinya hampir acak harus dianggap bukti kuat.
        self.assertTrue(analysis.packed or analysis.score >= 25)

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_non_pe_file_is_ignored(self) -> None:
        path = self.write("teks.txt", b"ini bukan program Windows sama sekali")
        self.assertFalse(self.engine.analyze(path).is_pe)
        self.assertEqual(self.engine.scan_file(path), [])

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_truncated_pe_does_not_crash(self) -> None:
        path = self.write("terpotong.exe", build_minimal_pe()[:300])
        analysis = self.engine.analyze(path)  # tidak boleh melempar error
        self.assertTrue(analysis.is_pe or analysis.error)

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_32bit_machine_detected(self) -> None:
        path = self.write("tiga2.exe", build_minimal_pe(machine=0x014C, subsystem=3))
        self.assertIn("386", self.engine.analyze(path).machine)

    @unittest.skipUnless(PEEngine().available, "pefile tidak terpasang")
    def test_future_timestamp_noted(self) -> None:
        # Penanda waktu PE hanya 32 bit, jadi nilai terbesarnya adalah
        # 0xFFFFFFFF - sekitar Februari 2106. Nilai itu sudah cukup tidak
        # masuk akal untuk sebuah program.
        path = self.write("waktu.exe", build_minimal_pe(timestamp=0xFFFFFFFF))
        analysis = self.engine.analyze(path)
        self.assertTrue(any("tidak masuk akal" in n.lower() for n in analysis.notes))


# --------------------------------------------------------------------------- #
# 5. ClamAV
# --------------------------------------------------------------------------- #


class TestClamAVParsing(unittest.TestCase):
    """Penguraian keluaran clamscan diuji dengan keluaran sungguhan."""

    REAL_OUTPUT = (
        "/tmp/a/eicar.txt: Eicar-Test-Signature FOUND\n"
        "/tmp/a/bersih.txt: OK\n"
        "/tmp/a/program.exe: OK\n"
        "/tmp/a/aneh.txt: No such file or directory\n"
        "WARNING: /tmp/a/aneh.txt: Can't access file\n"
        "/tmp/a/nama: dengan: titikdua.txt: Win.Trojan.Uji FOUND\n"
    )

    def test_infected_files_parsed(self) -> None:
        infected, _, _ = parse_clamscan_output(self.REAL_OUTPUT)
        self.assertEqual(infected["/tmp/a/eicar.txt"], "Eicar-Test-Signature")

    def test_clean_files_parsed(self) -> None:
        _, clean, _ = parse_clamscan_output(self.REAL_OUTPUT)
        self.assertIn("/tmp/a/bersih.txt", clean)
        self.assertIn("/tmp/a/program.exe", clean)

    def test_errors_parsed_and_warnings_ignored(self) -> None:
        _, _, errors = parse_clamscan_output(self.REAL_OUTPUT)
        self.assertIn("/tmp/a/aneh.txt", errors)
        self.assertNotIn("WARNING", " ".join(errors))

    def test_filename_containing_colon_is_handled(self) -> None:
        infected, _, _ = parse_clamscan_output(self.REAL_OUTPUT)
        self.assertIn("/tmp/a/nama: dengan: titikdua.txt", infected)

    def test_empty_output(self) -> None:
        self.assertEqual(parse_clamscan_output(""), ({}, set(), {}))

    def test_missing_binary_is_not_available(self) -> None:
        self.assertFalse(ClamAVEngine(executable="/tidak/ada/clamscan").available)

    def test_pua_signature_is_suspicious_not_malware(self) -> None:
        self.assertEqual(
            ClamAVEngine._finding("/x", "Win.Adware.Bundler").severity, "MENCURIGAKAN"
        )

    def test_virus_signature_is_malware(self) -> None:
        self.assertEqual(
            ClamAVEngine._finding("/x", "Win.Trojan.Emotet-123").severity, "MALWARE"
        )

    def test_eicar_is_malware_for_consistency(self) -> None:
        """EICAR harus sama tingkatnya dengan mesin lain (MALWARE)."""
        self.assertEqual(
            ClamAVEngine._finding("/x", "Eicar-Test-Signature").severity, "MALWARE"
        )


class TestClamAVRealRun(TempCase):
    """Uji terhadap clamscan sungguhan, dilewati bila tidak terpasang."""

    @unittest.skipUnless(
        ClamAVEngine().available, "ClamAV tidak terpasang atau basis data belum ada"
    )
    def test_eicar_detected_by_real_clamscan(self) -> None:
        findings = ClamAVEngine().scan_file(self.write("eicar.txt", EICAR_BYTES))
        self.assertTrue(findings)
        self.assertIn("Eicar", findings[0].rule)

    @unittest.skipUnless(
        ClamAVEngine().available, "ClamAV tidak terpasang atau basis data belum ada"
    )
    def test_clean_file_passes_real_clamscan(self) -> None:
        path = self.write("bersih.txt", b"belanja: telur, susu, kopi\n")
        self.assertEqual(ClamAVEngine().scan_file(path), [])

    @unittest.skipUnless(
        ClamAVEngine().available, "ClamAV tidak terpasang atau basis data belum ada"
    )
    def test_batch_scan_reports_each_file(self) -> None:
        good = self.write("baik.txt", b"isi biasa\n")
        bad = self.write("buruk.txt", EICAR_BYTES)
        result = ClamAVEngine().scan_paths([good, bad])
        self.assertIn(bad, result.infected)
        self.assertIn(good, result.clean)

    @unittest.skipUnless(
        ClamAVEngine().available, "ClamAV tidak terpasang atau basis data belum ada"
    )
    def test_progress_callback_called(self) -> None:
        paths = [self.write(f"f{i}.txt", b"biasa\n") for i in range(3)]
        seen: list[tuple[int, int]] = []
        ClamAVEngine().scan_paths(paths, on_batch=lambda a, b: seen.append((a, b)))
        self.assertTrue(seen)


# --------------------------------------------------------------------------- #
# 6. Karantina
# --------------------------------------------------------------------------- #


class TestQuarantine(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.q = Quarantine(os.path.join(self.tmp, "karantina"))

    def test_quarantine_removes_original_and_scrambles_content(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        ok, message = self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        self.assertTrue(ok, message)
        self.assertFalse(os.path.exists(path))

        entry = self.q.entries()[0]
        stored = os.path.join(self.q.files_dir, entry.stored_name)
        data = open(stored, "rb").read()
        self.assertNotIn(b"EICAR", data, "isi karantina masih bisa dikenali")
        self.assertEqual(len(data), len(EICAR_BYTES), "ukuran berubah")

    def test_restore_returns_identical_bytes(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        ok, message = self.q.restore(self.q.entries()[0].id)
        self.assertTrue(ok, message)
        self.assertEqual(open(path, "rb").read(), EICAR_BYTES)

    def test_restore_does_not_overwrite_existing_file(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        with open(path, "wb") as handle:
            handle.write(b"berkas baru yang penting")
        ok, message = self.q.restore(self.q.entries()[0].id)
        self.assertTrue(ok, message)
        self.assertEqual(open(path, "rb").read(), b"berkas baru yang penting")
        self.assertIn("dipulihkan", message)

    def test_verify_reports_no_problems(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        self.assertEqual(self.q.verify(), [])

    def test_verify_detects_damaged_entry(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        stored = os.path.join(self.q.files_dir, self.q.entries()[0].stored_name)
        with open(stored, "r+b") as handle:
            handle.seek(0)
            handle.write(b"XXXX")
        self.assertTrue(self.q.verify())

    def test_quarantine_missing_file_reports_error(self) -> None:
        ok, message = self.q.quarantine_file(
            os.path.join(self.tmp, "hantu"), "x", "y", "z", "MALWARE"
        )
        self.assertFalse(ok)
        self.assertIn("tidak ditemukan", message)

    def test_delete_removes_entry(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        entry = self.q.entries()[0]
        ok, _ = self.q.delete(entry.id)
        self.assertTrue(ok)
        self.assertEqual(self.q.active_entries(), [])
        self.assertFalse(os.path.exists(os.path.join(self.q.files_dir, entry.stored_name)))

    def test_unknown_entry_reports_error(self) -> None:
        self.assertFalse(self.q.restore("tidak-ada")[0])
        self.assertFalse(self.q.delete("tidak-ada")[0])

    def test_index_survives_reload(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        entry_id = self.q.entries()[0].id
        reopened = Quarantine(self.q.root)
        self.assertEqual([e.id for e in reopened.entries()], [entry_id])

    def test_corrupt_index_does_not_crash(self) -> None:
        path = self.write("jahat.txt", EICAR_BYTES)
        self.q.quarantine_file(path, "YARA", "EICAR", "uji", "MALWARE")
        with open(self.q.index_path, "w") as handle:
            handle.write("{ini bukan json")
        reopened = Quarantine(self.q.root)  # harus tetap bisa dibuka
        self.assertEqual(reopened.entries(), [])

    def test_two_files_with_same_name_do_not_collide(self) -> None:
        self.q.quarantine_file(self.write("a/jahat.txt", EICAR_BYTES), "x", "y", "z", "MALWARE")
        self.q.quarantine_file(
            self.write("b/jahat.txt", EICAR_BYTES + b"beda"), "x", "y", "z", "MALWARE"
        )
        self.assertEqual(len(self.q.active_entries()), 2)
        self.assertEqual(len({e.stored_name for e in self.q.active_entries()}), 2)

    def test_total_size_counts_active_entries(self) -> None:
        self.q.quarantine_file(self.write("jahat.txt", EICAR_BYTES), "x", "y", "z", "MALWARE")
        self.assertEqual(self.q.total_size(), len(EICAR_BYTES))


# --------------------------------------------------------------------------- #
# 7. Orkestrator pemindaian
# --------------------------------------------------------------------------- #


class TestScanEngine(TempCase):
    def setUp(self) -> None:
        super().setUp()
        # Basis data dan karantina sengaja ditaruh di luar self.tmp, karena
        # self.tmp adalah folder yang dipindai. Kalau ditaruh di dalamnya,
        # berkas kerja program ikut terhitung sebagai berkas yang diperiksa.
        work = tempfile.mkdtemp(prefix="sg-work-")
        self.addCleanup(shutil.rmtree, work, True)
        self.engine = ScanEngine(
            database=HashDatabase(os.path.join(work, "s.db")),
            quarantine=Quarantine(os.path.join(work, "q")),
            use_clamav=False,
        )
        self.addCleanup(self.engine.db.close)

    def test_eicar_found_by_hash_and_yara(self) -> None:
        findings = self.engine.scan_file(self.write("eicar.txt", EICAR_BYTES))
        engines = {f.engine for f in findings}
        self.assertIn("Hash SHA-256", engines)
        if YaraEngine().available:
            self.assertIn("YARA", engines)
        self.assertTrue(all(f.severity == "MALWARE" for f in findings))

    def test_clean_file_produces_no_findings(self) -> None:
        self.assertEqual(
            self.engine.scan_file(self.write("catatan.txt", b"belanja: telur, susu\n")), []
        )

    def test_double_extension_flagged(self) -> None:
        findings = self.engine.scan_file(self.write("Faktur.pdf.exe", b"bukan pdf sungguhan"))
        self.assertTrue(any(f.rule == "Ekstensi ganda" for f in findings))
        self.assertEqual(
            [f.severity for f in findings if f.rule == "Ekstensi ganda"], ["MENCURIGAKAN"]
        )

    def test_large_executable_gets_a_note(self) -> None:
        """Program yang jauh lebih besar dari wajar hanya diberi catatan.

        Ukuran besar sendirian bukan bukti apa-apa, jadi tingkatnya tidak boleh
        sampai MENCURIGAKAN.
        """
        path = self.write("besar.exe", b"MZ" + b"\x00" * (21 * 1024 * 1024))
        findings = self.engine.scan_file(path)
        sizes = [f for f in findings if f.rule == "Ukuran tidak wajar"]
        self.assertTrue(sizes, "aturan ukuran tidak jalan")
        self.assertEqual(sizes[0].severity, "PERLU DIPERIKSA")

    def test_large_text_file_is_not_flagged(self) -> None:
        # Ukuran besar pada berkas bukan-program tidak layak dicatat.
        path = self.write("film.mp4", b"\x00" * (21 * 1024 * 1024))
        self.assertEqual(
            [f for f in self.engine.scan_file(path) if f.rule == "Ukuran tidak wajar"],
            [],
        )

    def test_directory_scan_summary(self) -> None:
        self.write("a.txt", b"biasa\n")
        self.write("sub/b.txt", b"biasa juga\n")
        self.write("sub/eicar.txt", EICAR_BYTES)
        summary = self.engine.scan_directory(self.tmp)
        self.assertEqual(summary.total_files, 3)
        self.assertEqual(summary.scanned_files, 3)
        self.assertGreaterEqual(summary.infected, 1)
        self.assertFalse(summary.stopped)
        self.assertTrue(summary.engines_used)

    def test_cache_makes_second_scan_identical(self) -> None:
        self.write("a.txt", b"biasa\n")
        self.write("eicar.txt", EICAR_BYTES)
        first = self.engine.scan_directory(self.tmp)
        second = self.engine.scan_directory(self.tmp)
        self.assertEqual(second.cached_files, second.total_files)
        self.assertEqual(
            sorted((f.path, f.engine, f.rule) for f in first.findings),
            sorted((f.path, f.engine, f.rule) for f in second.findings),
            "hasil pemindaian ulang berbeda dari yang pertama",
        )
        self.assertEqual(first.infected, second.infected)

    def test_cache_invalidated_when_file_changes(self) -> None:
        path = self.write("a.txt", b"biasa\n")
        self.assertEqual(self.engine.scan_directory(self.tmp).infected, 0)
        with open(path, "wb") as handle:
            handle.write(EICAR_BYTES)
        os.utime(path, (time.time() + 5, time.time() + 5))
        second = self.engine.scan_directory(self.tmp)
        self.assertEqual(second.cached_files, 0)
        self.assertGreaterEqual(second.infected, 1)

    def test_stop_event_halts_scan(self) -> None:
        for index in range(40):
            self.write(f"f{index}.txt", b"biasa\n")
        stop = threading.Event()
        stop.set()
        self.assertTrue(self.engine.scan_directory(self.tmp, stop_event=stop).stopped)

    def test_exclusions_are_skipped(self) -> None:
        self.write("penting/eicar.txt", EICAR_BYTES)
        self.write("lain.txt", b"biasa\n")
        self.engine.exclusions = ["penting"]
        summary = self.engine.scan_directory(self.tmp)
        self.assertEqual(summary.total_files, 1)
        self.assertEqual(summary.infected, 0)

    def test_exclusion_matching_is_case_insensitive(self) -> None:
        self.write("Rahasia/eicar.txt", EICAR_BYTES)
        self.engine.exclusions = ["rahasia"]
        self.assertEqual(self.engine.scan_directory(self.tmp).total_files, 0)

    def test_symlink_loop_does_not_hang(self) -> None:
        self.write("asli.txt", b"biasa\n")
        try:
            os.symlink(self.tmp, os.path.join(self.tmp, "putar"))
        except (OSError, NotImplementedError):
            self.skipTest("tautan simbolik tidak didukung di sini")
        self.assertLess(self.engine.scan_directory(self.tmp).total_files, 10)

    def test_engine_status_report_lists_every_engine(self) -> None:
        names = {item["name"] for item in self.engine.prepare()["engines"]}
        self.assertIn("Hash SHA-256", names)
        self.assertIn("YARA", names)
        self.assertIn("Analisis PE", names)

    def test_findings_are_not_duplicated(self) -> None:
        self.write("eicar.txt", EICAR_BYTES)
        keys = [(f.path, f.rule, f.detail) for f in self.engine.scan_directory(self.tmp).findings]
        self.assertEqual(len(keys), len(set(keys)))

    def test_counts_match_findings(self) -> None:
        self.write("eicar.txt", EICAR_BYTES)
        self.write("Faktur.pdf.exe", b"palsu")
        summary = self.engine.scan_directory(self.tmp)
        self.assertEqual(
            summary.infected, sum(1 for f in summary.findings if f.severity == "MALWARE")
        )
        self.assertEqual(
            summary.suspicious,
            sum(1 for f in summary.findings if f.severity == "MENCURIGAKAN"),
        )


# --------------------------------------------------------------------------- #
# 8. Laporan
# --------------------------------------------------------------------------- #


class TestReport(TempCase):
    def _engine(self, name: str) -> ScanEngine:
        work = tempfile.mkdtemp(prefix=f"sg-{name}-")
        self.addCleanup(shutil.rmtree, work, True)
        engine = ScanEngine(
            database=HashDatabase(os.path.join(work, "r.db")),
            quarantine=Quarantine(os.path.join(work, "q")),
            use_clamav=False,
        )
        self.addCleanup(engine.db.close)
        return engine

    def test_report_contains_summary_and_disclaimer(self) -> None:
        engine = self._engine("r")
        self.write("eicar.txt", EICAR_BYTES)
        text = build_report(engine.scan_directory(self.tmp))
        self.assertIn("LAPORAN PEMINDAIAN", text)
        self.assertIn("EICAR", text.upper())
        # Laporan wajib menyebut keterbatasannya sendiri.
        self.assertIn("BUKAN JAMINAN", text.upper())

    def test_clean_report_states_limits(self) -> None:
        engine = self._engine("r2")
        self.write("biasa.txt", b"biasa\n")
        text = build_report(engine.scan_directory(self.tmp))
        self.assertIn("TIDAK ADA TEMUAN", text)
        self.assertIn("bukan berarti", text.lower())


# --------------------------------------------------------------------------- #
# 9. Pengaturan
# --------------------------------------------------------------------------- #


class TestSettings(TempCase):
    def test_roundtrip(self) -> None:
        settings = Settings()
        settings.malwarebazaar_key = "kunci-uji"
        settings.exclusions = ["C:\\Windows"]
        settings.auto_quarantine = True
        settings.save()

        loaded = Settings.load()
        self.assertEqual(loaded.malwarebazaar_key, "kunci-uji")
        self.assertEqual(loaded.exclusions, ["C:\\Windows"])
        self.assertTrue(loaded.auto_quarantine)

    def test_corrupt_file_falls_back_to_defaults(self) -> None:
        path = Settings.path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write("{rusak")
        self.assertEqual(Settings.load().malwarebazaar_key, "")

    def test_unknown_keys_are_ignored(self) -> None:
        path = Settings.path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            json.dump({"malwarebazaar_key": "a", "kunci_aneh": 1}, handle)
        self.assertEqual(Settings.load().malwarebazaar_key, "a")

    def test_settings_file_is_not_world_readable(self) -> None:
        Settings().save()
        # Berkas ini bisa berisi kunci API, jadi izinnya harus dibatasi.
        self.assertEqual(os.stat(Settings.path()).st_mode & 0o077, 0)


# --------------------------------------------------------------------------- #
# 10. Antarmuka
# --------------------------------------------------------------------------- #


def _safe_destroy(root: tk.Tk) -> None:
    """Hancurkan jendela, abaikan bila sudah hancur.

    Memanggil destroy() dua kali memang melempar TclError - itu perilaku Tk,
    bukan bug program. Pengujian yang menutup jendela sendiri harus tahan
    terhadap hal itu saat pembersihan.
    """
    try:
        root.destroy()
    except tk.TclError:
        pass


def _make_app():
    """Buka jendela ScanGuard untuk pengujian, dengan dialog modal diganti."""
    from scanguard import dialogs, gui

    root = tk.Tk()
    # Jendela sengaja TIDAK disembunyikan (tidak memakai withdraw): jendela yang
    # tidak dipetakan tidak pernah dihitung ukurannya oleh Tk, sehingga
    # winfo_width() bernilai 1 dan uji tata letak kehilangan maknanya.
    # messagebox bersifat modal: di lingkungan tanpa layar ia akan menunggu klik
    # yang tidak akan datang, sehingga pengujian menggantung tanpa pesan.
    patcher = mock.patch.object(gui, "messagebox", mock.Mock())
    patcher.start()
    patcher2 = mock.patch.object(dialogs, "messagebox", mock.Mock())
    patcher2.start()
    return root, gui.ScanGuardApp(root), patcher, patcher2


class TestGui(TempCase):
    def setUp(self) -> None:
        super().setUp()
        try:
            self.root, self.app, self.p1, self.p2 = _make_app()
        except tk.TclError as error:
            self.skipTest(f"tkinter tidak bisa membuka jendela: {error}")
        self.addCleanup(self.p2.stop)
        self.addCleanup(self.p1.stop)
        self.addCleanup(_safe_destroy, self.root)

    def _scan_until_done(self, timeout: float = 120.0) -> int:
        """Jalankan pemindaian sambil melayani jendela. Kembalikan jumlah frame."""
        frames = 0
        deadline = time.time() + timeout
        while self.app.scanning and time.time() < deadline:
            self.app.root.update()
            frames += 1
            time.sleep(0.002)
        self.app.root.update()
        return frames

    def test_widgets_exist(self) -> None:
        for widget in (self.app.choose_btn, self.app.scan_btn, self.app.stop_btn, self.app.log):
            self.assertTrue(widget.winfo_exists())

    def test_buttons_are_not_truncated(self) -> None:
        self.root.update()
        for button in (self.app.choose_btn, self.app.scan_btn, self.app.stop_btn):
            self.assertGreaterEqual(button.winfo_width(), button.winfo_reqwidth())

    def test_log_is_read_only(self) -> None:
        self.app._append_log("teks")
        self.assertEqual(self.app.log.cget("state"), "disabled")

    def test_every_severity_tag_has_a_colour(self) -> None:
        """Setiap tingkat bahaya harus punya warna yang benar-benar terpasang.

        Nama tag tkinter tidak boleh mengandung spasi: Tk akan memecahnya dan
        warnanya tidak terpakai, tanpa pesan error sama sekali.
        """
        configured = set(self.app.log.tag_names())
        for severity, tag in config.SEVERITY_TAGS.items():
            with self.subTest(severity=severity):
                self.assertIn(tag, configured, f"tag {tag} ({severity}) belum diatur")
                self.assertNotIn(" ", tag)

    def test_severity_label_is_not_used_directly_as_tag(self) -> None:
        """Nama tag harus aman untuk Tk, bukan label manusia apa adanya.

        Label manusia boleh berbentuk apa saja; yang penting nama tag yang
        dipakai tidak pernah sama dengan labelnya, dan tidak mengandung spasi.
        """
        configured = set(self.app.log.tag_names())
        for severity, tag in config.SEVERITY_TAGS.items():
            with self.subTest(severity=severity):
                self.assertNotEqual(tag, severity)
                self.assertNotIn(" ", tag)
                self.assertNotIn(severity, configured)

    def test_log_colours_actually_applied_to_text(self) -> None:
        """Buktikan tag warna benar-benar melekat pada teks di log.

        Log dibersihkan lebih dulu karena saat jendela dibuat sudah ada teks
        sambutan, sehingga nomor barisnya tidak bisa dipastikan.
        """
        self.app.clear_log()
        self.app._append_log("bahaya\n", config.SEV_MALWARE)
        self.app._append_log("curiga\n", config.SEV_SUSPICIOUS)
        self.app._append_log("catatan\n", config.SEV_NOTE)
        self.root.update()
        for line, severity in (
            (1, config.SEV_MALWARE),
            (2, config.SEV_SUSPICIOUS),
            (3, config.SEV_NOTE),
        ):
            with self.subTest(line=line):
                tags = set(self.app.log.tag_names(f"{line}.0"))
                self.assertIn(config.SEVERITY_TAGS[severity], tags)

    def test_footer_disclaimer_is_visible_at_minimum_size(self) -> None:
        """Teks keterbatasan harus benar-benar terlihat, bukan terhimpit.

        Widget yang memakai expand=True menyerap seluruh sisa ruang, sehingga
        widget sesudahnya bisa terhimpit sampai tinggi 1 piksel dan teksnya
        hilang - padahal tetap ada di dalam pohon widget. Karena itu tingginya
        diukur, bukan sekadar keberadaannya diperiksa.
        """
        self.root.geometry("880x620")
        self.root.update()
        self.app.footer_label.update_idletasks()
        self.assertGreater(
            self.app.footer_label.winfo_height(),
            10,
            "teks keterbatasan terhimpit sehingga tidak terbaca",
        )

    def test_buttons_fit_at_minimum_size(self) -> None:
        self.root.geometry("880x620")
        self.root.update()
        for button in (self.app.choose_btn, self.app.scan_btn, self.app.stop_btn):
            with self.subTest(button=button.cget("text")):
                self.assertGreaterEqual(button.winfo_width(), button.winfo_reqwidth())

    def test_closing_window_cancels_scheduled_callback(self) -> None:
        """Menutup jendela tidak boleh meninggalkan callback terjadwal.

        Callback yang masih terjadwal pada widget yang sudah dihancurkan membuat
        Tk mencetak 'invalid command name ..._pump_queue' ke stderr.
        """
        self.root.update()
        self.assertIsNotNone(self.app._pump_job)
        self.app.on_close()
        self.assertIsNone(self.app._pump_job)

    def test_invalid_folder_warns_without_crashing(self) -> None:
        self.app.folder_var.set("/folder/yang/tidak/ada")
        self.app.start_scan()
        self.assertFalse(self.app.scanning)
        self.root.update()

    def test_scan_updates_gui_without_freezing(self) -> None:
        """Jendela harus tetap dilayani main thread selama pemindaian."""
        self.write("eicar.txt", EICAR_BYTES)
        self.write("biasa.txt", b"biasa\n")
        self.app.folder_var.set(self.tmp)

        # Pemindaian sungguhan selesai dalam milidetik, jadi terlalu cepat untuk
        # diamati. Logika aslinya tetap dipakai; hanya ditambah jeda kecil.
        original = self.app.engine._scan_file_internal

        def slowed(path, use_cache, with_clamav):
            result = original(path, use_cache, with_clamav)
            time.sleep(0.004)
            return result

        self.app.engine._scan_file_internal = slowed
        self.app.start_scan()
        frames = self._scan_until_done()

        self.assertFalse(self.app.scanning, "pemindaian tidak pernah selesai")
        # Ambangnya rendah karena mesin uji bisa sangat cepat.
        self.assertGreater(frames, 3, "main thread tidak pernah melayani jendela")
        self.assertIsNotNone(self.app.last_summary)

    def test_stop_button_halts_scan(self) -> None:
        for index in range(60):
            self.write(f"f{index}.txt", b"biasa\n")
        self.app.folder_var.set(self.tmp)
        self.app.start_scan()
        self.app.stop_scan()
        self._scan_until_done()
        self.assertFalse(self.app.scanning)
        self.assertTrue(self.app.last_summary.stopped)

    def test_report_available_after_scan(self) -> None:
        self.write("eicar.txt", EICAR_BYTES)
        self.app.folder_var.set(self.tmp)
        self.app.start_scan()
        self._scan_until_done()
        self.assertIsNotNone(self.app.last_summary)
        self.assertIn(
            "LAPORAN PEMINDAIAN", build_report(self.app.last_summary, self.app.engine_status)
        )


# --------------------------------------------------------------------------- #
# 11. Kontras warna (dihitung, bukan dikira-kira)
# --------------------------------------------------------------------------- #


def _relative_luminance(hex_color: str) -> float:
    value = hex_color.lstrip("#")
    channels = [int(value[i : i + 2], 16) / 255 for i in (0, 2, 4)]

    def linear(channel: float) -> float:
        return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(c) for c in channels)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(foreground: str, background: str) -> float:
    first, second = _relative_luminance(foreground), _relative_luminance(background)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


class TestColourContrast(unittest.TestCase):
    """Kontras diuji sebagai angka WCAG, bukan dinilai dari gambar.

    Angka ini deterministik dan tidak bergantung pada font yang terpasang, jadi
    hasilnya sama di komputer mana pun.
    """

    def setUp(self) -> None:
        from scanguard.gui import COLORS

        self.c = COLORS

    def test_text_on_its_background_passes_wcag_aa(self) -> None:
        for foreground, background in [
            ("text", "bg"),
            ("text", "panel"),
            ("muted", "bg"),
            ("muted", "panel"),
            ("danger", "panel"),
            ("warn", "panel"),
            ("note", "panel"),
            ("ok", "panel"),
            ("accent", "panel"),
        ]:
            with self.subTest(pair=f"{foreground}/{background}"):
                ratio = contrast_ratio(self.c[foreground], self.c[background])
                self.assertGreaterEqual(
                    ratio, 4.5, f"{foreground}/{background} hanya {ratio:.2f}:1"
                )

    def test_button_text_passes_wcag_aa(self) -> None:
        for key in ("fill", "fill_active"):
            with self.subTest(button=key):
                ratio = contrast_ratio("#ffffff", self.c[key])
                self.assertGreaterEqual(ratio, 4.5, f"putih/{key} hanya {ratio:.2f}:1")
        for key in ("secondary", "secondary_active"):
            with self.subTest(button=key):
                ratio = contrast_ratio(self.c["text"], self.c[key])
                self.assertGreaterEqual(ratio, 4.5, f"text/{key} hanya {ratio:.2f}:1")
        for key in ("danger_fill", "danger_active"):
            with self.subTest(button=key):
                ratio = contrast_ratio("#ffffff", self.c[key])
                self.assertGreaterEqual(ratio, 4.5, f"putih/{key} hanya {ratio:.2f}:1")

    def test_severity_colours_are_distinguishable(self) -> None:
        colours = [self.c["danger"], self.c["warn"], self.c["note"], self.c["ok"]]
        self.assertEqual(len(set(colours)), len(colours))

    def test_progress_bar_is_visible_against_trough(self) -> None:
        self.assertGreaterEqual(contrast_ratio(self.c["bar"], self.c["panel"]), 1.5)


# --------------------------------------------------------------------------- #
# 12. Berkas paket dan installer
# --------------------------------------------------------------------------- #


class TestPackagingFiles(unittest.TestCase):
    """Periksa berkas build tanpa perlu Windows.

    Kesalahan seperti versi yang tidak ikut diperbarui, atau berkas data yang
    tidak disertakan ke bundel, baru ketahuan setelah .exe dibuat di Windows.
    Pemeriksaan ini menangkapnya jauh lebih awal.
    """

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, *parts: str) -> str:
        with open(os.path.join(self.ROOT, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_required_files_exist(self) -> None:
        for relative in (
            "antivirus.py",
            "ScanGuard.spec",
            "requirements.txt",
            "build_exe.bat",
            "build_installer.bat",
            os.path.join("installer", "ScanGuard.iss"),
            os.path.join("rules", "scanguard.yar"),
            os.path.join("assets", "icon.ico"),
            os.path.join("assets", "icon_256.png"),
        ):
            with self.subTest(file=relative):
                self.assertTrue(
                    os.path.exists(os.path.join(self.ROOT, relative)),
                    f"{relative} tidak ditemukan",
                )

    def test_spec_bundles_assets_and_rules(self) -> None:
        spec = self._read("ScanGuard.spec")
        for needle in ("icon.ico", "icon_256.png", "scanguard.yar"):
            with self.subTest(file=needle):
                self.assertIn(needle, spec)

    def test_spec_declares_engines_as_hidden_imports(self) -> None:
        """yara dan pefile diimpor di dalam fungsi, jadi wajib disebut manual.

        Tanpa keduanya di daftar hiddenimports, .exe tetap terbentuk dan tetap
        berjalan - hanya saja mesin YARA dan analisis PE diam-diam tidak aktif.
        Itu jenis kerusakan yang paling sulit disadari.
        """
        spec = self._read("ScanGuard.spec")
        self.assertIn('hiddenimports.append("yara")', spec)
        self.assertIn('hiddenimports.append("pefile")', spec)

    def test_spec_disables_upx(self) -> None:
        # Pemadatan UPX membuat .exe hasil PyInstaller sering dituduh virus
        # oleh antivirus lain - masalah dukungan yang merepotkan.
        self.assertIn("upx=False", self._read("ScanGuard.spec"))

    def test_spec_has_no_console_window(self) -> None:
        self.assertIn("console=False", self._read("ScanGuard.spec"))

    def test_installer_version_matches_application(self) -> None:
        """Nomor versi di installer harus sama dengan versi di kode."""
        iss = self._read("installer", "ScanGuard.iss")
        self.assertIn(f'#define AppVersion     "{config.APP_VERSION}"', iss)
        self.assertIn(f'VersionInfoVersion={config.APP_VERSION}.0', iss)

    def test_installer_batch_script_names_current_version(self) -> None:
        batch = self._read("build_installer.bat")
        self.assertIn(
            f"ScanGuard-Setup-{config.APP_VERSION}.exe",
            batch,
            "pesan di build_installer.bat menyebut versi yang salah",
        )

    def test_installer_has_required_sections(self) -> None:
        iss = self._read("installer", "ScanGuard.iss")
        for section in ("[Setup]", "[Files]", "[Icons]", "[Run]", "[Languages]"):
            with self.subTest(section=section):
                self.assertIn(section, iss)

    def test_installer_app_id_uses_escaped_brace_form(self) -> None:
        """AppId harus berbentuk {{GUID} - dan itu memang benar, bukan salah.

        Di Inno Setup, `{{` berarti satu kurung kurawal harfiah. Pemeriksa yang
        hanya menghitung kurung akan menyimpulkan berkas ini rusak, padahal
        justru bentuk inilah yang diminta. Yang diperiksa di sini adalah bentuk
        yang benar, bukan keseimbangan kurung.
        """
        iss = self._read("installer", "ScanGuard.iss")
        line = next(l for l in iss.splitlines() if l.startswith("AppId="))
        value = line.split("=", 1)[1].strip()
        self.assertTrue(value.startswith("{{"), f"bentuk AppId salah: {value}")
        self.assertTrue(value.endswith("}"), f"bentuk AppId salah: {value}")
        inner = value[2:-1]
        self.assertRegex(inner, r"^[0-9A-Fa-f-]{36}$", f"bukan GUID: {inner}")

    def test_installer_preserves_quarantine_on_uninstall(self) -> None:
        """Uninstall tidak boleh menghapus folder data pengguna.

        Di dalamnya ada karantina. Kalau ikut terhapus, berkas yang dikarantina
        hilang tanpa sepengetahuan pengguna.
        """
        iss = self._read("installer", "ScanGuard.iss")
        uninstall = iss.split("[UninstallDelete]", 1)[1]
        self.assertNotIn("{localappdata}", uninstall)
        self.assertIn("{app}", uninstall)

    def test_requirements_lists_both_engines(self) -> None:
        requirements = self._read("requirements.txt")
        self.assertIn("yara-python", requirements)
        self.assertIn("pefile", requirements)
        self.assertIn("pyinstaller", requirements.lower())

    def test_entry_point_handles_missing_engine_package(self) -> None:
        # Titik masuk harus menjelaskan kesalahannya, bukan gagal tanpa pesan.
        source = self._read("antivirus.py")
        self.assertIn("_fatal", source)
        self.assertIn("--cek-mesin", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
