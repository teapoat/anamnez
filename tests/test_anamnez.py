import ast
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from hashlib import sha256
from io import BytesIO, StringIO
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "anamnez"))
import build_portable
import evtx_tl
import health
import health_input
import wer_info
from evtx_read import Event, event_details, records


AT = datetime(2026, 11, 8, 12)
REPORT = "12345678-1234-1234-1234-123456789abc"
LEGACY_REPORT = "110826-12345-01"


def system(number, provider, event_id, data=None, stamp=AT):
    data = data or {}
    return Event(number, stamp, "System", provider, event_id, data, list(data.values()))


def boot(number=10):
    return system(number, "Microsoft-Windows-Kernel-General", 12)


def power(number=11, code="278", stamp=AT):
    return system(number, "Microsoft-Windows-Kernel-Power", 41,
                  {"bugcheckcode": code, "bugcheckparameter1": "0xc"}, stamp)


def bugcheck(number=12, report_id=REPORT, stamp=AT):
    return system(number, "Microsoft-Windows-WER-SystemErrorReporting", 1001,
                  {"param1": "0x116 (0x0000000c, 0x0, 0x0, 0x0)", "param3": report_id}, stamp)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "Capture with spaces"
        self.root.mkdir()
        self.write("00-summary.txt", "anamnez.ps1 - collected 2026-11-10 17:00:00\r\n"
                   "Host         : TEST   user: TEST\\user\r\n"
                   "Time zone    : UTC+05:00, offset now 05:00:00\r\n"
                   "Event logs (records  channel):\r\n  1  System\r\n  0  Application\r\n\r\n"
                   "Failed steps: 0\r\n")

    def write(self, relative, contents):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents.encode("utf-8") if isinstance(contents, str) else contents)
        return target

    def manifest(self):
        lines = [f"{sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.root).as_posix()}"
                 for path in sorted(self.root.rglob("*")) if path.is_file() and path.name != "00-manifest.sha256"]
        self.write("00-manifest.sha256", "\n".join(lines) + "\n")

    def test_summary_counts_and_bad_hash(self):
        self.write("evt/System.evtx", b"first")
        self.manifest()
        self.write("evt/System.evtx", b"edited")
        capture = health_input.Capture(self.root)
        self.assertEqual(capture.integrity, "failed")
        self.assertEqual(capture.metadata["host"], "TEST")
        self.assertEqual(capture.collected, datetime(2026, 11, 10, 12))
        self.assertEqual(capture.log_counts, {"System": 1, "Application": 0})
        self.assertEqual(capture.read_events("evt/System.evtx", "System"), [])
        self.assertEqual(capture.sources["System"]["status"], "unreadable")

    def test_wer_utf16_without_bom_and_legacy_ids(self):
        path = self.write("wer/Kernel_sample.aaaaaaaa.wer",
                          f"EventType=BlueScreen\r\nReportIdentifier={REPORT}\r\n"
                          f"IntegratorReportIdentifier={LEGACY_REPORT}\r\n".encode("utf-16-le"))
        rep = wer_info.from_wer(path)
        self.assertEqual(rep.etype, "BlueScreen")
        self.assertIn(LEGACY_REPORT, rep.report_ids)
        self.assertEqual(rep.sigs, [])
        fields = ["", "0", "BlueScreen", "No response", "0"] + [""] * 10
        fields += ["", r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive\Kernel_sample.aaaaaaaa",
                   "", "0", LEGACY_REPORT, "0"]
        event = Event(15, AT, "Application", "Windows Error Reporting", 1001, {},
                      ["\0".join(fields).encode("utf-16-le").hex()])
        mirror = wer_info.from_event(event)
        self.assertEqual(mirror.rid, LEGACY_REPORT)
        self.assertEqual(mirror.sigs, [])
        capture = health_input.Capture(self.root)
        primary = health.system_evidence([boot(), power(), bugcheck(report_id=LEGACY_REPORT)], capture)
        wer = health.wer_episodes([health.wer_evidence(rep, "wer/sample.wer"),
                                   health.wer_evidence(mirror, "evt/Application.evtx")])
        episodes, ambiguous = health.correlate(primary, wer, False)
        self.assertFalse(ambiguous)
        self.assertEqual(len(episodes), 1)
        self.assertEqual(len(episodes[0].evidence), 4)

    def test_missing_wer_and_corrupt_evtx_are_distinct(self):
        self.write("evt/System.evtx", b"truncated")
        report = health.build_report(self.root)
        self.assertEqual(report["integrity"], "missing")
        self.assertEqual(report["sources"]["System"]["status"], "unreadable")
        self.assertEqual(report["sources"]["WER files"]["status"], "missing")
        self.assertEqual(report["sections"]["OS and power"], "no_data")

    def test_healthy_input_with_empty_logs_has_no_evidence(self):
        self.write("evt/System.evtx", b"ElfFile\0" + bytes(4088))
        self.write("evt/Application.evtx", b"ElfFile\0" + bytes(4088))
        self.write("00-summary.txt", "Event logs (records  channel):\n  0  System\n  0  Application\n")
        self.manifest()
        report = health.build_report(self.root)
        self.assertEqual(report["sources"]["System"]["status"], "empty")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["sections"]["Storage"], "no_data")

    def test_manifest_ignores_unhashed_journal_but_flags_unlisted_events(self):
        self.manifest()
        self.write("00-journal.txt", "17:00:00  Collection started")
        self.write("evt/System.evtx", b"ElfFile\0" + bytes(4088))
        capture = health_input.Capture(self.root)
        self.assertEqual(capture.integrity, "verified")
        capture.read_events("evt/System.evtx", "System")
        self.assertIn("File is absent from the manifest", capture.sources["System"]["issues"])

    def test_report_output_and_html_escape(self):
        self.write("00-summary.txt", "Host : <script>payload</script>\nFailed steps: 0\n")
        result = self.root.parent / "reports"
        self.assertEqual(health.main([str(self.root), "-o", str(result)]), 0)
        self.assertEqual({path.name for path in result.iterdir()}, {"health.txt", "health.html", "health.json"})
        self.assertIn("Windows health report", (result / "health.txt").read_text())
        self.assertIn("&lt;script&gt;payload&lt;/script&gt;", (result / "health.html").read_text())
        self.assertEqual(json.loads((result / "health.json").read_text())["schema_version"], 1)
        self.assertEqual(health.main([str(self.root), "-o", str(result)]), 2)
        self.assertEqual(health.main([str(self.root), "-o", str(self.root / "reports")]), 2)

    def test_reports_keep_recorded_event_times_when_clock_is_suspect(self):
        capture = health_input.Capture(self.root)
        report = health.build_report(self.root)
        report["clock"]["status"] = "suspect"
        events = [boot(), power(), bugcheck(stamp=AT + timedelta(seconds=6)),
                  boot(19), power(20, code="0", stamp=None)]
        episodes, _ = health.correlate(health.system_evidence(events, capture), [], False)
        report["findings"] = health.findings(episodes, False, capture.collected)
        report["sections"]["OS and power"] = "critical"
        result = self.root.parent / "dated"
        health.write_reports(report, result)
        for filename in ("health.txt", "health.html"):
            with self.subTest(filename=filename):
                contents = (result / filename).read_text()
                self.assertIn("2026-11-08 12:00:00 UTC", contents)
                self.assertIn("2026-11-08 12:00:06 UTC", contents)
                self.assertIn("Time unavailable", contents)
                self.assertIn("Episode 1", contents)
                self.assertIn("may be incorrect", contents)
                self.assertIn("Startup after an unclean shutdown", contents)
                self.assertIn("Windows failed to recover the display driver", contents)
                self.assertNotIn("unknown to unknown", contents)
        html = (result / "health.html").read_text()
        self.assertIn('<details class="finding stripe critical" open>', html)
        self.assertIn('<details class="finding stripe warning">', html)
        self.assertNotIn('<details class="finding stripe warning" open>', html)
        self.assertIn('1 episode · 2 rows', html)
        self.assertIn('1 episode · 1 row', html)
        self.assertEqual(html.count('class="record-time"'), 3)

    def test_reports_show_explicit_smart_status_and_file(self):
        self.write("info/smart-sda.txt", "Device Model: Test ATA\nSMART overall-health self-assessment test result: PASSED\n")
        self.write("info/smart-sdb.txt", "Model Number: Test NVMe\nSMART overall-health self-assessment test result: FAILED!\n")
        self.write("info/smart-sdc.txt", "Product: Test VM\nSMART support is: Unavailable\n")
        self.write("info/smart-scan.txt", "/dev/sda\n")
        self.manifest()
        report = health.build_report(self.root)
        self.assertEqual(report["sources"]["SMART files"]["records"], 3)
        self.assertEqual(report["sections"]["Storage"], "critical")
        self.assertEqual([item["status"] for item in report["smart"]], ["passed", "failed", "unavailable"])
        html = health.report_html(report)
        self.assertIn("Test ATA: Overall check passed (PASSED)", html)
        self.assertIn("Test NVMe: Overall check failed (FAILED!)", html)
        self.assertIn("Test VM: Overall status unavailable", html)
        self.assertIn("info/smart-sdc.txt", html)

    @unittest.skipUnless(shutil.which("7z") or shutil.which("7zz"), "7-Zip is optional")
    def test_real_archive_with_spaces(self):
        self.manifest()
        archive = self.root.parent / "capture with spaces.7z"
        subprocess.run([shutil.which("7z") or shutil.which("7zz"), "a", str(archive), self.root.name],
                       cwd=self.root.parent, check=True, capture_output=True)
        with health_input.capture_folder(archive) as root:
            self.assertEqual(health.build_report(root)["integrity"], "verified")
        self.assertTrue(archive.is_file())


class FindingTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.capture = health_input.Capture(Path(temp.name))

    def classify(self, events, reports=(), clock=True):
        evidence = health.system_evidence(events, self.capture)
        wer = health.wer_episodes([health.wer_evidence(rep, "wer/test.wer") for rep in reports])
        episodes, ambiguous = health.correlate(evidence, wer, clock and not self.capture.clock_notes)
        return health.findings(episodes, clock and not self.capture.clock_notes, AT + timedelta(days=1)), ambiguous

    def test_power_41_decimal_and_dump_error_with_no_wer(self):
        dump = system(13, "volmgr", 161)
        findings, _ = self.classify([boot(), power(), dump])
        self.assertEqual(len(findings), 1)
        row, = findings
        self.assertEqual((row["kind"], row["code"], row["episodes"]), ("bugcheck", "0x116", 1))
        self.assertEqual((row["event_records"], row["related_dump_errors"]), (2, 1))

    def test_system_and_wer_copies_are_one_episode(self):
        rep = wer_info.Rep("wer", AT, "BlueScreen", ["116", "c"], REPORT, [])
        findings, _ = self.classify([boot(), power(), bugcheck()], [rep])
        row, = findings
        self.assertEqual((row["episodes"], row["event_records"], row["report_files"]), (1, 2, 1))

    def test_zero_bugcheck_and_wrong_provider(self):
        fake = system(12, "Another provider", 41, {"bugcheckcode": "278"})
        findings, _ = self.classify([boot(), power(code="0"), fake])
        self.assertEqual([row["kind"] for row in findings], ["unexpected_shutdown"])

    def test_live_event_and_distinct_matching_signatures(self):
        reps = [wer_info.Rep("wer", AT, "LiveKernelEvent", ["141", "1"], REPORT, []),
                wer_info.Rep("wer", AT + timedelta(seconds=1), "LiveKernelEvent", ["10000141", "1"], "other", []),
                wer_info.Rep("wer", AT, "LiveKernelEvent", ["141", "1"], REPORT, [])]
        findings, _ = self.classify([], reps)
        row, = findings
        self.assertEqual((row["kind"], row["code"], row["episodes"], row["report_files"]),
                         ("live_kernel", "0x141", 2, 3))
        self.assertIn("Live kernel event", wer_info.kernel_block(reps, set())[0])

    def test_clock_prevents_time_only_merge_and_windows(self):
        rep = wer_info.Rep("wer", AT, "BlueScreen", ["116", "c"], "", [])
        findings, _ = self.classify([power(stamp=None), bugcheck()], [rep], clock=False)
        row, = findings
        self.assertEqual(row["episodes"], 3)
        self.assertEqual(row["windows_days"], {"7": None, "30": None})
        self.assertIsNone(row["observed_first_utc"])

    def test_bad_block_never_assigned_to_system_drive(self):
        event = system(42, "disk", 7, {"device": r"\Device\Harddisk1\DR4"})
        findings, _ = self.classify([event])
        row, = findings
        self.assertEqual(row["subject"], r"\Device\Harddisk1\DR4")
        self.assertIn("Confirm the physical disk", row["next_check"])

    def test_ambiguous_power_matches_are_kept_separate(self):
        findings, ambiguous = self.classify([boot(), power(), power(number=12), bugcheck(number=13)])
        self.assertTrue(ambiguous)
        self.assertEqual(findings[0]["episodes"], 3)


class ParserTests(unittest.TestCase):
    def test_windows_filetime_with_seven_fractional_digits(self):
        self.assertEqual(health_input.utc("2026-11-08T17:01:02.3456789+05:00"),
                         datetime(2026, 11, 8, 12, 1, 2, 345678))

    def test_event_namespace_and_named_wer(self):
        event = event_details(12, None, '<Event xmlns="urn:test"><System><Channel>Application</Channel>'
                              '<Provider Name="Windows Error Reporting"/><EventID>1001</EventID></System>'
                              '<EventData><Data Name="EventName">LiveKernelEvent</Data><Data Name="P1">141</Data>'
                              '<Data Name="AttachedFiles">first &amp; second</Data></EventData></Event>')
        report = wer_info.from_event(event)
        self.assertEqual(wer_info.kernel_code(report), 0x141)
        self.assertEqual(report.files, ["first & second"])

    def test_invalid_evtx_header_is_reported(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "System.evtx"
            path.write_bytes(b"any text")
            issues = []
            self.assertEqual(list(records(path, on_issue=issues.append)), [])
        self.assertEqual(issues, ["Invalid or incomplete EVTX file header"])

    def test_timeline_keeps_undated_event(self):
        xml = '<Event><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>41</EventID></System></Event>'
        for arguments in ([], ["--hist"]):
            with self.subTest(arguments=arguments), patch.object(sys, "argv", ["timeline", "test.evtx", *arguments]), \
                    patch.object(evtx_tl, "records", return_value=iter([(3, None, xml)])), redirect_stdout(StringIO()) as out:
                evtx_tl.main()
                self.assertIn("time unknown", out.getvalue())

    def test_timeline_defaults_to_utc(self):
        xml = '<Event><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>41</EventID></System></Event>'
        with patch.object(sys, "argv", ["timeline", "test.evtx"]), \
                patch.object(evtx_tl, "records", return_value=iter([(3, AT, xml)])), redirect_stdout(StringIO()) as out:
            evtx_tl.main()
            self.assertIn("11-08 12:00:00", out.getvalue())


class PortableTests(unittest.TestCase):
    def test_public_kit_includes_both_runtimes_without_autoruns(self):
        downloads = [b"7zip"]
        for version in ("3.13", "3.8"):
            fake_python = BytesIO()
            with ZipFile(fake_python, "w") as runtime:
                runtime.writestr("python.exe", version.encode())
                runtime.writestr("LICENSE.txt", b"upstream license")
            downloads.append(fake_python.getvalue())
        with TemporaryDirectory() as temp, patch.object(
                build_portable, "download_verified", side_effect=downloads):
            output = Path(temp) / "test-kit"
            tools_dir = Path(temp) / "tools"
            files = {"smartmontools/bin/smartctl.exe": b"smartctl",
                     "smartmontools/bin/drivedb.h": b"drive database",
                     "smartmontools/doc/COPYING.txt": b"smartmontools license",
                     "smartmontools-7.5.tar.gz": b"smartmontools source"}
            for name, content in files.items():
                path = tools_dir / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            with ZipFile(tools_dir / "Autoruns.zip", "w") as source:
                source.writestr("autorunsc64.exe", b"autorunsc")
                source.writestr("Eula.txt", b"Sysinternals license")
            build_portable.build_kit(output, tools_dir)
            self.assertEqual([path.name for path in output.iterdir()], ["Anamnez-Windows-x64.zip"])
            with ZipFile(output / "Anamnez-Windows-x64.zip") as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.read("LICENSE"), (build_portable.HERE.parents[1] / "LICENSE").read_bytes())
                for version in ("3.13", "3.8"):
                    directory = "anamnez/tools/python/" + version
                    self.assertEqual(archive.read(directory + "/python.exe"), version.encode())
                    self.assertEqual(archive.read(directory + "/LICENSE.txt"), b"upstream license")
                self.assertEqual(archive.read("anamnez/tools/7zip/7zr.exe"), b"7zip")
                self.assertFalse(any(name.casefold().startswith("anamnez/tools/autoruns/")
                                     for name in archive.namelist()))
                self.assertIn(b"anamnez\\tools\\autoruns", archive.read("START.txt"))
                for name, content in files.items():
                    self.assertEqual(archive.read("anamnez/tools/smartmontools/" + Path(name).name), content)
                self.assertIn(b"-FromMenu", archive.read("diagnostics.bat"))
                self.assertIn(b"health.html", archive.read("anamnez/anamnez.ps1"))
                for file in ("health.py", "health_input.py", "wer_info.py", "evtx_read.py"):
                    ast.parse(archive.read("anamnez/" + file), filename=file, feature_version=(3, 8))


if __name__ == "__main__":
    unittest.main()
