import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from benchshield.scanner import SEVERITY_RANK, scan_directory

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_bench"
CLEAN = Path(__file__).resolve().parent / "fixtures" / "clean_bench"


class TestScannerOnVulnerableBench(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan_directory(EXAMPLES)

    def test_all_seven_classes_detected(self):
        classes = {f.vuln_class for f in self.result.findings}
        for v in ("V1", "V2", "V3", "V4", "V5", "V6", "V7"):
            self.assertIn(v, classes, f"vulnerability class {v} not detected")

    def test_all_rules_detected(self):
        rules = {f.rule for f in self.result.findings}
        expected = {"ENV-SHARED", "ENV-NET", "DATA-LEAK", "EVAL-CALL",
                    "JUDGE-INJECT", "WEAK-MATCH", "NO-CHECK", "TRUST-OUT"}
        self.assertTrue(expected <= rules, f"missing rules: {expected - rules}")

    def test_findings_have_location_and_severity(self):
        for f in self.result.findings:
            self.assertTrue(f.file)
            self.assertIn(f.severity, SEVERITY_RANK)
            if f.rule != "PARSE-ERROR":
                self.assertGreaterEqual(f.line, 0)
                self.assertTrue(f.remediation)

    def test_data_leak_reports_record_count(self):
        leak = [f for f in self.result.findings if f.rule == "DATA-LEAK"]
        self.assertEqual(len(leak), 1)
        self.assertIn("20 record(s)", leak[0].title)


class TestScannerOnCleanBench(unittest.TestCase):
    def test_no_findings_on_clean_fixture(self):
        result = scan_directory(CLEAN)
        problems = [f for f in result.findings if f.rule != "PARSE-ERROR"]
        self.assertEqual(problems, [], f"false positives: {problems}")

    def test_files_were_scanned(self):
        result = scan_directory(CLEAN)
        self.assertGreaterEqual(result.files_scanned, 3)


class TestScannerEdgeCases(unittest.TestCase):
    def test_missing_directory_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_directory(Path(__file__).parent / "does_not_exist")


class TestScannerRound2Regression(unittest.TestCase):
    """Regression tests for round-2 external code review (2026-09-10)."""

    def _write(self, root, rel, body):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p

    def test_nested_json_tasks_are_detected(self):
        # Round-2 #2: a bundle shaped {"tasks": [...]} was only yielding one
        # V1 finding because the scanner only inspected the top level.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bundle = {
                "benchmark": "demo",
                "tasks": [
                    {"id": "t1", "prompt": "x", "gold": 1},
                    {"id": "t2", "prompt": "y", "gold": 2},
                ],
            }
            self._write(root, "data/tasks.json", json.dumps(bundle))
            result = scan_directory(root)
            leaks = [f for f in result.findings if f.rule == "DATA-LEAK"]
            self.assertEqual(len(leaks), 1)
            self.assertIn("2 record(s)", leaks[0].title)

    def test_nested_json_under_metadata_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bundle = {
                "metadata": {"version": 1},
                "items": [
                    {"id": "t1", "prompt": "x", "answer": "yes"},
                ],
            }
            self._write(root, "items.json", json.dumps(bundle))
            result = scan_directory(root)
            leaks = [f for f in result.findings if f.rule == "DATA-LEAK"]
            self.assertEqual(len(leaks), 1)

    def test_env_shared_with_subpath_sibling_dirs(self):
        # Round-2 #3: agent_dir="ws/agent" and eval_dir="ws/eval" shared a
        # parent; the old equality check missed it.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = {"agent_dir": "ws/agent", "eval_dir": "ws/eval"}
            self._write(root, "config.json", json.dumps(cfg))
            result = scan_directory(root)
            shared = [f for f in result.findings if f.rule == "ENV-SHARED"]
            self.assertEqual(len(shared), 1)
            self.assertIn("ws/agent", shared[0].evidence)
            self.assertIn("ws/eval", shared[0].evidence)

    def test_env_shared_still_flags_identical_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = {"agent_dir": "ws", "eval_dir": "ws"}
            self._write(root, "config.json", json.dumps(cfg))
            result = scan_directory(root)
            shared = [f for f in result.findings if f.rule == "ENV-SHARED"]
            self.assertEqual(len(shared), 1)

    def test_env_shared_not_flagged_for_disjoint_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = {"agent_dir": "agent_ws", "eval_dir": "eval_ws"}
            self._write(root, "config.json", json.dumps(cfg))
            result = scan_directory(root)
            shared = [f for f in result.findings if f.rule == "ENV-SHARED"]
            self.assertEqual(shared, [])


class TestConfigDiagnostics(unittest.TestCase):
    """Round-4 (2026-09-10): dirty config shapes must surface a finding
    instead of being silently swallowed, otherwise an audit tool can
    claim 'no isolation problems' on a bench it never actually read."""

    def _write(self, root, rel, body):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p

    def test_top_level_number_config_emits_finding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config.json", "42")
            result = scan_directory(root)
            nondict = [f for f in result.findings if f.rule == "CONFIG-NONDICT"]
            self.assertEqual(len(nondict), 1)
            self.assertEqual(nondict[0].vuln_class, "V1")

    def test_top_level_string_config_emits_finding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config.json", '"hello"')
            result = scan_directory(root)
            nondict = [f for f in result.findings if f.rule == "CONFIG-NONDICT"]
            self.assertEqual(len(nondict), 1)

    def test_top_level_array_config_emits_finding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config.json", "[1, 2, 3]")
            result = scan_directory(root)
            nondict = [f for f in result.findings if f.rule == "CONFIG-NONDICT"]
            self.assertEqual(len(nondict), 1)

    def test_malformed_json_config_emits_parse_finding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config.json", "{ this is not json")
            result = scan_directory(root)
            parse = [f for f in result.findings if f.rule == "CONFIG-PARSE"]
            self.assertEqual(len(parse), 1)
            self.assertEqual(parse[0].vuln_class, "V0")

    def test_wrong_field_type_emits_finding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config.json",
                        json.dumps({"agent_dir": 42, "allow_network": "yes"}))
            result = scan_directory(root)
            ft = [f for f in result.findings if f.rule == "CONFIG-FIELD-TYPE"]
            self.assertEqual(len(ft), 1)
            self.assertIn("agent_dir", ft[0].evidence)
            self.assertIn("allow_network", ft[0].evidence)

    def test_dirty_configs_do_not_silently_claim_clean(self):
        # The trust violation we are guarding against: a scanner that
        # silently skips 3 bad configs and only flags one good one, leaving
        # the impression that those bad configs were audited and clean.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config_a.json", "42")
            self._write(root, "config_b.json", '"x"')
            self._write(root, "config_c.json", "[1]")
            result = scan_directory(root)
            rules = {f.rule for f in result.findings}
            self.assertIn("CONFIG-NONDICT", rules)
            self.assertGreaterEqual(result.files_scanned, 3)


if __name__ == "__main__":
    unittest.main()
