import unittest
from pathlib import Path

from benchshield.checklist import evaluate
from benchshield.report import render_markdown
from benchshield.scanner import scan_directory

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_bench"
CLEAN = Path(__file__).resolve().parent / "fixtures" / "clean_bench"


class TestChecklist(unittest.TestCase):
    def test_vulnerable_bench_fails_and_gets_bad_grade(self):
        scan = scan_directory(EXAMPLES)
        result = evaluate(scan.findings)
        self.assertIn(result.grade, ("D", "F"))
        failed_ids = {i[0] for i in result.failed}
        for cid in ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"):
            self.assertIn(cid, failed_ids, f"{cid} should fail on the vulnerable bench")

    def test_clean_bench_gets_grade_a(self):
        scan = scan_directory(CLEAN)
        result = evaluate(scan.findings, config={
            "fresh_snapshot": True, "log_segregation": True})
        self.assertEqual(result.grade, "A")
        self.assertEqual(result.failed, [])

    def test_runtime_items_are_manual_without_config(self):
        result = evaluate([])
        statuses = {i[0]: i[2] for i in result.items}
        self.assertEqual(statuses["C9"], "manual")
        self.assertEqual(statuses["C10"], "manual")
        self.assertEqual(result.grade, "A")

    def test_ten_items_present(self):
        result = evaluate([])
        self.assertEqual(len(result.items), 10)


class TestReport(unittest.TestCase):
    def test_markdown_renders_findings_and_checklist(self):
        scan = scan_directory(EXAMPLES)
        checklist = evaluate(scan.findings)
        md = render_markdown(scan, checklist)
        self.assertIn("# BenchShield Audit Report", md)
        self.assertIn("DATA-LEAK", md)
        self.assertIn("Agent-Eval Checklist", md)
        self.assertIn("Grade", md)

    def test_markdown_with_empty_scan(self):
        class FakeScan:
            root = "x"
            files_scanned = 0
            findings = []

            @property
            def severity_counts(self):
                return {"critical": 0, "high": 0, "medium": 0, "info": 0}

            def sorted_findings(self):
                return []

        class FakeReport:
            runner = agent = "r"
            solved_count, total, rate = 1, 2, 0.5

        checklist = evaluate([])
        md = render_markdown(FakeScan(), checklist, run_reports=[FakeReport()])
        self.assertIn("No vulnerability patterns detected", md)
        self.assertIn("| r | r | 1/2 | 50% |", md)


if __name__ == "__main__":
    unittest.main()
