"""Tests for SWE-bench / Terminal-Bench adapters and scanner integration."""
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from benchshield.adapters import (
    AdapterError,
    load_swebench,
    load_terminalbench,
    looks_like_swebench,
)
from benchshield.scanner import scan_directory


def _make_swebench_file(path, n=2):
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps({
                "instance_id": f"astropy__astropy-{1100 + i}",
                "problem_statement": f"Fix bug number {i}",
                "patch": f"diff --git a/file{i}.py b/file{i}.py\n+fixed {i}",
                "test_patch": f"diff --git a/test_{i}.py\n+assert fixed",
                "repo": "org/repo",
                "base_commit": "abc123",
            }) + "\n")
    return path


class TestSwebenchAdapter(unittest.TestCase):
    def test_load(self):
        with tempfile.TemporaryDirectory() as td:
            f = _make_swebench_file(Path(td) / "instances.jsonl")
            tasks = load_swebench(f)
            self.assertEqual(len(tasks), 2)
            self.assertEqual(tasks[0].id, "astropy__astropy-1100")
            self.assertIn("Fix bug", tasks[0].prompt)
            self.assertIn("diff --git", tasks[0].gold)
            self.assertEqual(tasks[0].gold_kind, "patch")
            # public view never leaks gold
            pv = tasks[0].public_view()
            self.assertNotIn("patch", json.dumps(pv))

    def test_missing_fields_raise(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bad.jsonl"
            f.write_text('{"instance_id": "x"}\n', encoding="utf-8")
            with self.assertRaises(AdapterError):
                load_swebench(f)

    def test_empty_file_raises(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "empty.jsonl"
            f.write_text("\n", encoding="utf-8")
            with self.assertRaises(AdapterError):
                load_swebench(f)

    def test_signature_detection(self):
        recs = [{"instance_id": "a", "problem_statement": "p", "patch": "d"},
                {"instance_id": "b", "problem_statement": "q", "patch": "e"}]
        self.assertTrue(looks_like_swebench(recs))
        self.assertFalse(looks_like_swebench([{"prompt": "x", "gold": "y"}]))
        self.assertFalse(looks_like_swebench([]))


class TestSwebenchScan(unittest.TestCase):
    def test_swebench_data_file_flags_data_leak(self):
        # The gold fields are 'patch'/'test_patch', not 'gold' — the scanner
        # must still recognize them via the format signature.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_swebench_file(root / "instances.jsonl")
            result = scan_directory(root)
            leaks = [f for f in result.findings if f.rule == "DATA-LEAK"]
            self.assertEqual(len(leaks), 1)
            self.assertIn("SWE-bench gold patches", leaks[0].title)
            self.assertIn("2 record(s)", leaks[0].title)


class TestTerminalBenchAdapter(unittest.TestCase):
    def _make_tb_dir(self, root):
        t1 = root / "hello-world"
        t1.mkdir(parents=True)
        (t1 / "task.yaml").write_text(textwrap.dedent("""
            instruction: Print hello world to stdout
            parser:
              name: pytest
        """), encoding="utf-8")
        (t1 / "solution.sh").write_text("#!/bin/bash\necho 'hello world'\n",
                                        encoding="utf-8")
        return root

    def test_load(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._make_tb_dir(Path(td))
            tasks = load_terminalbench(root)
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0].id, "hello-world")
            self.assertEqual(tasks[0].gold_kind, "solution-script")
            self.assertIn("hello world", tasks[0].prompt)
            self.assertIn("echo", tasks[0].gold)

    def test_missing_solution_raises(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "t" / "no-sol"
            d.mkdir(parents=True)
            (d / "task.yaml").write_text("instruction: do a thing\n",
                                         encoding="utf-8")
            with self.assertRaises(AdapterError):
                load_terminalbench(Path(td) / "t")

    def test_missing_task_yaml_raises(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "t" / "empty"
            d.mkdir(parents=True)
            with self.assertRaises(AdapterError):
                load_terminalbench(Path(td) / "t")


if __name__ == "__main__":
    unittest.main()
