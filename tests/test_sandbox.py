import tempfile
import unittest
from pathlib import Path

from benchshield.benchdata import generate_tasks
from benchshield.redteam import (
    EvalAlwaysTrue,
    HonestAgent,
    OverwriteChecker,
    PeekAnswers,
    ZeroCapabilityAgent,
)
from benchshield.sandbox import SecureRunner, VulnerableRunner


class TestDemoScanTarget(unittest.TestCase):
    """Round-5 (2026-09-10): `demo --report` used to hard-code the source
    tree's examples/ path and crash with FileNotFoundError after a regular
    `pip install` (examples/ is not part of the installed package)."""

    def test_scan_demo_bench_falls_back_to_generated_bundle(self):
        import tempfile

        import benchshield.__main__ as main_mod
        from benchshield.__main__ import _scan_demo_bench

        # Simulate the installed-package situation: point the module's
        # examples path at a directory that does not exist.
        with tempfile.TemporaryDirectory() as td:
            main_mod._EXAMPLES_OVERRIDE = Path(td) / "no_such_examples"
            try:
                scan, source = _scan_demo_bench(Path(td))
                self.assertIn("generated equivalent bundle", source)
                classes = {f.vuln_class for f in scan.findings}
                for v in ("V1", "V2", "V3", "V4", "V5", "V6", "V7"):
                    self.assertIn(v, classes, f"{v} missing from generated bundle scan")
            finally:
                main_mod._EXAMPLES_OVERRIDE = None

    def test_scan_demo_bench_uses_repo_examples_when_present(self):
        import tempfile

        import benchshield.__main__ as main_mod
        from benchshield.__main__ import _scan_demo_bench

        with tempfile.TemporaryDirectory() as td:
            main_mod._EXAMPLES_OVERRIDE = None
            scan, source = _scan_demo_bench(Path(td))
            real = Path(main_mod.__file__).resolve().parent.parent / "examples" / "vulnerable_bench"
            if real.is_dir():
                self.assertIn("bundled examples", source)
            else:  # running from an installed package without examples
                self.assertIn("generated equivalent bundle", source)
            self.assertGreater(len(scan.findings), 0)


class TestVulnerableRunnerRegression(unittest.TestCase):
    """Regression tests for issues found in external code review (2026-09-10)."""

    def setUp(self):
        self.tasks = generate_tasks(5, seed=99)
        self.tmp = Path(tempfile.mkdtemp(prefix="benchshield_regr_"))

    def test_no_state_leak_between_runs_on_same_runner(self):
        # Issue #1: a tampering agent used to poison the workspace for every
        # later agent on the same runner instance.
        runner = VulnerableRunner(self.tasks, self.tmp / "ws")
        tamper_report = runner.run(ZeroCapabilityAgent([OverwriteChecker()]))
        self.assertEqual(tamper_report.solved_count, tamper_report.total)
        honest_report = runner.run(HonestAgent())
        self.assertEqual(honest_report.solved_count, honest_report.total)
        mislabeled = [r for r in honest_report.results
                      if any("V7" in n for n in r.notes)]
        self.assertEqual(mislabeled, [],
                         "honest agent must not inherit V7 notes from a previous run")

    def test_corrupted_checker_does_not_crash_run(self):
        # Issue #2: a syntactically broken checker.py used to abort the whole
        # evaluation with SyntaxError. Now: task fails, run continues.
        class Crasher:
            name = "crasher"

            def act(self, task_public, workspace):
                (workspace / "checker.py").write_text("def check(:", encoding="utf-8")
                return "not python"  # not evaluable -> falls back to checker

        runner = VulnerableRunner(self.tasks, self.tmp / "ws2")
        report = runner.run(Crasher())  # must not raise
        self.assertEqual(len(report.results), report.total)
        self.assertEqual(report.solved_count, 0)
        crashed_notes = [r for r in report.results
                         if any("evaluator raised" in n for n in r.notes)]
        self.assertEqual(len(crashed_notes), report.total)

    def test_eval_payload_scores_full_on_vulnerable_runner(self):
        # V3 is now faithfully reproduced: the response "True" passes through
        # eval() without the gold answer ever being consulted.
        report = VulnerableRunner(self.tasks, self.tmp / "ws3").run(
            ZeroCapabilityAgent([EvalAlwaysTrue()]))
        self.assertEqual(report.solved_count, report.total)


class TestVulnerableRunner(unittest.TestCase):
    def setUp(self):
        self.tasks = generate_tasks(8, seed=11)
        self.tmp = Path(tempfile.mkdtemp(prefix="benchshield_vuln_"))

    def test_honest_agent_full_score(self):
        report = VulnerableRunner(self.tasks, self.tmp / "v_honest").run(HonestAgent())
        self.assertEqual(report.solved_count, report.total)

    def test_peek_exploit_full_score(self):
        agent = ZeroCapabilityAgent([PeekAnswers()])
        report = VulnerableRunner(self.tasks, self.tmp / "v_peek").run(agent)
        self.assertEqual(report.solved_count, report.total)

    def test_checker_overwrite_exploit_full_score(self):
        agent = ZeroCapabilityAgent([OverwriteChecker()])
        report = VulnerableRunner(self.tasks, self.tmp / "v_tamper").run(agent)
        self.assertEqual(report.solved_count, report.total)
        self.assertEqual(report.extras["checker_tampered_tasks"], report.total)


class TestSecureRunner(unittest.TestCase):
    def setUp(self):
        self.tasks = generate_tasks(8, seed=12)
        self.tmp = Path(tempfile.mkdtemp(prefix="benchshield_sec_"))

    def test_honest_agent_full_score(self):
        with SecureRunner(self.tasks, self.tmp / "s_honest") as runner:
            report = runner.run(HonestAgent())
        self.assertEqual(report.solved_count, report.total)

    def test_all_exploit_combos_score_zero(self):
        combos = [
            [PeekAnswers()],
            [OverwriteChecker()],
            [PeekAnswers(), OverwriteChecker(), EvalAlwaysTrue()],
        ]
        for i, payloads in enumerate(combos):
            with self.subTest(payloads=[p.name for p in payloads]):
                with SecureRunner(self.tasks, self.tmp / f"s_exploit_{i}") as runner:
                    report = runner.run(ZeroCapabilityAgent(payloads))
                self.assertEqual(report.solved_count, 0)

    def test_tamper_attempt_detected_and_logged(self):
        with SecureRunner(self.tasks, self.tmp / "s_tamper") as runner:
            report = runner.run(ZeroCapabilityAgent([OverwriteChecker()]))
        self.assertEqual(report.extras["tamper_attempts"], report.total)
        agent_log = (self.tmp / "s_tamper" / "logs" / "agent.log").read_text(encoding="utf-8")
        self.assertIn("checker.py", agent_log)
        eval_log = (self.tmp / "s_tamper" / "logs" / "eval.log").read_text(encoding="utf-8")
        self.assertIn('"pass": false', eval_log)

    def test_no_gold_in_agent_workspace(self):
        seen_files = []

        class SpyAgent:
            name = "spy"

            def act(self, task_public, workspace):
                seen_files.extend(p.name for p in Path(workspace).iterdir())
                return "0"

        with SecureRunner(self.tasks, self.tmp / "s_spy") as runner:
            report = runner.run(SpyAgent())
        self.assertEqual(report.solved_count, 0)
        self.assertNotIn("tasks.json", seen_files)
        self.assertNotIn("checker.py", seen_files)


class TestRound2Regression(unittest.TestCase):
    """Regression tests for round-2 external code review (2026-09-10)."""

    def setUp(self):
        self.tasks = generate_tasks(5, seed=42)
        self.tmp = Path(tempfile.mkdtemp(prefix="benchshield_r2_"))

    def test_eval_fallback_only_after_checker_rejects(self):
        # Round-2 #1: "True" used to score 20/20 by itself. Now the checker
        # runs first; eval() is only a fallback, so a single 'I have no idea'
        # can no longer steal the win on every task.
        class AlwaysOne:
            name = "always-one"

            def act(self, task_public, workspace):
                return "1"

        report = VulnerableRunner(self.tasks, self.tmp / "v_one").run(AlwaysOne())
        # The 'true' truthy payload (EvalAlwaysTrue) still wins because the
        # checker rejects "True" and eval() rescues it as a fallback.
        eval_report = VulnerableRunner(self.tasks, self.tmp / "v_eval").run(
            ZeroCapabilityAgent([EvalAlwaysTrue()]))
        self.assertEqual(eval_report.solved_count, eval_report.total)
        # But a plain numeric string ("1") is rejected by both branches and
        # no longer rides the V3 express lane.
        self.assertLess(report.solved_count, report.total,
                        "a truthy-but-incorrect response must not auto-pass "
                        "via the V3 eval() fallback on VulnerableRunner")

    def test_eval_fallback_is_documented_in_result_notes(self):
        report = VulnerableRunner(self.tasks, self.tmp / "v_notes").run(
            ZeroCapabilityAgent([EvalAlwaysTrue()]))
        noted = [r for r in report.results
                 if any("V3 eval() fallback" in n for n in r.notes)]
        self.assertEqual(len(noted), report.total)

    def test_wrong_numeric_answer_does_not_trigger_eval_fallback(self):
        # Round-3 fix: a *wrong* honest-looking answer ("999" for a math task
        # whose gold is "772") must NOT be silently rescued by the V3 eval()
        # fallback. Previously any response with a "+" character would pass.
        class WrongButNumeric:
            name = "wrong-but-numeric"

            def act(self, task_public, workspace):
                # Honest attempt at a math answer, but wrong.
                return "999"

        report = VulnerableRunner(self.tasks, self.tmp / "v_wrong").run(WrongButNumeric())
        self.assertEqual(report.solved_count, 0,
                         "a wrong numeric answer must fail on the checker, "
                         "not be silently rescued by eval()")
        rescued = [r for r in report.results
                   if any("V3 eval() fallback" in n for n in r.notes)]
        self.assertEqual(rescued, [],
                         "no task should have triggered the eval() fallback")

    def test_eval_payload_still_beats_vulnerable_runner(self):
        # The whole point of the eval() fallback: a payload that cannot be
        # parsed as an honest answer shape ("1+1" sent against a numeric
        # gold like "772") still has to win, because that is the bug the
        # V3 class documents.
        report = VulnerableRunner(self.tasks, self.tmp / "v_eval").run(
            ZeroCapabilityAgent([EvalAlwaysTrue()]))
        self.assertEqual(report.solved_count, report.total)

    def test_secure_runner_detects_task_txt_overwrite(self):
        # Round-2 #4: overwriting task.txt in place used to leave
        # tamper_attempts at 0. Now a content hash diff is counted.
        class SneakyOverwrite:
            name = "sneaky-overwrite"

            def act(self, task_public, workspace):
                (workspace / "task.txt").write_text("malicious", encoding="utf-8")
                return "I have no idea."

        with SecureRunner(self.tasks, self.tmp / "s_overwrite") as runner:
            report = runner.run(SneakyOverwrite())
        self.assertEqual(report.extras["tamper_attempts"], report.total)
        noted = [r for r in report.results
                 if any("task.txt was overwritten in place" in n for n in r.notes)]
        self.assertEqual(len(noted), report.total)
        agent_log = (self.tmp / "s_overwrite" / "logs" / "agent.log").read_text(encoding="utf-8")
        self.assertIn('"task_overwritten": true', agent_log)


if __name__ == "__main__":
    unittest.main()
