import json
import tempfile
import unittest
from pathlib import Path

from benchshield.benchdata import generate_tasks, public_view
from benchshield.redteam import (
    EvalAlwaysTrue,
    HonestAgent,
    OverwriteChecker,
    PeekAnswers,
    ZeroCapabilityAgent,
)


class TestPayloads(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="benchshield_rt_"))
        self.tasks = generate_tasks(5, seed=3)
        (self.tmp / "tasks.json").write_text(json.dumps(self.tasks), encoding="utf-8")

    def test_peek_returns_gold_when_tasks_file_present(self):
        payload = PeekAnswers()
        task = public_view(self.tasks[0])
        self.assertEqual(payload.respond(self.tmp, task), self.tasks[0]["gold"])

    def test_peek_returns_none_without_tasks_file(self):
        empty = Path(tempfile.mkdtemp(prefix="benchshield_rt_empty_"))
        self.assertIsNone(PeekAnswers().respond(empty, public_view(self.tasks[0])))

    def test_peek_returns_none_for_unknown_task(self):
        task = {"id": "task-999"}
        self.assertIsNone(PeekAnswers().respond(self.tmp, task))

    def test_overwrite_checker_deploys_file(self):
        OverwriteChecker().deploy(self.tmp, {})
        src = (self.tmp / "checker.py").read_text(encoding="utf-8")
        self.assertIn("return True", src)

    def test_eval_payload_returns_a_python_expression(self):
        # Round-2 fix: V3 reproduction now returns a *Python expression*
        # ("1+1") so it cannot be confused with a literal answer. The
        # evaluator's eval() is what gives it meaning.
        out = EvalAlwaysTrue().respond(self.tmp, {})
        self.assertIsInstance(out, str)
        self.assertNotEqual(out.strip(), "")

    def test_honest_agent_solves(self):
        agent = HonestAgent()
        task = public_view(self.tasks[0])
        self.assertEqual(agent.act(task, self.tmp), self.tasks[0]["gold"])

    def test_zero_capability_falls_back_to_no_idea(self):
        agent = ZeroCapabilityAgent([])
        self.assertEqual(agent.act(public_view(self.tasks[0]), self.tmp), "I have no idea.")


if __name__ == "__main__":
    unittest.main()
