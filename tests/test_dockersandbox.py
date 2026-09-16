"""Tests for the Docker task sandbox.

Docker-dependent tests auto-skip when the daemon is not available, so the
suite stays green on zero-Docker machines and CI.
"""
import unittest

from benchshield.dockersandbox import (
    DockerRunner,
    DockerSandbox,
    DockerUnavailableError,
)
from benchshield.benchdata import generate_tasks
from benchshield.redteam import HonestAgent, PeekAnswers, ZeroCapabilityAgent

import tempfile
from pathlib import Path


@unittest.skipUnless(DockerSandbox().available(), "docker not available")
class TestDockerSandbox(unittest.TestCase):
    def test_exact_match_evaluator_in_container(self):
        sb = DockerSandbox()
        r = sb.evaluate("42", "42")
        self.assertTrue(r.ok)
        self.assertIn('"pass": true', r.stdout)

        r2 = sb.evaluate("41", "42")
        self.assertTrue(r2.ok)
        self.assertIn('"pass": false', r2.stdout)

    def test_container_has_no_network(self):
        # Kernel-level C2: even a raw socket fails inside the container.
        sb = DockerSandbox()
        r = sb.run(["python", "-c",
                    "import socket\n"
                    "try:\n"
                    "    socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
                    "    print('NETWORKED')\n"
                    "except OSError:\n"
                    "    print('BLOCKED')\n"])
        self.assertTrue(r.ok)
        self.assertIn("BLOCKED", r.stdout)

    def test_root_filesystem_readonly(self):
        sb = DockerSandbox()
        r = sb.run(["python", "-c",
                    "try:\n"
                    "    open('/should-fail', 'w')\n"
                    "    print('WRITABLE')\n"
                    "except OSError:\n"
                    "    print('READONLY')\n"])
        self.assertTrue(r.ok)
        self.assertIn("READONLY", r.stdout)


class TestDockerSandboxFallback(unittest.TestCase):
    """Behavior when Docker is absent must degrade loudly, never silently."""

    def test_unavailable_raises_clear_error(self):
        class FakeSandbox(DockerSandbox):
            def available(self):
                return False

        sb = FakeSandbox()
        with self.assertRaises(DockerUnavailableError):
            sb.run(["echo", "hi"])

    def test_runner_marks_results_when_docker_absent(self):
        class FakeSandbox(DockerSandbox):
            def available(self):
                return False

        tasks = generate_tasks(3, seed=5)
        with tempfile.TemporaryDirectory() as td:
            with DockerRunner(tasks, Path(td) / "ws") as runner:
                runner.sandbox = FakeSandbox()
                report = runner.run(HonestAgent())
        self.assertFalse(report.extras["docker_available"])
        # No sandbox -> no verdicts, and every note says so explicitly.
        self.assertEqual(report.solved_count, 0)
        for r in report.results:
            self.assertTrue(any("Docker unavailable" in n for n in r.notes),
                            f"missing fallback note on {r.task_id}")


@unittest.skipUnless(DockerSandbox().available(), "docker not available")
class TestDockerRunnerEndToEnd(unittest.TestCase):
    def test_honest_and_peek_agent(self):
        tasks = generate_tasks(4, seed=9)
        with tempfile.TemporaryDirectory() as td:
            with DockerRunner(tasks, Path(td) / "e2e") as runner:
                honest = runner.run(HonestAgent())
                peek = runner.run(ZeroCapabilityAgent([PeekAnswers()]))
        self.assertEqual(honest.solved_count, honest.total)
        # No tasks.json in the agent workspace -> peek-answers gets nothing.
        self.assertEqual(peek.solved_count, 0)


if __name__ == "__main__":
    unittest.main()
