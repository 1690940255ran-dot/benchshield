"""Tests for the Docker task sandbox.

Docker-dependent tests auto-skip when the daemon is not available, so the
suite stays green on zero-Docker machines and CI.
"""
import subprocess
import unittest
from unittest import mock

from benchshield import dockersandbox
from benchshield.dockersandbox import (
    DockerRunner,
    DockerSandbox,
    DockerUnavailableError,
)
from benchshield.benchdata import generate_tasks
from benchshield.redteam import HonestAgent, PeekAnswers, ZeroCapabilityAgent

import tempfile
from pathlib import Path


class TestAvailabilityProbe(unittest.TestCase):
    """`available()` must mean "can actually run a Linux container".

    Regression guard: a Windows-container daemon answers `docker version`
    happily and then rejects every image this module needs, so a naive
    probe turns a clean *skip* into hard failures. That is exactly how the
    windows-latest CI jobs broke, and no machine we own can reproduce it —
    stubbing the probe is the only way to keep it fixed.
    """

    @staticmethod
    def _cp(stdout, returncode=0):
        return subprocess.CompletedProcess(["docker"], returncode, stdout, "")

    def _available(self, which_result, proc):
        with mock.patch.object(dockersandbox.shutil, "which",
                               return_value=which_result), \
                mock.patch.object(dockersandbox.subprocess, "run",
                                  return_value=proc):
            return DockerSandbox().available()

    def test_no_cli_is_unavailable(self):
        self.assertFalse(self._available(None, None))

    def test_linux_daemon_is_available(self):
        self.assertTrue(self._available("/usr/bin/docker", self._cp("linux\n")))

    def test_windows_container_daemon_is_unavailable(self):
        # The bug: daemon answers, so the old probe said "available".
        self.assertFalse(self._available(r"C:\docker.exe", self._cp("windows\n")))

    def test_daemon_error_is_unavailable(self):
        self.assertFalse(self._available("docker", self._cp("", 1)))

    def test_daemon_timeout_is_unavailable(self):
        with mock.patch.object(dockersandbox.shutil, "which",
                               return_value="docker"), \
                mock.patch.object(dockersandbox.subprocess, "run",
                                  side_effect=subprocess.TimeoutExpired(
                                      "docker", 15)):
            self.assertFalse(DockerSandbox().available())

    def test_os_type_is_case_insensitive(self):
        self.assertTrue(self._available("docker", self._cp("Linux\n")))

    def test_probe_checks_os_type_not_version(self):
        """The probe must ask for OSType; version probes are what broke."""
        calls = []

        def spy(argv, *a, **kw):
            calls.append(list(argv))
            return self._cp("linux\n")

        with mock.patch.object(dockersandbox.shutil, "which",
                               return_value="docker"), \
                mock.patch.object(dockersandbox.subprocess, "run", side_effect=spy):
            DockerSandbox().available()
        self.assertTrue(calls)
        self.assertIn("info", calls[0])
        self.assertIn("{{.OSType}}", calls[0])


@unittest.skipUnless(DockerSandbox().available(), "linux docker not available")
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


@unittest.skipUnless(DockerSandbox().available(), "linux docker not available")
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
