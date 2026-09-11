"""Tests for the C2 runtime network guard (netguard + SecureRunner integration)."""
import socket
import tempfile
import unittest
import urllib.request
from pathlib import Path

from benchshield.benchdata import generate_tasks
from benchshield.netguard import (
    NetworkBlockedError,
    network_blocked,
    network_is_blocked,
)
from benchshield.redteam import HonestAgent
from benchshield.sandbox import SecureRunner


class TestNetGuard(unittest.TestCase):
    def test_socket_creation_blocked_inside_context(self):
        with network_blocked():
            with self.assertRaises(NetworkBlockedError):
                socket.socket()
            self.assertTrue(network_is_blocked())

    def test_dns_blocked_inside_context(self):
        with network_blocked():
            with self.assertRaises(NetworkBlockedError):
                socket.getaddrinfo("example.com", 80)

    def test_urlopen_blocked_inside_context(self):
        with network_blocked():
            with self.assertRaises(NetworkBlockedError):
                urllib.request.urlopen("http://example.com")

    def test_network_restored_after_context(self):
        with network_blocked():
            pass
        # After the guard lifts, sockets can be created again (we do not
        # connect — just verify the patch was reverted).
        s = socket.socket()
        s.close()
        self.assertFalse(network_is_blocked())

    def test_guard_survives_exception_inside_context(self):
        try:
            with network_blocked():
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        s = socket.socket()
        s.close()


class TestSecureRunnerNetworkIsolation(unittest.TestCase):
    def setUp(self):
        self.tasks = generate_tasks(3, seed=7)
        self.tmp = Path(tempfile.mkdtemp(prefix="benchshield_net_"))

    def test_agent_network_attempt_is_blocked_and_counted(self):
        class PhoneHomeAgent:
            name = "phone-home"

            def act(self, task_public, workspace):
                socket.create_connection(("example.com", 80), timeout=1)
                return "done"

        with SecureRunner(self.tasks, self.tmp / "ws") as runner:
            report = runner.run(PhoneHomeAgent())
        self.assertEqual(report.solved_count, 0)
        self.assertEqual(report.extras["tamper_attempts"], report.total)
        noted = [r for r in report.results
                 if any("network attempt blocked" in n for n in r.notes)]
        self.assertEqual(len(noted), report.total)

    def test_honest_agent_unaffected_by_guard(self):
        with SecureRunner(self.tasks, self.tmp / "ws2") as runner:
            report = runner.run(HonestAgent())
        self.assertEqual(report.solved_count, report.total)

    def test_opt_out_disables_guard(self):
        class PhoneHomeAgent:
            name = "phone-home-allowed"

            def act(self, task_public, workspace):
                # Not actually reaching out — just proving the guard is off
                # by creating a socket (would raise under the guard).
                s = socket.socket()
                s.close()
                return "created a socket"

        with SecureRunner(self.tasks, self.tmp / "ws3",
                          block_network=False) as runner:
            report = runner.run(PhoneHomeAgent())
        net_notes = [r for r in report.results
                     if any("network" in n for n in r.notes)]
        self.assertEqual(net_notes, [])


if __name__ == "__main__":
    unittest.main()
