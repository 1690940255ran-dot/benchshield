"""Tests for YAML config / docker-compose scanning and the yamlmini parser."""
import tempfile
import textwrap
import unittest
from pathlib import Path

from benchshield.scanner import scan_directory
from benchshield.yamlmini import YamlMiniError, loads


class TestYamlMiniParser(unittest.TestCase):
    def test_flat_config(self):
        y = textwrap.dedent("""
            # comment
            agent_dir: ws/agent
            eval_dir: ws/eval
            allow_network: true
            fresh_snapshot: false
            timeout: 120
        """)
        self.assertEqual(loads(y), {
            "agent_dir": "ws/agent", "eval_dir": "ws/eval",
            "allow_network": True, "fresh_snapshot": False, "timeout": 120,
        })

    def test_nested_services(self):
        y = textwrap.dedent("""
            services:
              agent:
                volumes:
                  - shared:/workspace
                network_mode: host
              evaluator:
                volumes:
                  - shared:/eval
        """)
        self.assertEqual(loads(y), {
            "services": {
                "agent": {"volumes": ["shared:/workspace"], "network_mode": "host"},
                "evaluator": {"volumes": ["shared:/eval"]},
            }
        })

    def test_scalars(self):
        y = "a: 1\nb: 1.5\nc: 'yes'\nd: null\ne: ~\nf: \"quoted\"\ng: 'it''s'"
        self.assertEqual(loads(y), {
            "a": 1, "b": 1.5, "c": "yes", "d": None, "e": None,
            "f": "quoted", "g": "it's",
        })

    def test_document_separator(self):
        y = "a: 1\n---\nb: 2\n"
        self.assertEqual(loads(y), {"a": 1})

    def test_empty(self):
        self.assertIsNone(loads(""))
        self.assertIsNone(loads("# only a comment\n"))

    def test_unsupported_syntax_raises(self):
        for bad in ("x: &anchor 1", "x: [1, 2]", "x: *alias", "x: !tag v",
                    "x:\tTab indent: 1"):
            with self.subTest(bad=bad):
                with self.assertRaises(YamlMiniError):
                    loads(bad)


class TestYamlConfigScan(unittest.TestCase):
    def _write(self, root, rel, body):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p

    def test_yaml_config_env_shared_and_net(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config.yaml", """
                agent_dir: ws
                eval_dir: ws
                allow_network: true
            """)
            result = scan_directory(root)
            rules = {f.rule for f in result.findings}
            self.assertIn("ENV-SHARED", rules)
            self.assertIn("ENV-NET", rules)

    def test_yaml_config_clean_no_findings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "config.yaml", """
                agent_dir: agent_ws
                eval_dir: eval_ws
                allow_network: false
            """)
            result = scan_directory(root)
            problems = [f for f in result.findings if f.rule != "PARSE-ERROR"]
            self.assertEqual(problems, [])

    def test_yaml_config_dirty_syntax_is_finding_not_crash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "config.yaml").write_text("x: [flow, collection]", encoding="utf-8")
            result = scan_directory(root)
            parse = [f for f in result.findings if f.rule == "CONFIG-PARSE"]
            self.assertEqual(len(parse), 1)

    def test_yaml_tasks_data_leak(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, "tasks.yaml", """
                tasks:
                  - id: t1
                    prompt: What is 2+2?
                    gold: "4"
                  - id: t2
                    prompt: What is 3x3?
                    gold: "9"
            """)
            result = scan_directory(root)
            leaks = [f for f in result.findings if f.rule == "DATA-LEAK"]
            self.assertEqual(len(leaks), 1)
            self.assertIn("2 record(s)", leaks[0].title)


class TestComposeScan(unittest.TestCase):
    def _write(self, root, body):
        p = root / "docker-compose.yml"
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p

    def test_host_network_and_shared_volume_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, """
                version: "3"
                services:
                  agent:
                    image: agent:latest
                    network_mode: host
                    volumes:
                      - bench-data:/data
                  evaluator:
                    image: eval:latest
                    volumes:
                      - bench-data:/eval-data
            """)
            result = scan_directory(root)
            rules = {f.rule for f in result.findings}
            self.assertIn("COMPOSE-NET-HOST", rules)
            self.assertIn("COMPOSE-SHARED-VOL", rules)

    def test_isolated_compose_clean(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write(root, """
                version: "3"
                services:
                  agent:
                    image: agent:latest
                    volumes:
                      - agent-scratch:/data
                  evaluator:
                    image: eval:latest
                    volumes:
                      - eval-secrets:/eval-data
            """)
            result = scan_directory(root)
            compose = [f for f in result.findings if f.rule.startswith("COMPOSE")]
            self.assertEqual(compose, [])

    def test_compose_parse_error_is_finding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "docker-compose.yml").write_text(
                "services: {flow: style}", encoding="utf-8")
            result = scan_directory(root)
            parse = [f for f in result.findings if f.rule == "COMPOSE-PARSE"]
            self.assertEqual(len(parse), 1)


if __name__ == "__main__":
    unittest.main()
