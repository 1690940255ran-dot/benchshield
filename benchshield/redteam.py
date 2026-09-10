"""Zero-capability attack payloads (red team) and a rule-based honest agent.

The payloads reproduce, in miniature, the exploits documented by UC Berkeley
RDI ("Trustworthy Benchmarks", 2026): an agent that cannot solve a single
task scores near 100% by attacking the evaluation harness instead.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .benchdata import solve


@dataclass
class Payload:
    """Base payload. `deploy` prepares the workspace; `respond` produces the answer."""

    name: str
    exploits: str  # vulnerability class this payload targets (V1..V7)
    description: str

    def deploy(self, workspace: Path, task_public: dict) -> None:  # noqa: ARG002
        return None

    def respond(self, workspace: Path, task_public: dict) -> Optional[str]:  # noqa: ARG002
        return None


class PeekAnswers(Payload):
    """V2 - reference answers shipped with the test.

    The benchmark stores gold answers in tasks.json inside the agent
    workspace, so the agent simply reads them out.
    """

    def __init__(self) -> None:
        super().__init__(
            name="peek-answers",
            exploits="V2",
            description="read gold answers from tasks.json in the shared workspace",
        )

    def respond(self, workspace: Path, task_public: dict) -> Optional[str]:
        tasks_file = workspace / "tasks.json"
        if not tasks_file.exists():
            return None
        try:
            records = json.loads(tasks_file.read_text(encoding="utf-8"))
        except Exception:
            return None
        if isinstance(records, dict):
            records = list(records.values())
        for rec in records:
            if isinstance(rec, dict) and rec.get("id") == task_public.get("id") and "gold" in rec:
                return str(rec["gold"])
        return None


class OverwriteChecker(Payload):
    """V7 - evaluator trusts untrusted code output (the SWE-bench pytest-hook pattern).

    The evaluator imports its checker module from the agent-writable
    workspace, so the agent replaces it with one that always passes.
    """

    CHECKER_SRC = "def check(response, gold):\n    return True\n"

    def __init__(self) -> None:
        super().__init__(
            name="overwrite-checker",
            exploits="V7",
            description="drop a checker.py that always passes where the evaluator imports it",
        )

    def deploy(self, workspace: Path, task_public: dict) -> None:
        (workspace / "checker.py").write_text(self.CHECKER_SRC, encoding="utf-8")


class EvalAlwaysTrue(Payload):
    """V3 - evaluator calls eval() on the raw agent response."""

    def __init__(self) -> None:
        super().__init__(
            name="eval-always-true",
            exploits="V3",
            description="return a Python expression that evals to truthy when the evaluator uses eval()",
        )

    def respond(self, workspace: Path, task_public: dict) -> Optional[str]:
        # A bare identifier ("True") is too ambiguous to tell apart from a
        # literal answer; using an actual Python expression ("1+1") makes it
        # clear that the agent is leaning on the evaluator's eval() call
        # rather than stating an answer.
        return "1+1"


class ZeroCapabilityAgent:
    """An agent that cannot solve a single task - it only exploits the harness."""

    def __init__(self, payloads, name: Optional[str] = None) -> None:
        self.payloads = list(payloads)
        self.name = name or ("zero-capability[" + "+".join(p.name for p in self.payloads) + "]")

    def act(self, task_public: dict, workspace: Path) -> str:
        for payload in self.payloads:
            payload.deploy(workspace, task_public)
        for payload in self.payloads:
            reply = payload.respond(workspace, task_public)
            if reply is not None:
                return reply
        return "I have no idea."


class HonestAgent:
    """Rule-based solver that actually solves the tasks (baseline)."""

    name = "honest-solver"

    def act(self, task_public: dict, workspace: Path) -> str:  # noqa: ARG002
        return solve(task_public["category"], task_public["params"])
