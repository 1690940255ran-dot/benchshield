"""Agent-Eval Checklist (C1-C10) scoring.

Derived from scanner findings plus optional benchmark config flags. C9/C10
are runtime properties; they score "pass" only when the config explicitly
declares them, otherwise they stay "manual" for human verification.
"""
from __future__ import annotations

from dataclasses import dataclass

ITEMS = [
    ("C1", "Agent and evaluator environments are isolated (no shared writable paths)"),
    ("C2", "Network egress is disabled for the agent during tasks"),
    ("C3", "Reference answers are never agent-accessible"),
    ("C4", "No eval()/exec() on agent-controlled strings"),
    ("C5", "LLM-judge prompts sanitize agent-controlled input"),
    ("C6", "Robust answer comparison (no substring containment)"),
    ("C7", "Validation logic actually verifies correctness"),
    ("C8", "Evaluator loads no code/files from agent-writable locations"),
    ("C9", "Fresh environment snapshot per task"),
    ("C10", "Agent and evaluator logs are segregated and append-only"),
]

RULE_TO_ITEM = {
    "ENV-SHARED": "C1",
    "ENV-NET": "C2",
    "DATA-LEAK": "C3",
    "EVAL-CALL": "C4",
    "JUDGE-INJECT": "C5",
    "WEAK-MATCH": "C6",
    "NO-CHECK": "C7",
    "TRUST-OUT": "C8",
}

_SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class ChecklistResult:
    items: list  # list of (cid, title, status, details)
    grade: str

    @property
    def failed(self) -> list:
        return [i for i in self.items if i[2] == "fail"]


def evaluate(findings, config=None) -> ChecklistResult:
    config = config or {}
    failed_rules = {f.rule for f in findings}
    items = []
    for cid, title in ITEMS:
        mapped = sorted(r for r, c in RULE_TO_ITEM.items() if c == cid)
        hit = [r for r in mapped if r in failed_rules]
        if hit:
            sev = _max_severity(findings, hit)
            items.append((cid, title, "fail", f"{sev} finding: {', '.join(hit)}"))
        elif cid in ("C9", "C10"):
            key = "fresh_snapshot" if cid == "C9" else "log_segregation"
            if config.get(key) is True:
                items.append((cid, title, "pass", "declared in config"))
            else:
                items.append((cid, title, "manual", "verify at runtime"))
        else:
            items.append((cid, title, "pass", "no pattern detected"))
    return ChecklistResult(items=items, grade=_grade(items, findings))


def _max_severity(findings, rules) -> str:
    sevs = [f.severity for f in findings if f.rule in rules]
    if not sevs:
        return "medium"
    return max(sevs, key=lambda s: _SEVERITY_RANK.get(s, 0))


def _grade(items, findings) -> str:
    if not any(i[2] == "fail" for i in items):
        return "A"
    worst = max((_SEVERITY_RANK.get(f.severity, 0) for f in findings), default=0)
    if worst >= 3:
        return "F"
    if worst == 2:
        return "D"
    return "C"
