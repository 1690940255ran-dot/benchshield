"""Task-format adapters: SWE-bench and Terminal-Bench -> BenchShield tasks.

Real-world agent benchmarks ship data in their own formats. These adapters
convert them into BenchShield's internal task records so the runners, the
checklist and (importantly) the *scanner's DATA-LEAK rule* can operate on
them:

- SWE-bench: one JSONL file, one object per instance with fields like
  ``instance_id``, ``problem_statement``, ``patch``, ``test_patch``. The
  patch fields ARE gold answers (V2): if that file ends up inside the
  agent workspace, the agent can just read the solution.

- Terminal-Bench: a directory of task folders, each with ``task.yaml``
  (instruction etc.) and usually a ``solution.sh`` / ``solve.sh`` script.
  The solution script is the gold answer (V2).

All parsing reuses the zero-dependency ``yamlmini`` parser — no new deps.
Adapters are deliberately strict: unknown shapes raise ``AdapterError``
instead of returning half-loaded tasks (the same "never guess about
isolation-relevant data" rule the config scanner follows).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .yamlmini import YamlMiniError, loads


class AdapterError(ValueError):
    """Raised when input does not match the expected benchmark format."""


@dataclass
class Task:
    """Internal task record: what the agent may see vs. what it must not."""
    id: str
    prompt: str
    gold: str
    gold_kind: str = "answer"  # answer | patch | solution-script
    extra: dict = None

    def public_view(self) -> dict:
        d = {"id": self.id, "prompt": self.prompt}
        if self.extra:
            d.update(self.extra)
        return d


# ---------------------------------------------------------------- SWE-bench

SWEBENCH_REQUIRED = ("instance_id", "problem_statement", "patch")


def load_swebench(path) -> list:
    """Load a SWE-bench instances JSONL file into Task records.

    ``patch`` / ``test_patch`` become gold (never shown to the agent);
    ``problem_statement`` becomes the prompt. This mirrors what the V2
    rule is about: those files must never sit in the agent workspace.
    """
    path = Path(path)
    tasks = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AdapterError(f"{path.name}:{lineno}: invalid JSON: {exc}")
            missing = [k for k in SWEBENCH_REQUIRED if not rec.get(k)]
            if missing:
                raise AdapterError(
                    f"{path.name}:{lineno}: SWE-bench record missing "
                    f"field(s): {', '.join(missing)}")
            tasks.append(Task(
                id=str(rec["instance_id"]),
                prompt=str(rec["problem_statement"]),
                gold=str(rec["patch"]),
                gold_kind="patch",
                extra={"repo": rec.get("repo"), "base_commit":
                       rec.get("base_commit")},
            ))
    if not tasks:
        raise AdapterError(f"{path}: no SWE-bench instances found")
    return tasks


# ----------------------------------------------------------- Terminal-Bench

def load_terminalbench(path) -> list:
    """Load a Terminal-Bench task directory into Task records.

    Expected layout (the standard checkout):

        <path>/<task-name>/task.yaml        # instruction, etc.
        <path>/<task-name>/solution.sh      # or solve.sh — the gold answer

    The solution script is loaded as gold (V2): it must never be exposed
    to the agent at runtime.
    """
    root = Path(path)
    if not root.is_dir():
        raise AdapterError(f"not a directory: {root}")
    tasks = []
    task_dirs = sorted(d for d in root.iterdir() if d.is_dir())
    if not task_dirs:
        raise AdapterError(f"{root}: no task directories found")
    for d in task_dirs:
        yaml_path = d / "task.yaml"
        if not yaml_path.exists():
            raise AdapterError(f"{d}: missing task.yaml")
        try:
            meta = loads(yaml_path.read_text(encoding="utf-8"))
        except YamlMiniError as exc:
            raise AdapterError(f"{yaml_path}: cannot parse task.yaml: {exc}")
        if not isinstance(meta, dict):
            raise AdapterError(f"{yaml_path}: task.yaml must be a mapping")
        instruction = (meta.get("instruction")
                       or meta.get("description") or "").strip()
        if not instruction:
            raise AdapterError(f"{yaml_path}: no instruction found")
        solution = None
        for name in ("solution.sh", "solve.sh", "solution.py"):
            candidate = d / name
            if candidate.exists():
                solution = candidate.read_text(encoding="utf-8")
                break
        if solution is None:
            raise AdapterError(
                f"{d}: no solution script found (solution.sh / solve.sh / "
                "solution.py)")
        tasks.append(Task(
            id=meta.get("name") or d.name,
            prompt=instruction,
            gold=solution,
            gold_kind="solution-script",
        ))
    return tasks


# ------------------------------------------------------------- scan bridge

SWEBENCH_GOLD_KEYS = {"patch", "test_patch"}
SWEBENCH_SIGNATURE_KEYS = {"instance_id", "problem_statement"}


def looks_like_swebench(records: list) -> bool:
    """True when a list of dicts carries the SWE-bench field signature."""
    if not records:
        return False
    hits = sum(1 for r in records
               if isinstance(r, dict) and SWEBENCH_SIGNATURE_KEYS <= set(r))
    return hits >= max(1, len(records) // 2)
