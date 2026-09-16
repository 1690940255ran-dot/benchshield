"""LLM-as-judge semantic evaluation built on judgeguard (V4 defense in use).

Exact-match scoring is brittle for open-ended tasks; the standard fix is an
LLM judge — which reintroduces the V4 injection risk. This module is the
safe way to do it:

- the judge prompt is built by ``judgeguard.build_judge_prompt`` (sanitized
  response, random fence, anti-injection preamble);
- before the model is even called, ``judgeguard.detect_injection`` screens
  the raw response: a flagged attempt FAILS the task outright and is
  recorded (the judge never sees attacker text);
- the model's verdict must be strictly ``PASS`` or ``FAIL`` (case
  insensitive, whitespace trimmed, first word only); anything else counts
  as a judge error and the task is NOT marked solved (fail-closed);
- the judge runs *after* netguard-style separation: gold goes only into
  the prompt sent to the judge model, never into the agent workspace.

Model access is abstract: any callable ``complete(prompt) -> str`` works,
so tests use a fake judge and production uses ``OllamaJudge`` (works with
any OpenAI-compatible /api/chat endpoint, including local Ollama, with
zero dependencies via urllib).

Fail-closed rule: when the judge cannot be reached or returns garbage,
the task fails and the error is recorded — a semantic score is only ever
earned, never defaulted into.
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field

from .judgeguard import build_judge_prompt, detect_injection

_VERDICT_RE = re.compile(r"^\s*(PASS|FAIL)\b", re.I)


@dataclass
class JudgeVerdict:
    task_id: str
    passed: bool
    judge_error: str = ""        # non-empty when the judge itself failed
    injection_flags: list = field(default_factory=list)
    judge_output: str = ""       # raw model output (truncated), for logs


class SemanticJudge:
    """Wrap a `complete(prompt) -> str` model with judgeguard protections."""

    def __init__(self, complete, *, max_length: int = 4000) -> None:
        self.complete = complete
        self.max_length = max_length

    def judge(self, task_id: str, response, gold) -> JudgeVerdict:
        # 1) Injection screen happens on the RAW response, before any
        #    prompt is built — flagged attempts never reach the model.
        flags = detect_injection(response if isinstance(response, str)
                                 else str(response))
        if flags:
            return JudgeVerdict(task_id, passed=False,
                                injection_flags=flags,
                                judge_output="(blocked by injection screen)")

        # 2) Hardened prompt: sanitized, random-fenced, gold isolated.
        prompt, report = build_judge_prompt(response, gold,
                                            max_length=self.max_length)
        if report.suspicious:
            return JudgeVerdict(task_id, passed=False,
                                injection_flags=report.injection_flags,
                                judge_output="(blocked by sanitize report)")

        # 3) Call the model; fail closed on any error.
        try:
            raw = self.complete(prompt)
        except Exception as exc:
            return JudgeVerdict(task_id, passed=False,
                                judge_error=f"judge call failed: "
                                           f"{type(exc).__name__}: {exc}")
        output = (raw or "").strip()

        # 4) Strict verdict parsing: first word must be PASS/FAIL.
        m = _VERDICT_RE.match(output)
        if not m:
            return JudgeVerdict(task_id, passed=False,
                                judge_error="judge output not PASS/FAIL",
                                judge_output=output[:200])
        return JudgeVerdict(task_id, passed=m.group(1).upper() == "PASS",
                            judge_output=output[:200])


class OllamaJudge:
    """OpenAI-compatible chat completion backend (works with local Ollama).

    Uses only urllib from the stdlib; the HTTP call happens inside the
    judge runner (evaluator side), which is outside the agent's netguard
    block by design.
    """

    def __init__(self, model: str = "qwen3.5:9b",
                 endpoint: str = "http://localhost:11434") -> None:
        self.model = model
        self.endpoint = endpoint.rstrip("/")

    def complete(self, prompt: str) -> str:
        payload = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0},
        }).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint + "/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["message"]["content"]


def run_semantic_benchmark(judge: SemanticJudge, tasks, agent,
                           workspace: str = None) -> list:
    """Score an agent over tasks with the semantic judge (gold never shown).

    `workspace` is passed through to agents whose act() signature expects
    one (e.g. the built-in HonestAgent / ZeroCapabilityAgent).
    """
    verdicts = []
    for task in tasks:
        public = {k: v for k, v in task.items() if k != "gold"}
        try:
            response = agent.act(public, workspace)
        except TypeError:
            response = agent.act(public)
        verdicts.append(judge.judge(task["id"], response, task["gold"]))
    return verdicts
