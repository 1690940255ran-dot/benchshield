"""Docker-based task sandboxes: a fresh, locked-down container per task.

This is the strongest isolation tier BenchShield offers. The in-process
``netguard`` blocks Python-level network calls; ``DockerSandbox`` blocks
everything at the kernel level by running each task's evaluator inside an
ephemeral container with:

- ``--network none``      — no network namespace at all (C2, kernel-enforced)
- ``--read-only``         — immutable root filesystem (nothing persists)
- ``--tmpfs /workspace``  — scratch space that vanishes with the container
- ``--rm``                — container is deleted on exit (C9, fresh per task)
- no ``--privileged``, no extra capabilities

How code gets in: everything is piped over stdin — the driver script and
its JSON payload never touch the host filesystem, so there are no mounts
to poison and no volumes to share (the V1 shared-volume anti-pattern is
structurally impossible here).

``DockerRunner`` composes this with the existing task model: the agent
still runs on the host (orchestrated by ``SecureRunner`` semantics), but
the *evaluator* — the component that holds gold answers — executes in the
sandbox. For fully agent-side sandboxing, point your agent's tool calls at
``DockerSandbox.run`` as well.

Docker is OPTIONAL: the daemon must be able to run **Linux** containers
(``python:3.12-slim`` is a Linux image, so a Windows-container daemon does
not qualify). When no such daemon is reachable every API raises
``DockerUnavailableError`` and the test suite auto-skips, so zero-Docker
users lose nothing.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .benchdata import public_view
from .netguard import network_blocked
from .sandbox import RunReport, TaskResult, _agent_name

DEFAULT_IMAGE = "python:3.12-slim"

# Driver executed inside the container. Reads a JSON payload from stdin:
# {"gold": ..., "response": ...} and prints {"pass": true/false}.
# exact_match mirrors eval_worker semantics so results are comparable.
_DRIVER = r'''
import json, sys
payload = json.loads(sys.stdin.read())
gold = str(payload.get("gold", "")).strip()
resp = str(payload.get("response", "")).strip()
print(json.dumps({"pass": resp == gold}))
'''


class DockerUnavailableError(RuntimeError):
    """Docker (or the daemon) is not available on this machine."""


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class DockerSandbox:
    """Run a command in a fresh, disposable, network-less container."""

    def __init__(self, image: str = DEFAULT_IMAGE, timeout: int = 120) -> None:
        self.image = image
        self.timeout = timeout
        self._docker_path = shutil.which("docker")

    def available(self) -> bool:
        """True when a daemon that can run **Linux** containers is reachable.

        All three conditions matter, and the third is the one that bites:

        1. the docker CLI exists;
        2. the daemon answers;
        3. the daemon runs LINUX containers.

        A Windows-container daemon (the default on Windows CI runners)
        answers every version probe happily, then fails on every image this
        module needs — ``python:3.12-slim`` is a Linux image. Without the
        OS-type probe, "is Docker available?" degenerates into "is the CLI
        installed?", and the caller finds out the hard way, mid-`docker run`,
        with a hard failure instead of a clean skip. Probing the OS type
        keeps this an availability check rather than a deferred crash.
        """
        if not self._docker_path:
            return False
        try:
            proc = subprocess.run(
                ["docker", "info", "--format", "{{.OSType}}"],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0 and proc.stdout.strip().lower() == "linux"

    def _require(self) -> None:
        if not self.available():
            raise DockerUnavailableError(
                "Docker is not available; the sandboxed evaluator cannot run. "
                "Falling back to SecureRunner (process isolation) is safe — "
                "it is the documented behavior when Docker is absent.")

    def run(self, command: list, stdin_text: str = "") -> SandboxResult:
        """Execute `command` inside a fresh locked-down container."""
        self._require()
        argv = [
            "docker", "run", "--rm", "--interactive",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/workspace:size=16m",
            "--cap-drop", "ALL",
            self.image,
        ] + list(command)
        proc = subprocess.run(
            argv, input=stdin_text, capture_output=True, text=True,
            timeout=self.timeout,
        )
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)

    def evaluate(self, response, gold) -> SandboxResult:
        """Run the exact-match evaluator inside a fresh container.

        Code and payload travel via stdin; no host filesystem is mounted.
        """
        payload = json.dumps({"gold": gold, "response": response})
        return self.run(["python", "-c", _DRIVER], stdin_text=payload)


class DockerRunner:
    """SecureRunner variant whose evaluator executes in a Docker sandbox.

    Same trust model as SecureRunner (C1/C3/C4/C8/C9/C10 — see sandbox.py)
    plus kernel-level network isolation and an immutable root filesystem
    for the evaluator process (C2, and defense against a compromised
    evaluator corrupting the host).
    """

    name = "docker"

    def __init__(self, tasks, workspace_root,
                 image: str = DEFAULT_IMAGE, timeout: int = 120,
                 block_network: bool = True) -> None:
        self.tasks = list(tasks)
        self.root = Path(workspace_root)
        self.logs_dir = self.root / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.agent_log_path = self.logs_dir / "agent.log"
        self.eval_log_path = self.logs_dir / "eval.log"
        self.sandbox = DockerSandbox(image=image, timeout=timeout)
        self.block_network = block_network

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, agent) -> RunReport:
        name = _agent_name(agent)
        results = []
        docker_ok = self.sandbox.available()
        with open(self.agent_log_path, "a", encoding="utf-8") as alog, open(
            self.eval_log_path, "a", encoding="utf-8"
        ) as elog:
            for task in self.tasks:
                notes = []
                # C3: agent only ever sees the public view; C9: fresh dir.
                import tempfile
                task_ws = Path(tempfile.mkdtemp(prefix=task["id"] + "_",
                                                dir=str(self.root)))
                try:
                    (task_ws / "task.txt").write_text(task["prompt"],
                                                      encoding="utf-8")
                    # C2 at the agent side: Python-level network block.
                    try:
                        if self.block_network:
                            with network_blocked():
                                out = agent.act(public_view(task), task_ws)
                        else:
                            out = agent.act(public_view(task), task_ws)
                    except Exception as exc:  # agent blew up: task failed
                        out = ""
                        notes.append(f"agent raised: {type(exc).__name__}: {exc}")
                    if not docker_ok:
                        notes.append(
                            "Docker unavailable: evaluator did NOT run in a "
                            "sandbox; treat this result as process-isolated "
                            "only")
                        solved = False
                    else:
                        sb = self.sandbox.evaluate(out, task["gold"])
                        if sb.ok:
                            try:
                                solved = bool(json.loads(
                                    sb.stdout.strip().splitlines()[-1])["pass"])
                            except (json.JSONDecodeError, KeyError, IndexError):
                                solved = False
                                notes.append("sandbox evaluator output "
                                             "unparseable")
                        else:
                            solved = False
                            notes.append(f"sandbox evaluator failed: "
                                         f"{sb.stderr.strip()[:120]}")
                    alog.write(json.dumps({"task": task["id"],
                                           "agent_output": str(out)[:200]},
                                          ensure_ascii=False) + "\n")
                    elog.write(json.dumps({"task": task["id"],
                                           "pass": solved}) + "\n")
                    results.append(TaskResult(task["id"], name, solved,
                                              str(out), notes))
                finally:
                    import shutil as _shutil
                    _shutil.rmtree(task_ws, ignore_errors=True)
        return RunReport(self.name, name, results,
                         extras={"docker_available": docker_ok})
