"""BenchShield command-line interface.

Usage:
    python -m benchshield scan examples/vulnerable_bench
    python -m benchshield demo --n 50
    python -m benchshield export-bench --n 50 --out tasks.json
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .benchdata import generate_tasks
from .checklist import evaluate
from .example_bench import write_example_bench
from .redteam import (
    EvalAlwaysTrue,
    HonestAgent,
    OverwriteChecker,
    PeekAnswers,
    ZeroCapabilityAgent,
)
from .report import render_markdown
from .sandbox import SecureRunner, VulnerableRunner
from .scanner import SEVERITY_RANK, ScanResult, scan_directory

CONFIG_NAMES = ("bench_config.json", "config.json")


def _load_config(root: Path) -> dict:
    for name in CONFIG_NAMES:
        path = root / name
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
    return {}


def cmd_scan(args) -> int:
    root = Path(args.path)
    try:
        scan = scan_directory(root)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    config = _load_config(root)
    checklist = evaluate(scan.findings, config)
    counts = scan.severity_counts

    print(f"BenchShield scan of {root}")
    print(f"  files scanned : {scan.files_scanned}")
    print(f"  findings      : {len(scan.findings)} "
          f"(critical {counts['critical']}, high {counts['high']}, "
          f"medium {counts['medium']}, info {counts['info']})")
    print()
    for f in scan.sorted_findings():
        print(f"  [{f.severity.upper():<8}] {f.vuln_class} {f.rule:<12} "
              f"{f.file}:{f.line}  {f.title}")

    print()
    failed = [i[0] for i in checklist.failed]
    if failed:
        print(f"Agent-Eval Checklist grade: {checklist.grade} (failed: {', '.join(failed)})")
    else:
        print(f"Agent-Eval Checklist grade: {checklist.grade}")

    out = Path(args.out) if args.out else Path.cwd() / "benchshield_report.md"
    try:
        out.write_text(render_markdown(scan, checklist), encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write report to {out}: {exc}", file=sys.stderr)
        return 2
    print(f"report written to {out}")

    has_critical = any(f.severity == "critical" for f in scan.findings)
    return 1 if has_critical else 0


def _demo_note(report, key: str) -> str:
    if report.runner == "vulnerable":
        if key == "peek":
            return "V2: gold answers read from workspace tasks.json"
        if key == "tamper":
            n = report.extras.get("checker_tampered_tasks", 0)
            return f"V7: checker.py replaced by agent on {n}/{report.total} tasks"
        if key == "eval":
            return ("V3: response evaluated as code (eval() fallback accepts "
                    "any Python expression when the checker rejects it)")
        return ""
    if key == "peek":
        return "blocked: no gold answers present in the agent workspace"
    if key == "tamper":
        n = report.extras.get("tamper_attempts", 0)
        return f"{n} tamper attempt(s) logged and neutralized"
    if key == "eval":
        return "blocked: response parsed as plain text, never evaluated as code"
    return ""


# Test seam: when set, _scan_demo_bench uses this path instead of the
# repo's examples/ directory (lets tests simulate an installed package
# where examples/ is absent).
_EXAMPLES_OVERRIDE = None


def _scan_demo_bench(base: Path):
    """Pick the scan target for the demo report.

    Prefers the repo's examples/vulnerable_bench (source checkout or
    editable install). After a regular `pip install` the examples tree is
    not shipped inside site-packages, so an equivalent bundle is
    materialized inside the demo's temp dir instead — the scan still
    covers all seven vulnerability patterns either way.

    Returns (ScanResult, target_path); never raises on a missing bundle.
    """
    if _EXAMPLES_OVERRIDE is not None:
        target = Path(_EXAMPLES_OVERRIDE)
    else:
        target = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_bench"
    source = "bundled examples/vulnerable_bench"
    if not target.is_dir():
        target = write_example_bench(base / "vulnerable_bench")
        source = "generated equivalent bundle (examples/ not shipped with this install)"
    try:
        return scan_directory(target), source
    except FileNotFoundError as exc:
        # Belt and suspenders: report the failure but keep the demo usable.
        print(f"warning: could not scan demo bench ({exc}); "
              "the report will contain run results only", file=sys.stderr)
        empty = ScanResult(root=str(target), files_scanned=0, findings=[])
        return empty, source


def cmd_demo(args) -> int:
    tasks = generate_tasks(args.n, seed=args.seed)
    base = Path(tempfile.mkdtemp(prefix="benchshield_demo_"))
    vuln_dir = base / "vulnerable"
    secure_dir = base / "secure"

    agents = [
        ("honest", HonestAgent()),
        ("peek", ZeroCapabilityAgent([PeekAnswers()], name="zero-cap [V2 peek-answers]")),
        ("eval", ZeroCapabilityAgent([EvalAlwaysTrue()], name="zero-cap [V3 eval-always-true]")),
        ("tamper", ZeroCapabilityAgent([OverwriteChecker()],
                                       name="zero-cap [V7 overwrite-checker]")),
    ]

    reports = []
    # Each agent gets a FRESH vulnerable runner so no state can leak between
    # runs (VulnerableRunner.run() also self-resets, belt and suspenders).
    for i, (key, agent) in enumerate(agents):
        vuln = VulnerableRunner(tasks, vuln_dir / f"agent_{i}")
        reports.append((key, vuln.run(agent)))
    with SecureRunner(tasks, secure_dir) as secure:
        for key, agent in agents:
            reports.append((key, secure.run(agent)))

    print(f"=== BenchShield demo: {len(tasks)} tasks ===")
    print()
    print(f"{'Runner':<11} {'Agent':<32} {'Solved':>7} {'Rate':>7}  Notes")
    for key, report in reports:
        note = _demo_note(report, key)
        print(f"{report.runner:<11} {report.agent:<32} "
              f"{report.solved_count:>3}/{report.total:<3} "
              f"{report.rate * 100:>6.1f}%  {note}")
    print()
    print("Verdict:")
    print("- On the VULNERABLE runner, zero-capability agents score 100% without")
    print("  solving a single task (the Berkeley RDI result, reproduced locally).")
    print("- On the SECURE runner the same agents score 0%: gold answers never enter")
    print("  the agent workspace and tampered files are logged and ignored.")
    print(f"- Artifacts: {base}")

    if args.report:
        scan, scan_source = _scan_demo_bench(base)
        checklist = evaluate(scan.findings)
        try:
            Path(args.report).write_text(
                render_markdown(scan, checklist, run_reports=[r for _, r in reports]),
                encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write demo report to {args.report}: {exc}",
                  file=sys.stderr)
            return 2
        print(f"- Demo report written to {args.report} "
              f"(scan target: {scan_source})")
    return 0


def cmd_export_bench(args) -> int:
    tasks = generate_tasks(args.n, seed=args.seed)
    out = Path(args.out)
    try:
        out.write_text(json.dumps(tasks, ensure_ascii=False, indent=1), encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write to {out}: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {len(tasks)} tasks to {out}")
    return 0


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="benchshield",
        description="Anti-cheating audit and isolated evaluation sandbox for AI agent benchmarks.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="audit a benchmark project for the 7 vulnerability patterns")
    p_scan.add_argument("path", help="benchmark project directory")
    p_scan.add_argument("--out", default=None, help="report output path (default: <path>/benchshield_report.md)")

    p_demo = sub.add_parser("demo", help="run the vulnerable-vs-secure end-to-end demonstration")
    p_demo.add_argument("--n", type=int, default=50, help="number of tasks (default: 50)")
    p_demo.add_argument("--seed", type=int, default=42)
    p_demo.add_argument("--report", default=None, help="also write a markdown demo report")

    p_export = sub.add_parser("export-bench", help="export a generated mini-benchmark task set")
    p_export.add_argument("--n", type=int, default=50)
    p_export.add_argument("--seed", type=int, default=42)
    p_export.add_argument("--out", default="tasks.json")

    args = parser.parse_args(argv)
    handlers = {"scan": cmd_scan, "demo": cmd_demo, "export-bench": cmd_export_bench}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
