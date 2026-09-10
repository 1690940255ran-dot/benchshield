<div align="center">

# BenchShield

**Anti-cheating audit and isolated evaluation sandbox for AI agent benchmarks.**

[![CI](https://github.com/1690940255ran-dot/benchshield/actions/workflows/ci.yml/badge.svg)](https://github.com/1690940255ran-dot/benchshield/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#design-notes)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-52%20passing-brightgreen.svg)](tests/)

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

---

## The problem

In April 2026, UC Berkeley RDI showed that an agent with **zero task capability** can score
near 100% on eight major agent benchmarks (SWE-bench Verified, Terminal-Bench, WebArena,
GAIA, ...) — not by solving tasks, but **by exploiting how the benchmarks evaluate**:
reading gold answers from the workspace, overwriting the checker, returning a truthy
expression to an `eval()` call, ...

If you are building or maintaining an agent benchmark, the question is not *whether* your
harness can be cheated — it is **how easily**, and **how would you know**.

## What BenchShield does

BenchShield turns that research into four composable tools:

| Tool | What it does |
|---|---|
| `scan` | Static auditor that detects the **seven recurring vulnerability patterns** (V1–V7) in a benchmark project, with file/line evidence |
| `runtime` | `SecureRunner` — a hardened evaluation runtime enforcing process isolation, per-task workspaces, and tamper logging |
| `redteam` | Zero-capability attack agents (payload library) that **prove** a harness is exploitable — and that your defenses hold |
| `checklist` | The **Agent-Eval Checklist (C1–C10)** with an A–F grade, drop-in for CI |

Zero third-party dependencies. Python 3.10+. MIT licensed.

## The 30-second demo

```
$ python -m benchshield demo --n 50

Runner      Agent                             Solved    Rate  Notes
vulnerable  honest-solver                     50/50   100.0%
vulnerable  zero-cap [V2 peek-answers]        50/50   100.0%  V2: gold answers read from workspace tasks.json
vulnerable  zero-cap [V3 eval-always-true]    50/50   100.0%  V3: response evaluated as code (eval() fallback accepts any Python expression when the checker rejects it)
vulnerable  zero-cap [V7 overwrite-checker]   50/50   100.0%  V7: checker.py replaced by agent on 50/50 tasks
secure      honest-solver                     50/50   100.0%
secure      zero-cap [V2 peek-answers]         0/50     0.0%  blocked: no gold answers present in the agent workspace
secure      zero-cap [V3 eval-always-true]     0/50     0.0%  blocked: response parsed as plain text, never evaluated as code
secure      zero-cap [V7 overwrite-checker]    0/50     0.0%  50 tamper attempt(s) logged and neutralized
```

Same agents, same tasks. The only difference is the evaluation harness — and that difference
is worth 100 points of reported "capability". This is the Berkeley RDI result, reproduced
locally in ~30 seconds.

## Install

```bash
git clone https://github.com/1690940255ran-dot/benchshield.git
cd benchshield
pip install -e .          # optional; running from the repo root works too
```

## Quickstart

```bash
# 1. Audit a benchmark project (exit code 1 on critical findings -> CI friendly)
python -m benchshield scan examples/vulnerable_bench

# 2. Watch zero-capability agents score 100% on a vulnerable harness and 0% on the secure one
python -m benchshield demo

# 3. Export the 50-task mini benchmark for your own experiments
python -m benchshield export-bench --n 50 --seed 42 --out tasks.json
```

Real `scan` output on the bundled deliberately-vulnerable benchmark:

```
$ python -m benchshield scan examples/vulnerable_bench

BenchShield scan of examples/vulnerable_bench
  files scanned : 3
  findings      : 8 (critical 3, high 4, medium 1, info 0)

  [CRITICAL] V7 TRUST-OUT    run_eval.py:38  spec_from_file_location() references an agent-writable path or variable
  [CRITICAL] V3 EVAL-CALL    run_eval.py:46  eval() called on non-literal input
  [CRITICAL] V2 DATA-LEAK    tasks.json:1  20 record(s) with gold answers (gold answers shipped next to prompts)
  [HIGH    ] V1 ENV-SHARED   bench_config.json:1  agent workspace and evaluator directory share a path or parent
  [HIGH    ] V1 ENV-NET      bench_config.json:1  network egress allowed for the agent during tasks
  [HIGH    ] V6 NO-CHECK     run_eval.py:21  check() can return True without validating
  [HIGH    ] V4 JUDGE-INJECT run_eval.py:33  LLM-judge prompt interpolates agent-controlled text unsanitized
  [MEDIUM  ] V5 WEAK-MATCH   run_eval.py:28  substring containment used for answer validation

Agent-Eval Checklist grade: F (failed: C1, C2, C3, C4, C5, C6, C7, C8)
```

Because the scan exits `1` on critical findings, it drops straight into CI as a gate.

## The seven vulnerability patterns

| Class | Pattern | Scanner rule | Severity |
|---|---|---|---|
| V1 | No isolation between agent and evaluator (shared dirs, network egress) | `ENV-SHARED`, `ENV-NET` | high |
| V2 | Reference answers shipped with the test | `DATA-LEAK` | critical |
| V3 | `eval()`/`exec()` on untrusted input | `EVAL-CALL` | critical |
| V4 | LLM judge without input sanitization | `JUDGE-INJECT` | high |
| V5 | Weak string matching (substring containment) | `WEAK-MATCH` | medium |
| V6 | Validation logic that doesn't evaluate | `NO-CHECK` | high |
| V7 | Evaluator trusting untrusted code/files (pytest-hook pattern) | `TRUST-OUT` | critical |

The scanner is heuristic (Python AST analysis + JSON config conventions). It is tuned for
no false negatives on the seven patterns; findings still deserve human review.

## Agent-Eval Checklist

| # | Requirement | Enforced by |
|---|---|---|
| C1 | Agent and evaluator environments isolated | `SecureRunner`: evaluator = separate process |
| C2 | Network egress disabled for the agent | config flag (see limitations) |
| C3 | Reference answers never agent-accessible | `SecureRunner`: gold never written to the workspace |
| C4 | No `eval()`/`exec()` on agent strings | scanner + runtime (response parsed as text) |
| C5 | Judge prompts sanitize agent input | scanner |
| C6 | Robust answer comparison | `exact_match` checker |
| C7 | Validation actually verifies correctness | scanner |
| C8 | No code loaded from agent-writable paths | checker ships with the evaluator |
| C9 | Fresh environment per task | `SecureRunner`: fresh temp dir per task |
| C10 | Segregated append-only logs | `SecureRunner`: `logs/agent.log`, `logs/eval.log` |

## Project layout

```
benchshield/
├── benchshield/
│   ├── scanner.py       # static analysis for the 7 vulnerability patterns
│   ├── checklist.py     # Agent-Eval Checklist (C1-C10) scoring
│   ├── sandbox.py       # VulnerableRunner / SecureRunner
│   ├── redteam.py       # zero-capability attack payloads + honest baseline agent
│   ├── benchdata.py     # deterministic 5-category mini benchmark
│   ├── example_bench.py # self-contained vulnerable-bench generator (demo target)
│   ├── eval_worker.py   # evaluator entry point (separate process)
│   ├── report.py        # markdown report rendering
│   └── __main__.py      # CLI: scan / demo / export-bench
├── examples/vulnerable_bench/   # demo benchmark containing all 7 patterns
├── tests/                       # 52 unit tests, stdlib unittest
└── pyproject.toml
```

## Design notes

- **The vulnerable runner is a feature.** `VulnerableRunner` deliberately reproduces the
  exploit preconditions so the attack payloads (and your defenses) can be tested end-to-end.
- **The demo is the paper, locally.** The `demo` command reproduces the headline Berkeley
  RDI result — 100% score with zero capability — and then blocks the exact same attacks
  with the secure runner.
- **No dependencies** so the tool can run anywhere, including CI and air-gapped machines.
- **Defense in depth in the scanner itself.** Dirty configs (unparseable JSON, non-object
  roots, wrong field types) are reported as findings instead of silently skipped — an
  audit tool must never claim "clean" on files it could not read.

## Limitations

- Scanner supports Python + JSON/JSONL benchmarks; YAML and docker-compose are on the roadmap.
- Network isolation (C2) is enforced on Linux runners via namespaces in the roadmap; today it
  is a config-declared property.
- The mini benchmark is fully verifiable (exact match); LLM-judge sanitization (V4) can only
  be flagged statically, not proven safe.

## Roadmap

- [ ] Docker-based task sandboxes (fresh container snapshot per task, no network namespace)
- [ ] YAML / docker-compose config scanning
- [ ] SWE-bench / Terminal-Bench task-format adapters
- [ ] Judge-prompt sanitizer library (defense, not just detection)

## Contributing

Issues and PRs are welcome. The test suite is plain `unittest` with zero dependencies:

```bash
python -m unittest discover -s tests -t .
```

## References

- UC Berkeley RDI, *Trustworthy Benchmarks* (2026): zero-capability agents exploit eight
  major benchmarks to near-perfect scores; source of the seven patterns and the checklist.
- Terminal-Bench 2.0: Docker-per-task isolation as the methodological standard.
- SWE-bench-Live: verified, contamination-free leaderboard practices.

## License

MIT — see [LICENSE](LICENSE).
