"""Static scanner for the seven recurring agent-benchmark vulnerability
patterns documented by UC Berkeley RDI ("Trustworthy Benchmarks", 2026):

V1  No isolation between agent and evaluator
V2  Reference answers shipped with the test
V3  eval()/exec() on untrusted input
V4  LLM judge without input sanitization
V5  Weak string matching
V6  Validation logic that doesn't evaluate
V7  Trusting untrusted code output

The scan is heuristic (AST patterns + config conventions). It is designed to
have no false negatives on the seven patterns and to keep false positives
low; findings should always be reviewed by a human.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

GOLD_KEYS = {"answer", "gold", "gold_answer", "expected", "expected_answer",
             "solution", "ground_truth", "label"}
PROMPT_KEYS = {"prompt", "question", "task", "instruction", "description",
               "problem", "query"}
AGENT_DIR_KEYS = {"agent_dir", "agent_workspace", "workspace", "agent_root"}
EVAL_DIR_KEYS = {"eval_dir", "test_dir", "tests_dir", "evaluator_dir", "eval_root"}

RESP_RE = re.compile(r"resp|response|answer|output|agent", re.I)
GOLD_RE = re.compile(r"gold|answer|expected|solution|label|truth", re.I)
JUDGE_RE = re.compile(r"judge|grade|evaluat|score|correct|assistant|rubric", re.I)
UNTRUSTED_PATH_RE = re.compile(r"agent|workspace|checker|submission", re.I)
CHECKER_FN_RE = re.compile(r"^(check|validate|verify|reward|score|grade)", re.I)

DANGEROUS_CALLS = {"eval", "exec"}
LOADER_CALLS = {"open", "exec", "import_module", "spec_from_file_location",
                "__import__", "load_module", "runpy"}

SEVERITIES = {"V1": "high", "V2": "critical", "V3": "critical", "V4": "high",
              "V5": "medium", "V6": "high", "V7": "critical"}

SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}

VULN_CLASSES = {
    "V0": "File could not be parsed (audit incomplete for this file)",
    "V1": "No isolation between agent and evaluator",
    "V2": "Reference answers shipped with the test",
    "V3": "eval()/exec() on untrusted input",
    "V4": "LLM judge without input sanitization",
    "V5": "Weak string matching",
    "V6": "Validation logic that doesn't evaluate",
    "V7": "Trusting untrusted code output",
}

REMEDIATIONS = {
    "V1": ("Run the evaluator in a separate container/process, give the agent its own "
           "scratch directory, and disable network egress during tasks."),
    "V2": ("Strip gold answers from every file inside the agent workspace; deliver "
           "answers only to the evaluator process."),
    "V3": ("Never eval()/exec() agent output; parse it with a schema/JSON parser instead."),
    "V4": ("Sanitize agent text before interpolating it into judge prompts (escape "
           "delimiters, cap length, wrap in quoted blocks)."),
    "V5": ("Compare normalized exact answers or use a validated semantic scorer, "
           "not substring containment."),
    "V6": ("Make validators actually compare the response against the gold answer."),
    "V7": ("Ship checker code with the evaluator image; never import or execute "
           "anything from agent-writable paths."),
}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".benchshield"}


@dataclass
class Finding:
    rule: str
    vuln_class: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    remediation: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "vuln_class": self.vuln_class, "title": self.title,
            "severity": self.severity, "file": self.file, "line": self.line,
            "evidence": self.evidence, "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    root: str
    files_scanned: int
    findings: list = field(default_factory=list)

    @property
    def severity_counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: -SEVERITY_RANK.get(f.severity, 0))


COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml",
                 "compose.yaml", "docker-compose.override.yml"}
COMPOSE_AGENT_RE = re.compile(r"agent|solver|subject|player|policy", re.I)
COMPOSE_EVAL_RE = re.compile(r"eval|grader|checker|judge|scorer|verifier", re.I)


def _config_finding(p, result, root, rule, vuln_class, title, severity, evidence, remediation):
    result.findings.append(Finding(
        rule, vuln_class, title, severity,
        p.relative_to(root).as_posix(), 1, evidence, remediation))


def _load_json_config(p, result, root, counted):
    """Parse a JSON config file; returns dict or None (findings added on failure)."""
    rel_p = p.relative_to(root).as_posix()
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # Auditing a half-loaded config is worse than no audit at
        # all: it gives a false sense of safety. Surface the failure
        # as a V0 finding so the operator knows isolation/policy
        # could not be verified for this file.
        result.files_scanned += 1
        counted.add(str(p))
        result.findings.append(Finding(
            "CONFIG-PARSE", "V0",
            f"config file could not be parsed: {exc}",
            "info", rel_p, 0, "",
            "Fix the JSON syntax/encoding so the config can be audited; "
            "agent_dir / eval_dir / allow_network values for this file "
            "are unknown and isolation cannot be verified."))
        return None


def _load_yaml_config(p, result, root, counted):
    """Parse a YAML config file; returns dict or None (findings added on failure)."""
    from .yamlmini import YamlMiniError, loads
    rel_p = p.relative_to(root).as_posix()
    try:
        data = loads(p.read_text(encoding="utf-8"))
    except YamlMiniError as exc:
        result.files_scanned += 1
        counted.add(str(p))
        result.findings.append(Finding(
            "CONFIG-PARSE", "V0",
            f"YAML config could not be parsed: {exc}",
            "info", rel_p, 0, "",
            "Fix the YAML syntax so the config can be audited. BenchShield "
            "supports the common config subset (block mappings, sequences, "
            "scalars); anchors, flow collections and block literals are "
            "rejected to avoid silently misreading isolation settings."))
        return None
    except (OSError, UnicodeDecodeError) as exc:
        result.files_scanned += 1
        counted.add(str(p))
        result.findings.append(Finding(
            "CONFIG-PARSE", "V0", f"config file could not be read: {exc}",
            "info", rel_p, 0, "",
            "Fix the encoding so the config can be audited."))
        return None
    return data


def _check_config_shape(p, result, root, counted, data, kind="JSON"):
    """Validate the parsed config is an object; returns True if usable."""
    if isinstance(data, dict):
        return True
    result.files_scanned += 1
    counted.add(str(p))
    result.findings.append(Finding(
        "CONFIG-NONDICT", "V1",
        f"config file is not a {kind} object; isolation/policy "
        "fields cannot be checked",
        "high", p.relative_to(root).as_posix(), 1,
        f"top-level {kind} type: {type(data).__name__}",
        "Config files must be a mapping whose keys map to agent/evaluator "
        "directory paths and policy flags. Any other top-level shape "
        "silently disables isolation auditing."))
    return False


def scan_directory(root) -> ScanResult:
    """Scan a benchmark project directory for the seven vulnerability patterns."""
    root = Path(root)
    result = ScanResult(root=str(root), files_scanned=0, findings=[])
    if not root.is_dir():
        raise FileNotFoundError(f"not a directory: {root}")

    files = [
        p for p in sorted(root.rglob("*"))
        if p.is_file() and not (SKIP_DIRS & set(p.relative_to(root).parts))
    ]

    # Pass 1: config files first (they tell us where the agent workspace is),
    # then docker-compose files (V1 isolation rules).
    counted = set()
    config = {}
    for p in files:
        name_lower = p.name.lower()
        if p.suffix == ".json" and "config" in name_lower:
            data = _load_json_config(p, result, root, counted)
            if data is None:
                continue
            if not _check_config_shape(p, result, root, counted, data, "JSON"):
                continue
            result.files_scanned += 1
            counted.add(str(p))
            _scan_config(p, data, result, root)
            config.update(data)
        elif p.suffix in {".yaml", ".yml"} and "config" in name_lower:
            data = _load_yaml_config(p, result, root, counted)
            if data is None:
                continue
            if not _check_config_shape(p, result, root, counted, data, "YAML"):
                continue
            result.files_scanned += 1
            counted.add(str(p))
            _scan_config(p, data, result, root)
            config.update(data)
        elif name_lower in COMPOSE_NAMES:
            result.files_scanned += 1
            counted.add(str(p))
            _scan_compose(p, result, root)

    agent_dirs = [str(v) for k, v in config.items()
                  if k in AGENT_DIR_KEYS and isinstance(v, str)]

    # Pass 2: Python sources and task data files.
    for p in files:
        if str(p) in counted:
            continue
        if p.suffix == ".py":
            result.files_scanned += 1
            _scan_python(p, result, root)
        elif p.suffix in {".json", ".jsonl"}:
            result.files_scanned += 1
            _scan_data(p, result, root, agent_dirs)
        elif p.suffix in {".yaml", ".yml"}:
            result.files_scanned += 1
            _scan_yaml_data(p, result, root, agent_dirs)
    return result


# ---------------------------------------------------------------- compose rules

def _volumes_of(service: dict) -> set:
    """Named volumes and bind-mount sources referenced by a compose service."""
    vols = set()
    for entry in service.get("volumes", []) or []:
        if not isinstance(entry, str):
            continue
        source = entry.split(":")[0].strip()
        if source and source not in ("/", "."):
            vols.add(source)
    return vols


def _scan_compose(path: Path, result: ScanResult, root: Path) -> None:
    """V1 rules for docker-compose style benchmark setups.

    A compose file is the isolation boundary of a container-based bench.
    Two patterns make it porous:
      * the agent service runs with host networking (full egress + can
        reach the evaluator on localhost);
      * the agent and evaluator services mount the SAME volume/bind path,
        recreating the shared-workspace anti-pattern inside containers.
    """
    from .yamlmini import YamlMiniError, loads
    rel = path.relative_to(root).as_posix()
    try:
        data = loads(path.read_text(encoding="utf-8"))
    except YamlMiniError as exc:
        result.findings.append(Finding(
            "COMPOSE-PARSE", "V0", f"compose file could not be parsed: {exc}",
            "info", rel, 0, "",
            "Fix the YAML so the compose file can be audited; service "
            "isolation for this file is unknown."))
        return
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict) or not services:
        return

    agent_services = {n: s for n, s in services.items()
                      if isinstance(s, dict) and COMPOSE_AGENT_RE.search(n)
                      and not COMPOSE_EVAL_RE.search(n)}
    eval_services = {n: s for n, s in services.items()
                     if isinstance(s, dict) and COMPOSE_EVAL_RE.search(n)}

    # ENV-NET equivalent: agent container with host networking.
    for name, svc in agent_services.items():
        if svc.get("network_mode") == "host":
            result.findings.append(Finding(
                "COMPOSE-NET-HOST", "V1",
                f"agent service '{name}' uses network_mode: host",
                "high", rel, 1, f"services.{name}.network_mode: host",
                "Give the agent service its own network and remove it from "
                "the evaluator's network; never run the agent with host "
                "networking during tasks."))

    # ENV-SHARED equivalent: agent and evaluator share a volume/bind path.
    for aname, asvc in agent_services.items():
        avols = _volumes_of(asvc)
        if not avols:
            continue
        for ename, esvc in eval_services.items():
            shared = avols & _volumes_of(esvc)
            if shared:
                result.findings.append(Finding(
                    "COMPOSE-SHARED-VOL", "V1",
                    f"agent service '{aname}' and evaluator service "
                    f"'{ename}' mount the same volume(s)",
                    "high", rel, 1, f"shared: {sorted(shared)}",
                    "The agent must not share any volume or bind path with "
                    "the evaluator; move gold answers and checker code to "
                    "evaluator-only volumes."))


# ---------------------------------------------------------------- config rules

def _paths_overlap(a: str, b: str) -> bool:
    """True when the two paths share a parent (or one contains the other).

    String equality alone misses the common misconfiguration where
    ``agent_dir=ws/agent`` and ``eval_dir=ws/eval`` sit in the same
    ``ws/`` directory and so inherit each other's permissions / state.
    """
    def parts_of(p: str) -> list:
        return [seg for seg in p.replace("\\", "/").split("/") if seg not in ("", ".")]

    pa, pb = parts_of(a), parts_of(b)
    if not pa or not pb:
        return True
    common = 0
    for x, y in zip(pa, pb):
        if x != y:
            break
        common += 1
    # Shared storage: at least one matching prefix segment beyond root.
    return common > 0


def _scan_config(path: Path, data: dict, result: ScanResult, root: Path) -> None:
    rel = path.relative_to(root).as_posix()
    # Validate field types *before* using them. A wrong-type field makes
    # the matching rule unreliable, so report it instead of guessing.
    bad_fields = []
    for k, v in data.items():
        if k in AGENT_DIR_KEYS or k in EVAL_DIR_KEYS:
            if not isinstance(v, str):
                bad_fields.append((k, type(v).__name__, "string (path)"))
        elif k == "allow_network":
            if not isinstance(v, bool):
                bad_fields.append((k, type(v).__name__, "boolean"))
    if bad_fields:
        result.findings.append(Finding(
            "CONFIG-FIELD-TYPE", "V1",
            "config field has the wrong type; isolation/policy check is "
            "incomplete for this file",
            "high", rel, 1, f"bad fields: {bad_fields}",
            "agent_dir / eval_dir must be strings (paths); allow_network "
            "must be a boolean. Wrong types are flagged but treated as "
            "missing, so the corresponding V1 rule does not fire."))
    agent_vals = [str(v) for k, v in data.items() if k in AGENT_DIR_KEYS and isinstance(v, str)]
    eval_vals = [str(v) for k, v in data.items() if k in EVAL_DIR_KEYS and isinstance(v, str)]
    shared_pairs = sorted({
        (a, e) for a in agent_vals for e in eval_vals if _paths_overlap(a, e)
    })
    if shared_pairs:
        result.findings.append(Finding(
            "ENV-SHARED", "V1",
            "agent workspace and evaluator directory share a path or parent",
            "high", rel, 1, f"shared: {shared_pairs}", REMEDIATIONS["V1"]))
    if data.get("allow_network") is True:
        result.findings.append(Finding(
            "ENV-NET", "V1",
            "network egress allowed for the agent during tasks",
            "high", rel, 1, "allow_network: true", REMEDIATIONS["V1"]))


def _is_under(rel_posix: str, agent_dir: str) -> bool:
    agent_dir = agent_dir.strip()
    if agent_dir in {".", "", "./"}:
        return True
    parts = [seg for seg in agent_dir.replace("\\", "/").split("/") if seg not in ("", ".")]
    if not parts:
        return True
    rel_parts = rel_posix.split("/")
    return rel_parts[: len(parts)] == parts


def _scan_data(path: Path, result: ScanResult, root: Path, agent_dirs: list) -> None:
    rel = path.relative_to(root).as_posix()
    try:
        if path.suffix == ".jsonl":
            records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
            records = _flatten_records(data)
    except Exception:
        return

    dict_records = [r for r in records if isinstance(r, dict)]
    has_gold = any(set(r) & GOLD_KEYS for r in dict_records)
    if not has_gold:
        return
    has_prompt = any(set(r) & PROMPT_KEYS for r in dict_records)
    in_agent_dir = any(_is_under(rel, d) for d in agent_dirs) if agent_dirs else False
    if not (has_prompt or in_agent_dir):
        return

    n = sum(1 for r in dict_records if set(r) & GOLD_KEYS)
    reason = ("gold answers shipped next to prompts" if has_prompt
              else "gold-answer file stored inside the agent workspace")
    gold_keys = sorted({k for r in dict_records for k in r if k in GOLD_KEYS})
    result.findings.append(Finding(
        "DATA-LEAK", "V2",
        f"{n} record(s) with gold answers ({reason})",
        "critical", rel, 1, f"gold keys: {gold_keys}", REMEDIATIONS["V2"]))


def _flatten_records(node):
    """Walk a JSON/YAML document and return every dict that looks like a
    task record (i.e. sits inside a list anywhere in the tree).

    A task bundle is often shaped like ``{"metadata": ..., "tasks": [...]}``
    or ``{"benchmark": {"items": [...]}}``. Walking only the top level would
    miss every nested list of records and produce a false negative on
    DATA-LEAK.
    """
    found = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, list):
            for item in cur:
                if isinstance(item, dict):
                    found.append(item)
                elif isinstance(item, (list, dict)):
                    stack.append(item)
        elif isinstance(cur, dict):
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
    return found


def _scan_yaml_data(path: Path, result: ScanResult, root: Path, agent_dirs: list) -> None:
    """DATA-LEAK check for YAML task bundles (same logic as JSON data files)."""
    from .yamlmini import YamlMiniError, loads
    rel = path.relative_to(root).as_posix()
    try:
        data = loads(path.read_text(encoding="utf-8"))
    except (YamlMiniError, OSError, UnicodeDecodeError):
        return
    if data is None:
        return
    records = _flatten_records(data)
    dict_records = [r for r in records if isinstance(r, dict)]
    has_gold = any(set(r) & GOLD_KEYS for r in dict_records)
    if not has_gold:
        return
    has_prompt = any(set(r) & PROMPT_KEYS for r in dict_records)
    in_agent_dir = any(_is_under(rel, d) for d in agent_dirs) if agent_dirs else False
    if not (has_prompt or in_agent_dir):
        return

    n = sum(1 for r in dict_records if set(r) & GOLD_KEYS)
    reason = ("gold answers shipped next to prompts" if has_prompt
              else "gold-answer file stored inside the agent workspace")
    gold_keys = sorted({k for r in dict_records for k in r if k in GOLD_KEYS})
    result.findings.append(Finding(
        "DATA-LEAK", "V2",
        f"{n} record(s) with gold answers ({reason})",
        "critical", rel, 1, f"gold keys: {gold_keys}", REMEDIATIONS["V2"]))


# ---------------------------------------------------------------- python rules

def _subtree_text(node: ast.AST) -> str:
    parts = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            parts.append(n.id)
        elif isinstance(n, ast.Attribute):
            parts.append(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            parts.append(n.value)
    return " ".join(parts)


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _scan_python(path: Path, result: ScanResult, root: Path) -> None:
    rel = path.relative_to(root).as_posix()
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError) as exc:
        result.findings.append(Finding(
            "PARSE-ERROR", "V0", f"could not parse file: {exc}",
            "info", rel, 0, "",
            "Fix the syntax/encoding error so the file can be audited; "
            "findings for this file are incomplete."))
        return
    _RuleVisitor(rel, result, source.splitlines()).visit(tree)


class _RuleVisitor(ast.NodeVisitor):
    def __init__(self, rel: str, result: ScanResult, lines: list) -> None:
        self.rel = rel
        self.result = result
        self.lines = lines

    def _add(self, rule: str, vuln_class: str, title: str, node: ast.AST,
             severity: str = None) -> None:
        line = getattr(node, "lineno", 0)
        evidence = ""
        if 0 < line <= len(self.lines):
            evidence = self.lines[line - 1].strip()[:160]
        self.result.findings.append(Finding(
            rule, vuln_class, title,
            severity or SEVERITIES[vuln_class], self.rel, line,
            evidence, REMEDIATIONS.get(vuln_class, "")))

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        # V3: eval()/exec() on a non-literal (agent-controlled) string
        if name in DANGEROUS_CALLS and node.args and not isinstance(node.args[0], ast.Constant):
            self._add("EVAL-CALL", "V3", f"{name}() called on non-literal input", node)
        # V7: code/files loaded from an agent-writable location
        elif name in LOADER_CALLS and node.args:
            text = _subtree_text(node)
            if UNTRUSTED_PATH_RE.search(text):
                self._add("TRUST-OUT", "V7",
                          f"{name}() references an agent-writable path or variable", node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # V5: substring containment used to validate answers
        if any(isinstance(op, ast.In) for op in node.ops):
            text = _subtree_text(node)
            if GOLD_RE.search(text) and RESP_RE.search(text):
                self._add("WEAK-MATCH", "V5",
                          "substring containment used for answer validation", node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        # V4: agent-controlled text interpolated raw into a judge prompt
        names = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                names.append(_subtree_text(value.value))
        const_text = " ".join(
            str(v.value) for v in node.values if isinstance(v, ast.Constant))
        if names and RESP_RE.search(" ".join(names)) and JUDGE_RE.search(const_text):
            self._add("JUDGE-INJECT", "V4",
                      "LLM-judge prompt interpolates agent-controlled text unsanitized",
                      node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # V6: a validator that returns True without ever comparing anything
        if CHECKER_FN_RE.match(node.name):
            returns_true = any(
                isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
                and n.value.value is True
                for n in ast.walk(node))
            has_compare = any(isinstance(n, ast.Compare) for n in ast.walk(node))
            if returns_true and not has_compare:
                self._add("NO-CHECK", "V6",
                          f"{node.name}() can return True without validating", node)
        self.generic_visit(node)
