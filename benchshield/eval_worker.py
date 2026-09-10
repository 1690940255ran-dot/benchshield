"""Evaluator worker: runs in a SEPARATE process from the agent.

Gold answers are delivered only to this process (never into the agent
workspace). The agent's response is read from a file path; the verdict is
printed as a single JSON line on stdout.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def exact_match(response: str, gold: str) -> bool:
    return str(response).strip() == str(gold).strip()


CHECKERS = {"exact_match": exact_match}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    spec = json.loads(argv[0])
    response = Path(spec["response_file"]).read_text(encoding="utf-8")
    ok = CHECKERS[spec["checker"]](response, spec["gold"])
    print(json.dumps({"pass": bool(ok)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
