"""Clean evaluator example: passes the BenchShield audit."""
import json
from pathlib import Path

EVAL_DIR = Path("eval_dir")


def exact_match(response, gold):
    return str(response).strip() == str(gold).strip()


def main():
    tasks = json.loads((EVAL_DIR / "tasks_eval.json").read_text(encoding="utf-8"))
    responses = json.loads((EVAL_DIR / "responses.json").read_text(encoding="utf-8"))
    for task in tasks:
        reply = responses.get(task["id"], "")
        print(task["id"], exact_match(reply, task["gold"]))


if __name__ == "__main__":
    main()
