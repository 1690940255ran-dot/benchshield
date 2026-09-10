"""Deliberately VULNERABLE benchmark evaluator.

This file exists to demonstrate BenchShield's scanner. It intentionally
contains all seven vulnerability patterns documented by UC Berkeley RDI
("Trustworthy Benchmarks", 2026). DO NOT use it as a template.
"""
import importlib.util
import json
from pathlib import Path

CONFIG = json.loads(
    Path(__file__).parent.joinpath("bench_config.json").read_text(encoding="utf-8"))

# V1: agent and evaluator share one directory.
WORKSPACE = Path(CONFIG["agent_dir"])

# V2: the task file with gold answers lives inside the agent workspace.
TASKS = json.loads((WORKSPACE / "tasks.json").read_text(encoding="utf-8"))


def check(response, gold):
    # V6: never actually validates anything.
    return True


def looks_correct(response, gold):
    # V5: substring containment accepts wrong answers.
    return gold in response


def build_judge_prompt(response, gold):
    # V4: agent-controlled text is interpolated raw into the judge prompt.
    return f"You are a strict judge. Grade the answer: {response} Expected: {gold}"


def load_checker():
    # V7: checker code is imported from the agent-writable workspace.
    spec = importlib.util.spec_from_file_location("checker", WORKSPACE / "checker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evaluate(agent_response, task):
    # V3: the raw agent response is passed straight to eval().
    verdict = eval(agent_response)
    return bool(verdict)


def main():
    checker = load_checker()
    for task in TASKS:
        response = input(f"[{task['id']}] {task['prompt']}> ")
        if (evaluate(response, task) or looks_correct(response, task["gold"])
                or checker.check(response, task["gold"])):
            print("PASS")
        else:
            print("FAIL")


if __name__ == "__main__":
    main()
