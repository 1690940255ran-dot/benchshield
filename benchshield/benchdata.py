"""Deterministic, verifiable mini-benchmark generation.

Each task is a small puzzle with a unique correct answer, so correctness can
be checked exactly (no LLM judges needed for the core benchmark).
"""
from __future__ import annotations

import random

CATEGORIES = ("math_add", "math_mul", "str_reverse", "count_vowels", "max_list")

_VOWELS = set("aeiou")


def _vowel_count(s: str) -> int:
    return sum(1 for c in s.lower() if c in _VOWELS)


def solve(category: str, params: dict) -> str:
    """Reference solver: produces the gold answer for a task."""
    if category == "math_add":
        return str(params["a"] + params["b"])
    if category == "math_mul":
        return str(params["a"] * params["b"])
    if category == "str_reverse":
        return params["s"][::-1]
    if category == "count_vowels":
        return str(_vowel_count(params["s"]))
    if category == "max_list":
        return str(max(params["items"]))
    raise ValueError(f"unknown category: {category}")


def make_prompt(category: str, params: dict) -> str:
    if category == "math_add":
        return f"What is {params['a']} + {params['b']}? Reply with the number only."
    if category == "math_mul":
        return f"What is {params['a']} x {params['b']}? Reply with the number only."
    if category == "str_reverse":
        return f"Reverse the string '{params['s']}'. Reply with the reversed string only."
    if category == "count_vowels":
        return f"How many vowels are in '{params['s']}'? Reply with the number only."
    if category == "max_list":
        return f"What is the maximum of {params['items']}? Reply with the number only."
    raise ValueError(f"unknown category: {category}")


def _make_task(rng: random.Random, index: int) -> dict:
    category = CATEGORIES[index % len(CATEGORIES)]
    if category == "math_add":
        params = {"a": rng.randint(2, 999), "b": rng.randint(2, 999)}
    elif category == "math_mul":
        params = {"a": rng.randint(2, 99), "b": rng.randint(2, 99)}
    elif category == "str_reverse":
        params = {"s": "".join(rng.choice("abcdefghij") for _ in range(rng.randint(5, 12)))}
    elif category == "count_vowels":
        params = {"s": "".join(rng.choice("abcdefghij") for _ in range(rng.randint(8, 20)))}
    else:  # max_list
        params = {"items": [rng.randint(1, 500) for _ in range(rng.randint(5, 10))]}
    return {
        "id": f"task-{index + 1:03d}",
        "category": category,
        "params": params,
        "prompt": make_prompt(category, params),
        "gold": solve(category, params),
    }


def generate_tasks(n: int = 50, seed: int = 42) -> list:
    """Generate `n` tasks deterministically (same seed -> identical tasks)."""
    rng = random.Random(seed)
    return [_make_task(rng, i) for i in range(n)]


def public_view(task: dict) -> dict:
    """The task as the agent is allowed to see it: gold answer stripped."""
    return {k: v for k, v in task.items() if k != "gold"}
