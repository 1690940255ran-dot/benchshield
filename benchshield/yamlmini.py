"""A minimal YAML subset parser (zero dependencies).

Benchmark configs and docker-compose files use a small, regular slice of
YAML, so a purpose-built parser is both smaller and safer than pulling in
PyYAML. Supported syntax:

- block mappings (``key: value``) with arbitrary nesting via indentation
- block sequences (``- item``), including lists of mappings
- scalars: strings (plain / single-quoted / double-quoted), ints, floats,
  booleans (true/false/yes/no/on/off), null (null / ~ / empty)
- comments (``#`` at line start or after whitespace) and blank lines
- top-level document separator ``---`` (only the first document is parsed)

NOT supported (by design; these raise YamlMiniError so callers never get
silently wrong data): anchors/aliases, multi-line literals (``|``/``>``),
flow collections (``[a, b]``/``{a: b}``) other than empty ``[]``/``{}``,
tags, directives other than ``%YAML``.

This parser is intentionally conservative: when it cannot faithfully
represent the input, it fails loudly instead of guessing.
"""
from __future__ import annotations


class YamlMiniError(ValueError):
    """Raised when the input uses YAML features outside the supported subset."""


_BOOL_TRUE = {"true", "yes", "on"}
_BOOL_FALSE = {"false", "no", "off"}
_NULL = {"null", "~", ""}


def _parse_scalar(raw: str):
    s = raw.strip()
    if not s:
        return None
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return s[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1].replace("''", "'")
    if s.startswith("[") or s.startswith("{"):
        if s in ("[]", "{}"):
            return [] if s == "[]" else {}
        raise YamlMiniError(f"flow collections are not supported: {s[:40]}")
    if s.startswith("|") or s.startswith(">"):
        raise YamlMiniError("block literals (| and >) are not supported")
    low = s.lower()
    if low in _BOOL_TRUE:
        return True
    if low in _BOOL_FALSE:
        return False
    if low in _NULL:
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    if s.startswith("&") or s.startswith("*") or s.startswith("!"):
        raise YamlMiniError(f"anchors/aliases/tags are not supported: {s[:40]}")
    return s


def _strip_comment(line: str) -> str:
    """Remove a trailing comment, respecting simple quoting."""
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in (" ", "\t"):
                return line[:i]
    return line


class _Line:
    __slots__ = ("indent", "content", "num")

    def __init__(self, indent: int, content: str, num: int) -> None:
        self.indent = indent
        self.content = content
        self.num = num


def _preprocess(text: str) -> list:
    lines = []
    for num, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw.rstrip())
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped == "---":
            if lines:
                break  # second document: only the first is parsed
            continue
        if stripped.startswith("%"):
            continue  # %YAML directives
        if "\t" in line:
            raise YamlMiniError(f"line {num}: tabs are not allowed for indentation")
        indent = len(line) - len(line.lstrip(" "))
        lines.append(_Line(indent, stripped, num))
    return lines


def _split_key(content: str):
    """Split 'key: value' respecting quotes; return (key, value_str) or None."""
    in_single = in_double = False
    for i, ch in enumerate(content):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            if i + 1 == len(content) or content[i + 1] == " ":
                key = content[:i].strip()
                if key.startswith(("[", "{", "-", "?")):
                    return None
                if not key:
                    return None
                value = content[i + 1:].strip()
                return key, value
    return None


def _parse_block(lines: list, start: int, indent: int):
    """Parse one block (mapping or sequence) starting at lines[start].

    Returns (parsed_value, next_index).
    """
    if start >= len(lines):
        return None, start
    if lines[start].content.startswith("- "):
        return _parse_sequence(lines, start, indent)
    return _parse_mapping(lines, start, indent)


def _parse_sequence(lines: list, start: int, indent: int):
    items = []
    i = start
    while (i < len(lines) and lines[i].indent == indent
           and lines[i].content.startswith("- ")):
        item_text = lines[i].content[2:]
        kv = _split_key(item_text)
        if kv is None:
            items.append(_parse_scalar(item_text))
            i += 1
            continue
        # "- key: value" starts a nested mapping; its continuation lines are
        # indented deeper than the dash. Rebase them onto a virtual block
        # where the first mapping entry sits at indent 0.
        sub = [_Line(0, kv[0] + (": " + kv[1] if kv[1] else ":"), lines[i].num)]
        j = i + 1
        base = None
        while j < len(lines) and lines[j].indent > indent:
            if base is None:
                base = lines[j].indent
            sub.append(_Line(lines[j].indent - base, lines[j].content, lines[j].num))
            j += 1
        value, _ = _parse_block(sub, 0, 0)
        items.append(value)
        i = j
    return items, i


def _parse_mapping(lines: list, start: int, indent: int):
    mapping = {}
    i = start
    while i < len(lines) and lines[i].indent == indent:
        line = lines[i]
        if line.content.startswith("- "):
            break
        kv = _split_key(line.content)
        if kv is None:
            raise YamlMiniError(f"line {line.num}: cannot parse mapping entry: "
                                f"{line.content[:50]}")
        key_raw, value_str = kv
        key = _parse_scalar(key_raw)
        if not isinstance(key, str):
            raise YamlMiniError(f"line {line.num}: non-string key not supported")
        if value_str:
            mapping[key] = _parse_scalar(value_str)
            i += 1
            continue
        # No inline value: either a nested block, a sequence at the key's
        # own indent, or null.
        nxt = i + 1
        if nxt < len(lines) and lines[nxt].indent > indent:
            value, i = _parse_block(lines, nxt, lines[nxt].indent)
            mapping[key] = value
        elif (nxt < len(lines) and lines[nxt].indent == indent
              and lines[nxt].content.startswith("- ")):
            value, i = _parse_sequence(lines, nxt, indent)
            mapping[key] = value
        else:
            mapping[key] = None
            i += 1
    return mapping, i


def loads(text: str):
    """Parse a YAML subset document into Python objects.

    Raises YamlMiniError on unsupported syntax — never returns wrong data
    silently.
    """
    lines = _preprocess(text)
    if not lines:
        return None
    value, _ = _parse_block(lines, 0, lines[0].indent)
    return value
