"""
sigma_eval.py — MINIMAL Sigma evaluator that exercises the AI-agent detection rules
against telemetry events (not just parsing the YAML: it actually evaluates match/no-match).

Supports the Sigma subset used by the rules in this repo:
  - selection blocks (field->value map); all fields in a block = AND
  - list value = OR (trailing `all` modifier = AND over the list)
  - modifiers: contains, startswith, endswith, re (+ re|i), gte, lte, gt, lt (equality by default)
  - condition: boolean expression with and / or / not / parentheses over block names

Events are FLAT dicts with dotted keys (OpenTelemetry GenAI style),
e.g. {"event_type": "tool_call", "tool.name": "shell", "tool.allowed": false}.

Only dependency: PyYAML (pip install pyyaml).
"""
from __future__ import annotations

import re
from typing import Any

import yaml


# --------------------------------------------------------------------------- #
# Matching one field with its modifiers                                       #
# --------------------------------------------------------------------------- #
def _field_matches(ev_val: Any, mods: list[str], expected: Any) -> bool:
    if isinstance(expected, list):
        if mods and mods[-1] == "all":
            return all(_field_matches(ev_val, mods[:-1], e) for e in expected)
        return any(_field_matches(ev_val, mods, e) for e in expected)

    mod = mods[0] if mods else ""

    if mod in ("contains", "startswith", "endswith", "re", "gte", "lte", "gt", "lt") and ev_val is None:
        return False

    if mod == "":
        # Sigma: plain string equality is case-insensitive
        if isinstance(ev_val, str) and isinstance(expected, str):
            return ev_val.lower() == expected.lower()
        return ev_val == expected or str(ev_val) == str(expected)
    if mod == "contains":
        return str(expected).lower() in str(ev_val).lower()
    if mod == "startswith":
        return str(ev_val).lower().startswith(str(expected).lower())
    if mod == "endswith":
        return str(ev_val).lower().endswith(str(expected).lower())
    if mod == "re":
        # Sigma: `re` is case-SENSITIVE (like Splunk/KQL); `|re|i` makes it insensitive
        flags = re.IGNORECASE if "i" in mods[1:] else 0
        return re.search(str(expected), str(ev_val), flags) is not None
    if mod in ("gte", "lte", "gt", "lt"):
        try:
            a, b = float(ev_val), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gte": a >= b, "lte": a <= b, "gt": a > b, "lt": a < b}[mod]
    raise ValueError(f"modificador Sigma no soportado: {mod}")


def _block_matches(block: dict, event: dict) -> bool:
    for spec, expected in block.items():
        parts = spec.split("|")
        field, mods = parts[0], parts[1:]
        if not _field_matches(event.get(field), mods, expected):
            return False
    return True


# --------------------------------------------------------------------------- #
# Boolean condition evaluator (recursive descent, no eval)                    #
# --------------------------------------------------------------------------- #
def _tokenize(cond: str) -> list[str]:
    return re.findall(r"\(|\)|\b\w+\b", cond)


def _eval_condition(cond: str, results: dict[str, bool]) -> bool:
    tokens = _tokenize(cond)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def nxt() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def expr() -> bool:  # OR
        val = term()
        while peek() == "or":
            nxt()
            val = term() or val
        return val

    def term() -> bool:  # AND
        val = factor()
        while peek() == "and":
            nxt()
            val = factor() and val
        return val

    def factor() -> bool:
        tok = peek()
        if tok == "not":
            nxt()
            return not factor()
        if tok == "(":
            nxt()
            val = expr()
            if peek() == ")":
                nxt()
            return val
        nxt()
        if tok not in results:
            raise ValueError(f"condition references an unknown block: {tok}")
        return results[tok]

    return expr()


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #
def load_rule(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def event_matches(rule: dict, event: dict) -> bool:
    detection = rule["detection"]
    blocks = {k: v for k, v in detection.items() if k != "condition"}
    results = {name: _block_matches(block, event) for name, block in blocks.items()}
    condition = str(detection.get("condition", "selection")).strip()
    return _eval_condition(condition, results)


def matching_indices(rule: dict, events: list[dict]) -> list[int]:
    """Indices of the events that fire the rule."""
    return [i for i, ev in enumerate(events) if event_matches(rule, ev)]
