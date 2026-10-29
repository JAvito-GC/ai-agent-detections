"""
Exercises EVERY rule against its fixtures: every malicious event MUST fire, the benign
ones must NOT.

Rules are auto-discovered: each `rules/*.yml` declares `x_fixtures: <dir>` pointing to
`fixtures/<dir>/` with `malicious.json` + `benign.json`. A new rule with its fixture pair
joins the suite automatically; a rule WITHOUT fixtures fails the suite (nothing ships
untested).

    pip install -r requirements.txt
    PYTHONPATH=tests pytest -q
"""
import json
import pathlib

import pytest

from sigma_eval import load_rule, matching_indices

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE_FILES = sorted((ROOT / "rules").glob("*.yml"))


def _load_events(path: pathlib.Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def _fixture_dir(rule: dict) -> pathlib.Path:
    key = rule.get("x_fixtures")
    assert key, f"rule '{rule.get('title')}' does not declare x_fixtures"
    return ROOT / "fixtures" / key


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.stem)
def test_malicious_fires(rule_file):
    rule = load_rule(str(rule_file))
    events = _load_events(_fixture_dir(rule) / "malicious.json")
    hits = matching_indices(rule, events)
    missed = [i for i in range(len(events)) if i not in hits]
    assert not missed, f"{rule_file.name}: malicious fixture events {missed} did NOT fire"


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.stem)
def test_benign_quiet(rule_file):
    rule = load_rule(str(rule_file))
    events = _load_events(_fixture_dir(rule) / "benign.json")
    hits = matching_indices(rule, events)
    assert not hits, f"{rule_file.name}: benign fixture fired on events {hits} (false positive)"


def test_rules_exist():
    assert RULE_FILES, "no rules found in rules/"


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.stem)
def test_rule_well_formed(rule_file):
    """Every rule has id, title, detection and both fixtures."""
    rule = load_rule(str(rule_file))
    for key in ("id", "title", "detection"):
        assert rule.get(key), f"{rule_file.name}: missing '{key}'"
    fdir = _fixture_dir(rule)
    for kind in ("malicious.json", "benign.json"):
        assert (fdir / kind).exists(), f"{rule_file.name}: missing fixture {fdir.name}/{kind}"


SCALAR = (str, int, float, bool)


def _bad_values(selection):
    """Field values must be scalars or lists of scalars. An unquoted `- foo:` in YAML
    becomes a dict and silently never matches, so the rule loses that pattern."""
    maps = selection if isinstance(selection, list) else [selection]
    for m in maps:
        if not isinstance(m, dict):
            continue
        for field, value in m.items():
            for v in value if isinstance(value, list) else [value]:
                if not isinstance(v, SCALAR):
                    yield f"{field} -> {v!r}"


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.stem)
def test_detection_values_are_scalars(rule_file):
    rule = load_rule(str(rule_file))
    bad = [b for name, sel in rule["detection"].items() if name != "condition"
           for b in _bad_values(sel)]
    assert not bad, f"{rule_file.name}: non-scalar detection values (quote them in YAML): {bad}"
