import json
from pathlib import Path

from agents.PreprocessAgent import JoernAnalyzer, RawAlert
from agents.preprocess_components import AlertDeduplicator


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "data" / "joern_rules.json"


def _load_rules():
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))


def test_joern_rules_cover_phase2_high_risk_families():
    rules = _load_rules()
    names = {rule["name"] for rule in rules}
    labels = "\n".join(rule["query"] for rule in rules)

    assert names == {
        "buffer-overflow-source-sink",
        "out-of-bounds-index-or-length",
        "use-after-free-same-method",
        "double-free-same-method",
        "null-deref-explicit-null",
    }
    for label in [
        "buffer-overflow",
        "out-of-bounds",
        "use-after-free",
        "double-free",
        "null-pointer-dereference",
    ]:
        assert f"\\t{label}" in labels


def test_joern_rules_are_valid_for_loader_contract():
    analyzer = JoernAnalyzer()
    rules = analyzer.load_rules(str(RULES_PATH))

    assert len(rules) == 5
    for rule in rules:
        assert analyzer._validate_rule(rule)
        assert rule["query"].count("%s") == 1
        assert "importCpg(\"%s\")" in rule["query"]
        assert "println(s\"BNF\\t" in rule["query"]
        assert rule["severity"] in {"critical", "high"}
        assert ".code.headOption" not in rule["query"]


def test_joern_bnf_parser_accepts_function_and_evidence_fields():
    analyzer = JoernAnalyzer()
    output = "BNF\tfoo.c\t42\tptr\tptr freed at line 10 and used at line 42: ptr->x\tuse-after-free\n"

    alerts = analyzer._parse_joern_output(output, severity="error", project_path=str(ROOT))

    assert len(alerts) == 1
    assert alerts[0].file.endswith("foo.c")
    assert alerts[0].line == 42
    assert alerts[0].func == "ptr"
    assert alerts[0].msg == "use-after-free: ptr freed at line 10 and used at line 42: ptr->x"
    assert alerts[0].severity == "error"
    assert alerts[0].tool == "joern"


def test_deduplicator_merges_cppcheck_and_joern_high_risk_wording():
    deduplicator = AlertDeduplicator()
    alerts = [
        RawAlert(
            alert_id="cppcheck-uaf",
            file="demo.c",
            line=17,
            func="unknown",
            msg="Dereferencing 'buf' after it is deallocated / released",
            severity="error",
            tool="cppcheck",
        ),
        RawAlert(
            alert_id="joern-uaf",
            file="demo.c",
            line=17,
            func="buf",
            msg="use-after-free: buf freed at line 16 and used at line 17",
            severity="error",
            tool="joern",
        ),
    ]

    merged = deduplicator.deduplicate(alerts)

    assert len(merged) == 1
    assert merged[0].tool == "cppcheck+joern"
    assert "use-after-free" in merged[0].msg
