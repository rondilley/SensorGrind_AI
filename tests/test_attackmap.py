"""attackmap rule-table contract + pipeline registration.

attackmap runs as part of the `analyzers` stage via sgquery.ANALYZER_ORDER
(not as a top-level evolve stage) and writes output/reports/attackmap/.
These tests pin the rule-table shape, that its source analyzers are real,
and that it stays registered and surfaced in the report.
"""
from __future__ import annotations

import re

import attackmap
import sgquery

TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?\b")


def test_attack_rules_are_well_formed():
    assert attackmap.ATTACK_RULES, "no ATT&CK rules defined"
    for rule in attackmap.ATTACK_RULES:
        assert len(rule) == 4, f"rule not a 4-tuple: {rule}"
        module, field, pattern, technique = rule
        assert module and field and technique
        assert TECH_RE.match(technique), f"technique id not T#### form: {technique}"


def test_attack_rule_source_modules_are_real_analyzers():
    """Each rule reads a known analyzer's report; guard against typos that
    would make the rule silently never fire."""
    known = set(sgquery.ANALYZER_ORDER)
    for module, *_ in attackmap.ATTACK_RULES:
        assert module in known, f"attackmap rule references unknown analyzer {module}"


def test_attackmap_runs_after_its_inputs_in_analyzer_order():
    order = sgquery.ANALYZER_ORDER
    assert "attackmap" in order, "attackmap not in sgquery.ANALYZER_ORDER"
    am = order.index("attackmap")
    for dep in ("portscans", "rdpbrute", "probesigs", "droppers", "botnetcls"):
        assert order.index(dep) < am, f"attackmap must run after {dep}"


def test_attackmap_result_schema_columns():
    assert attackmap.RESULT_SCHEMA.names == ["technique", "evidence_count", "sources"]


def test_http_template_rules_wellformed():
    import re
    assert attackmap.HTTP_TEMPLATE_RULES, "no HTTP template rules"
    for rx, tech in attackmap.HTTP_TEMPLATE_RULES:
        assert isinstance(rx, re.Pattern), f"not a compiled regex: {rx}"
        assert TECH_RE.match(tech), f"technique id not T#### form: {tech}"


def test_report_surfaces_attackmap():
    """A2: the ATT&CK coverage must be rendered in the comprehensive report,
    not just computed to a parquet nobody reads."""
    from pathlib import Path
    src = (Path(attackmap.__file__).resolve().parent
           / "report" / "comprehensive_report.py").read_text()
    assert "attackmap" in src, "comprehensive report does not surface attackmap"
    assert "ATT&CK" in src
