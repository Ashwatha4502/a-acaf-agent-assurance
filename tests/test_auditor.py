"""
Engine tests for A-ACAF Phase 1 (static config audit).

These encode the adversarial cases a governance reviewer would probe:
  - wildcard grants must not slip past the destructive-permissions control
  - disabling logging must never *improve* a score via dependent controls
  - undeclared configuration must fail closed, not pass silently
  - the scoring math must behave at the extremes (all-fail, all-pass, N/A)
"""

import copy
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.auditor import audit_agent, audit_fleet, SEVERITY_WEIGHT, _grade
from rubric.controls import CONTROLS, Severity
from mock_data.fleet import FLEET_BEFORE, FLEET_AFTER


def _finding(result, control_id):
    return next(f for f in result.findings if f.control_id == control_id)


def _minimal_clean_agent():
    """A fully remediated agent that should score 100."""
    return {
        "agent_id": "t-clean", "agent_name": "clean", "environment": "test",
        "iam_policy": {"statements": [
            {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::records/*"]},
        ]},
        "accessible_resources": [
            {"arn": "arn:aws:s3:::records", "data_classification": "PII"},
        ],
        "data_boundary": {"mode": "restricted", "allowed_classifications": ["PII"],
                          "processing_basis": "GDPR Art.6(1)(b)"},
        "logging": {"action_trace_enabled": True, "sink": "cloudtrail",
                    "immutable_store": True,
                    "captured_fields": ["model_id", "model_version", "prompt_hash"]},
        "guardrails": {"input_filtering": True, "output_validation": True},
        "has_downstream_execution": True,
        "human_oversight": {"approval_required_for": ["refund"], "kill_switch": True},
        "high_risk_actions": ["refund"],
        "model": {"model_id": "anthropic.claude-sonnet", "version": "20250219-v1"},
        "lifecycle": {"change_review": True},
    }


# ---------------------------------------------------------------------------
# Fail-closed: wildcard permissions
# ---------------------------------------------------------------------------

def test_service_wildcard_counts_as_destructive():
    """s3:* over a PII bucket must fail AAC-ACCESS-02 — a wildcard is a
    superset of every destructive action, not an exemption from them."""
    agent = _minimal_clean_agent()
    agent["iam_policy"] = {"statements": [{"actions": ["s3:*"], "resources": ["*"]}]}
    result = audit_agent(agent)
    assert _finding(result, "AAC-ACCESS-02").status == "FAIL"


def test_global_wildcard_counts_as_destructive():
    agent = _minimal_clean_agent()
    agent["iam_policy"] = {"statements": [{"actions": ["*"], "resources": ["*"]}]}
    result = audit_agent(agent)
    assert _finding(result, "AAC-ACCESS-02").status == "FAIL"


def test_enumerated_delete_on_sensitive_fails():
    agent = _minimal_clean_agent()
    agent["iam_policy"]["statements"].append(
        {"actions": ["s3:DeleteObject"], "resources": ["arn:aws:s3:::records"]})
    result = audit_agent(agent)
    assert _finding(result, "AAC-ACCESS-02").status == "FAIL"


def test_read_only_on_sensitive_passes():
    result = audit_agent(_minimal_clean_agent())
    assert _finding(result, "AAC-ACCESS-02").status == "PASS"


def test_wildcard_never_scores_higher_than_enumerated_delete():
    """Regression for the original bypass: the broadest grant must score
    no better than an explicitly destructive one."""
    enumerated = _minimal_clean_agent()
    enumerated["iam_policy"] = {"statements": [
        {"actions": ["s3:DeleteObject"], "resources": ["*"]}]}
    wildcard = _minimal_clean_agent()
    wildcard["iam_policy"] = {"statements": [
        {"actions": ["s3:*"], "resources": ["*"]}]}
    assert (audit_agent(wildcard).assurance_score
            <= audit_agent(enumerated).assurance_score)


# ---------------------------------------------------------------------------
# N/A semantics: dependent logging controls
# ---------------------------------------------------------------------------

def test_immutability_na_when_tracing_disabled():
    agent = _minimal_clean_agent()
    agent["logging"] = {"action_trace_enabled": False}
    result = audit_agent(agent)
    assert _finding(result, "AAC-LOG-01").status == "FAIL"
    assert _finding(result, "AAC-LOG-02").status == "N/A"
    assert _finding(result, "AAC-LOG-03").status == "N/A"


def test_disabling_logging_never_improves_score():
    """The original bug: with logging off, LOG-02/LOG-03 passed for free.
    Turning tracing ON (with immutable, attributable logs) must never
    produce a lower score than leaving it off."""
    logging_off = _minimal_clean_agent()
    logging_off["logging"] = {"action_trace_enabled": False}
    logging_on = _minimal_clean_agent()  # full, clean logging
    assert (audit_agent(logging_on).assurance_score
            > audit_agent(logging_off).assurance_score)


def test_na_not_counted_as_passed():
    agent = _minimal_clean_agent()
    agent["logging"] = {"action_trace_enabled": False}
    s = audit_agent(agent).summary
    assert s["not_assessable"] == 2
    assert s["passed"] + s["failed"] + s["not_assessable"] == s["total_controls"]


# ---------------------------------------------------------------------------
# Fail-closed: undeclared configuration
# ---------------------------------------------------------------------------

def test_unrestricted_boundary_touching_pii_requires_basis():
    """An undeclared boundary must not dodge the lawful-basis control when
    the agent can actually reach PII/PHI resources."""
    agent = _minimal_clean_agent()
    agent["data_boundary"] = {"mode": "unrestricted"}
    result = audit_agent(agent)
    assert _finding(result, "AAC-DATA-02").status == "FAIL"


def test_undeclared_downstream_execution_fails_closed():
    agent = _minimal_clean_agent()
    del agent["has_downstream_execution"]
    agent["guardrails"] = {"input_filtering": True}  # no output_validation
    result = audit_agent(agent)
    assert _finding(result, "AAC-RES-02").status == "FAIL"


def test_explicitly_no_downstream_execution_passes_without_validation():
    agent = _minimal_clean_agent()
    agent["has_downstream_execution"] = False
    agent["guardrails"] = {"input_filtering": True}
    result = audit_agent(agent)
    assert _finding(result, "AAC-RES-02").status == "PASS"


def test_empty_config_does_not_crash_and_scores_badly():
    result = audit_agent({})
    assert result.assurance_score <= 20
    assert result.grade.startswith("F")


# ---------------------------------------------------------------------------
# Scoring properties and demo regression
# ---------------------------------------------------------------------------

def test_clean_agent_scores_100():
    result = audit_agent(_minimal_clean_agent())
    assert result.assurance_score == 100
    assert result.summary["failed"] == 0


def test_demo_fleet_regression_scores():
    """Pin the demo narrative. If a control or weight changes, this fails
    loudly and the README numbers must be re-verified."""
    before = [r.assurance_score for r in audit_fleet(FLEET_BEFORE)]
    after = [r.assurance_score for r in audit_fleet(FLEET_AFTER)]
    assert before == [0, 35, 48]
    assert after == [100, 100, 100]


def test_grade_boundaries():
    assert _grade(90).startswith("A")
    assert _grade(89).startswith("B")
    assert _grade(60).startswith("C")
    assert _grade(59).startswith("D")
    assert _grade(39).startswith("F")


def test_severity_weights_are_ordered():
    assert (SEVERITY_WEIGHT[Severity.CRITICAL]
            > SEVERITY_WEIGHT[Severity.HIGH]
            > SEVERITY_WEIGHT[Severity.MEDIUM]
            > SEVERITY_WEIGHT[Severity.LOW])


def test_owasp_mappings_use_2025_numbering_only():
    """LLM08 was Excessive Agency in the 2023 list; in the 2025 list it is
    Vector and Embedding Weaknesses, which no A-ACAF control claims. Any
    LLM08 reference here would mean a version mix-up crept back in."""
    for c in CONTROLS:
        for ref in c.owasp_llm:
            assert not ref.startswith("LLM08"), f"{c.id} references LLM08"
