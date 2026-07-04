"""
AI Agent Control Assurance Framework (A-ACAF)
Audit Engine
-------------------------------------------------------------------------------
Runs the control rubric against a normalized agent configuration and produces
audit-grade findings: severity, business risk, control reference, evidence, and
remediation. Also computes a per-agent assurance score.
-------------------------------------------------------------------------------
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rubric.controls import CONTROLS, Control, Severity


# Weight each severity for the assurance score. A CRITICAL failure hurts far
# more than a MEDIUM one — a flat pass/fail ratio would hide real risk.
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    control_id: str
    title: str
    domain: str
    status: str            # "PASS" or "FAIL"
    severity: str          # only meaningful on FAIL
    evidence: str
    business_risk: str
    remediation: str
    nist_ai_rmf: list
    iso_42001: list
    owasp_llm: list


@dataclass
class AgentAuditResult:
    agent_id: str
    agent_name: str
    environment: str
    assessed_at: str
    assurance_score: int          # 0-100, higher = better
    grade: str
    findings: list                # list[Finding]
    summary: dict                 # counts

    def failed(self) -> list:
        return [f for f in self.findings if f.status == "FAIL"]

    def passed(self) -> list:
        return [f for f in self.findings if f.status == "PASS"]


def _grade(score: int) -> str:
    if score >= 90: return "A - Deployment-ready"
    if score >= 75: return "B - Minor gaps"
    if score >= 60: return "C - Remediate before scale"
    if score >= 40: return "D - Significant exposure"
    return "F - Not fit for production"


def audit_agent(agent: dict) -> AgentAuditResult:
    findings: list[Finding] = []
    penalty = 0
    max_penalty = 0

    for ctrl in CONTROLS:
        weight = SEVERITY_WEIGHT[ctrl.severity]
        result, evidence = ctrl.check(agent)
        # result is True (pass), False (fail), or None (not assessable).
        # N/A controls are excluded from the denominator: they neither reward
        # nor punish, so disabling a parent control (e.g. logging) can never
        # improve the score via its dependent controls.
        if result is None:
            status = "N/A"
        elif result:
            status = "PASS"
            max_penalty += weight
        else:
            status = "FAIL"
            max_penalty += weight
            penalty += weight
        findings.append(Finding(
            control_id=ctrl.id,
            title=ctrl.title,
            domain=ctrl.domain.value,
            status=status,
            severity=ctrl.severity.value if status == "FAIL" else "-",
            evidence=evidence,
            business_risk=(ctrl.rationale if status == "FAIL"
                           else "Control not assessable for this configuration." if status == "N/A"
                           else "Control satisfied."),
            remediation=ctrl.remediation if status == "FAIL" else "-",
            nist_ai_rmf=ctrl.nist_ai_rmf,
            iso_42001=ctrl.iso_42001,
            owasp_llm=ctrl.owasp_llm,
        ))

    # Score: 100 minus the proportion of severity-weighted penalty incurred.
    score = round(100 * (1 - (penalty / max_penalty))) if max_penalty else 100

    fails = [f for f in findings if f.status == "FAIL"]
    n_na = sum(1 for f in findings if f.status == "N/A")
    summary = {
        "total_controls": len(findings),
        "passed": len(findings) - len(fails) - n_na,
        "failed": len(fails),
        "not_assessable": n_na,
        "critical": sum(1 for f in fails if f.severity == "CRITICAL"),
        "high": sum(1 for f in fails if f.severity == "HIGH"),
        "medium": sum(1 for f in fails if f.severity == "MEDIUM"),
        "low": sum(1 for f in fails if f.severity == "LOW"),
    }

    return AgentAuditResult(
        agent_id=agent.get("agent_id", "unknown"),
        agent_name=agent.get("agent_name", "unnamed-agent"),
        environment=agent.get("environment", "unknown"),
        assessed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        assurance_score=score,
        grade=_grade(score),
        findings=findings,
        summary=summary,
    )


def audit_fleet(agents: list[dict]) -> list[AgentAuditResult]:
    return [audit_agent(a) for a in agents]


if __name__ == "__main__":
    import json
    # quick smoke test with a deliberately bad agent
    bad = {
        "agent_id": "smoke-1", "agent_name": "smoke-test", "environment": "test",
        "iam_policy": {"statements": [{"actions": ["*"], "resources": ["*"]}]},
        "accessible_resources": [],
        "data_boundary": {"mode": "unrestricted"},
        "logging": {"action_trace_enabled": False},
        "guardrails": {},
        "human_oversight": {},
        "high_risk_actions": ["delete_records"],
        "model": {"version": "latest"},
        "lifecycle": {},
    }
    res = audit_agent(bad)
    print(f"{res.agent_name}: score {res.assurance_score} ({res.grade})")
    print("summary:", json.dumps(res.summary))
