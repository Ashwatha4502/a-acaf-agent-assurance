"""
AI Agent Control Assurance Framework (A-ACAF)
Control Rubric
-------------------------------------------------------------------------------
Each control maps a concrete, machine-checkable condition on a deployed AI agent
to one or more governance frameworks:

  - NIST AI RMF 1.0      (GOVERN / MAP / MEASURE / MANAGE functions)
  - ISO/IEC 42001:2023   (AI Management System clauses & Annex A controls)
  - OWASP LLM Top 10 (2025 list)

Mapping principles (see DESIGN.md for the full rationale):
  - Mappings use the 2025 OWASP numbering only. Controls with no honest OWASP
    equivalent carry an empty mapping rather than a forced one — logging, for
    example, is not an OWASP LLM Top 10 entry.
  - Checks are FAIL-CLOSED: absent or undeclared configuration is treated as
    the risky state, never as a pass.
  - A check may return None (not True/False) meaning NOT ASSESSABLE for this
    configuration (e.g. log immutability when logging is disabled entirely).
    N/A controls are excluded from the score denominator.

This module is the single source of truth. The audit engine consumes it; the
report generator renders it. Nothing else defines controls.
-------------------------------------------------------------------------------
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Domain(str, Enum):
    ACCESS = "Access & Least Privilege"
    DATA = "Data Governance & Boundaries"
    LOGGING = "Auditability & Traceability"
    RESILIENCE = "Adversarial Resilience"
    OVERSIGHT = "Human Oversight & Control"
    LIFECYCLE = "Model Lifecycle & Change Mgmt"


@dataclass
class Control:
    id: str                       # e.g. "AAC-ACCESS-01"
    title: str
    domain: Domain
    severity: Severity            # severity if the control FAILS
    rationale: str                # why this matters, in audit language
    # Framework mappings — the credibility multiplier
    nist_ai_rmf: list[str]
    iso_42001: list[str]
    owasp_llm: list[str]          # 2025 numbering; empty = no honest mapping
    # The actual check: takes an agent-config dict, returns (result, evidence)
    # where result is True (pass), False (fail), or None (not assessable)
    check: Callable[[dict], tuple[Optional[bool], str]]
    remediation: str


# ---------------------------------------------------------------------------
# CHECK FUNCTIONS
# Each takes a normalized agent-config dict and returns (result, evidence)
# where result is True / False / None (N/A). All checks fail closed: missing
# or undeclared configuration is treated as the risky state.
# ---------------------------------------------------------------------------

# Services where a service-level wildcard implies destructive capability
_DESTRUCTIVE_PREFIXES = ("s3:Delete", "s3:Put", "dynamodb:Delete", "rds:Delete")
_DESTRUCTIVE_SERVICES = ("s3", "dynamodb", "rds")


def _action_is_destructive(action: str) -> bool:
    """A '*' or 'service:*' grant is a superset of every destructive action in
    that service, so wildcards are treated as destructive — otherwise an agent
    with s3:* would pass a control that an agent with s3:DeleteObject fails."""
    if action == "*":
        return True
    if action.endswith(":*") and action.split(":")[0] in _DESTRUCTIVE_SERVICES:
        return True
    return any(action.startswith(p) for p in _DESTRUCTIVE_PREFIXES)


def _chk_no_wildcard_actions(agent: dict) -> tuple[Optional[bool], str]:
    """Agent's execution role must not grant wildcard (*) actions.
    Not assessable if no IAM policy is provided — absence of evidence is not
    a pass; the agent's permissions simply cannot be audited."""
    if "iam_policy" not in agent:
        return None, "Not assessable: no IAM policy provided for this agent."
    offending = []
    for stmt in agent.get("iam_policy", {}).get("statements", []):
        actions = stmt.get("actions", [])
        actions = actions if isinstance(actions, list) else [actions]
        for a in actions:
            if a == "*" or a.endswith(":*"):
                offending.append(a)
    if offending:
        return False, f"Wildcard actions granted to agent role: {', '.join(sorted(set(offending)))}"
    return True, "No wildcard actions found in agent execution role."


def _chk_no_destructive_on_sensitive(agent: dict) -> tuple[Optional[bool], str]:
    """Agent must not hold destructive perms (incl. wildcards) on data tagged
    sensitive/PHI/PII. Wildcards count: '*' and 's3:*' imply Delete/Put.
    Not assessable if no IAM policy is provided."""
    if "iam_policy" not in agent:
        return None, "Not assessable: no IAM policy provided for this agent."
    hits = []
    sensitive_resources = {r["arn"] for r in agent.get("accessible_resources", [])
                           if r.get("data_classification") in ("PHI", "PII", "sensitive")}
    for stmt in agent.get("iam_policy", {}).get("statements", []):
        actions = stmt.get("actions", [])
        actions = actions if isinstance(actions, list) else [actions]
        resources = stmt.get("resources", [])
        resources = resources if isinstance(resources, list) else [resources]
        for a in actions:
            if _action_is_destructive(a):
                for r in resources:
                    if r == "*" or r in sensitive_resources:
                        hits.append(f"{a} on {r}")
    if hits:
        return False, f"Destructive permissions (incl. wildcard supersets) on sensitive data: {'; '.join(hits)}"
    return True, "No destructive permissions on PHI/PII/sensitive resources."


def _chk_data_boundary_declared(agent: dict) -> tuple[Optional[bool], str]:
    """Agent must declare an explicit allowed-data-domain (no implicit 'access everything')."""
    boundary = agent.get("data_boundary")
    if not boundary or boundary.get("mode") == "unrestricted":
        return False, "Agent has no declared data boundary (unrestricted data access)."
    scopes = boundary.get("allowed_classifications", [])
    return True, f"Data boundary declared. Allowed classifications: {', '.join(scopes) or 'none'}."


def _chk_pii_not_in_scope_without_basis(agent: dict) -> tuple[Optional[bool], str]:
    """If agent touches PII/PHI — via its declared boundary OR the resources it
    can actually reach — it must declare a lawful/processing basis. Checking
    reachable resources closes the loophole where an undeclared (unrestricted)
    boundary would otherwise dodge the control entirely."""
    boundary = agent.get("data_boundary") or {}
    declared = set(boundary.get("allowed_classifications", []))
    reachable = {r.get("data_classification") for r in agent.get("accessible_resources", [])}
    touches_sensitive = bool({"PII", "PHI"} & (declared | reachable))
    if touches_sensitive and not boundary.get("processing_basis"):
        return False, "Agent can reach PII/PHI but declares no processing basis (GDPR Art.6 / HIPAA)."
    return True, "PII/PHI processing basis declared or no PII/PHI in scope."


def _chk_action_logging_enabled(agent: dict) -> tuple[Optional[bool], str]:
    """All agent tool-invocations must be logged (CloudTrail / agent trace)."""
    log = agent.get("logging", {})
    if not log.get("action_trace_enabled"):
        return False, "Agent action tracing is disabled — invocations are not auditable."
    return True, f"Action tracing enabled (sink: {log.get('sink', 'unknown')})."


def _chk_log_immutability(agent: dict) -> tuple[Optional[bool], str]:
    """Audit logs must be tamper-evident (immutable store / object lock).
    Not assessable when tracing is disabled — there are no logs to protect,
    and that failure is already captured (CRITICAL) by AAC-LOG-01."""
    log = agent.get("logging", {})
    if not log.get("action_trace_enabled"):
        return None, "Not assessable: action tracing is disabled (see AAC-LOG-01)."
    if not log.get("immutable_store"):
        return False, "Action logs are mutable — no object-lock / immutability guarantee."
    return True, "Audit logs stored in immutable / tamper-evident store."


def _chk_decision_attribution(agent: dict) -> tuple[Optional[bool], str]:
    """Each logged action must capture model id + version + prompt hash.
    Not assessable when tracing is disabled (captured by AAC-LOG-01)."""
    log = agent.get("logging", {})
    if not log.get("action_trace_enabled"):
        return None, "Not assessable: action tracing is disabled (see AAC-LOG-01)."
    captured = set(log.get("captured_fields", []))
    required = {"model_id", "model_version", "prompt_hash"}
    missing = required - captured
    if missing:
        return False, f"Log records missing attribution fields: {', '.join(sorted(missing))}."
    return True, "Logs capture model id, version, and prompt hash for full attribution."


def _chk_prompt_injection_controls(agent: dict) -> tuple[Optional[bool], str]:
    """Agent must have input-side guardrails against prompt injection / jailbreak."""
    g = agent.get("guardrails", {})
    if not g.get("input_filtering"):
        return False, "No input filtering / injection guardrail configured (OWASP LLM01)."
    return True, f"Input guardrail active (provider: {g.get('provider', 'unknown')})."


def _chk_output_handling(agent: dict) -> tuple[Optional[bool], str]:
    """Agent output feeding downstream systems must be treated as untrusted.
    Fail-closed: if downstream execution is undeclared, assume it exists."""
    g = agent.get("guardrails", {})
    downstream = agent.get("has_downstream_execution")
    if downstream is None:
        downstream = True  # undeclared = assume worst case
    if downstream and not g.get("output_validation"):
        return False, "Agent output drives downstream actions with no output validation (OWASP LLM05)."
    return True, "Output validation configured or downstream execution explicitly absent."


def _chk_human_checkpoint_high_risk(agent: dict) -> tuple[Optional[bool], str]:
    """High-impact actions must require human-in-the-loop approval.
    Not assessable if the high-risk action set was never declared — a config
    cannot vacuously pass this control by omitting the declaration. Whether
    the declaration itself is COMPLETE is a runtime question (Phase 2:
    compare observed actions against declared scope)."""
    if "high_risk_actions" not in agent:
        return None, "Not assessable: no high-risk action declaration provided."
    hitl = agent.get("human_oversight", {})
    high_risk_actions = agent.get("high_risk_actions", [])
    gated = set(hitl.get("approval_required_for", []))
    ungated = [a for a in high_risk_actions if a not in gated]
    if ungated:
        return False, f"High-risk actions run without human approval: {', '.join(ungated)}."
    return True, "All declared high-risk actions gated by human approval."


def _chk_kill_switch(agent: dict) -> tuple[Optional[bool], str]:
    """Operators must be able to disable/pause the agent (documented kill switch)."""
    hitl = agent.get("human_oversight", {})
    if not hitl.get("kill_switch"):
        return False, "No documented kill switch / pause mechanism for the agent."
    return True, "Kill switch / pause mechanism documented and available."


def _chk_model_pinned(agent: dict) -> tuple[Optional[bool], str]:
    """Model version must be pinned (not 'latest') for reproducible governance."""
    m = agent.get("model", {})
    ver = str(m.get("version", "")).lower()
    if ver in ("", "latest", "auto"):
        return False, f"Model version not pinned (='{ver or 'unset'}') — decisions not reproducible."
    return True, f"Model pinned to {m.get('model_id')} @ {m.get('version')}."


def _chk_change_review(agent: dict) -> tuple[Optional[bool], str]:
    """Model/prompt changes must go through a documented review before production."""
    lc = agent.get("lifecycle", {})
    if not lc.get("change_review"):
        return False, "No change-review process for model/prompt updates (uncontrolled drift risk)."
    return True, "Model/prompt changes gated by documented review process."


# ---------------------------------------------------------------------------
# THE CONTROL SET
# ISO/IEC 42001:2023 Annex A references use the actual control titles from the
# standard. OWASP references use the 2025 numbering; an empty list means the
# control has no honest OWASP LLM Top 10 equivalent (see DESIGN.md).
# ---------------------------------------------------------------------------

CONTROLS: list[Control] = [
    # ---- ACCESS ----
    Control(
        id="AAC-ACCESS-01",
        title="Agent execution role avoids wildcard permissions",
        domain=Domain.ACCESS,
        severity=Severity.HIGH,
        rationale=("An agent role granting '*' or 'service:*' actions violates least privilege. "
                   "Because agents act autonomously, an over-broad role converts a single prompt "
                   "injection into arbitrary account actions."),
        nist_ai_rmf=["MANAGE-2.1", "GOVERN-1.2"],
        iso_42001=["A.9.4 (Intended use of the AI system)", "Clause 8.1 (Operational planning & control)"],
        owasp_llm=["LLM06: Excessive Agency"],
        check=_chk_no_wildcard_actions,
        remediation=("Scope the agent role to the explicit set of actions required for its task. "
                     "Replace wildcards with enumerated actions and resource ARNs."),
    ),
    Control(
        id="AAC-ACCESS-02",
        title="No destructive permissions over sensitive data",
        domain=Domain.ACCESS,
        severity=Severity.CRITICAL,
        rationale=("Delete/overwrite permissions on PHI/PII/sensitive stores let an autonomous or "
                   "manipulated agent cause irreversible data loss or integrity compromise. "
                   "Wildcard grants count — 's3:*' is a superset of every destructive S3 action."),
        nist_ai_rmf=["MANAGE-2.1", "MEASURE-2.6"],
        iso_42001=["A.9.4 (Intended use of the AI system)", "A.7.4 (Quality of data for AI systems)"],
        owasp_llm=["LLM06: Excessive Agency", "LLM02: Sensitive Information Disclosure"],
        check=_chk_no_destructive_on_sensitive,
        remediation=("Remove Delete*/Put* actions and service wildcards on sensitive resources. "
                     "Grant read-only where the workflow allows; route writes through a reviewed "
                     "service, not the agent."),
    ),
    # ---- DATA ----
    Control(
        id="AAC-DATA-01",
        title="Explicit data boundary is declared",
        domain=Domain.DATA,
        severity=Severity.HIGH,
        rationale=("Governance requires knowing exactly which data an agent may touch. An "
                   "unrestricted agent cannot be assessed for data-handling compliance."),
        nist_ai_rmf=["MAP-4.1", "GOVERN-1.3"],
        iso_42001=["A.4.3 (Data resources)", "A.9.4 (Intended use of the AI system)"],
        owasp_llm=["LLM02: Sensitive Information Disclosure"],
        check=_chk_data_boundary_declared,
        remediation=("Define an explicit data boundary: allowed classifications and source systems. "
                     "Default-deny any data domain not enumerated."),
    ),
    Control(
        id="AAC-DATA-02",
        title="Lawful processing basis for PII/PHI",
        domain=Domain.DATA,
        severity=Severity.HIGH,
        rationale=("If the agent can reach personal or health data — declared or not — a documented "
                   "processing basis (GDPR Art.6 / HIPAA permitted use) is a hard compliance "
                   "requirement."),
        nist_ai_rmf=["MAP-4.1", "GOVERN-1.1"],
        iso_42001=["A.7.3 (Acquisition of data — data rights)", "A.2.3 (Alignment with other organisational policies)"],
        owasp_llm=["LLM02: Sensitive Information Disclosure"],
        check=_chk_pii_not_in_scope_without_basis,
        remediation=("Record the lawful/processing basis for each sensitive data class the agent "
                     "can reach, or remove that class from the agent's boundary and resources."),
    ),
    # ---- LOGGING ----
    Control(
        id="AAC-LOG-01",
        title="Agent action tracing is enabled",
        domain=Domain.LOGGING,
        severity=Severity.CRITICAL,
        rationale=("Without a complete action trace you cannot reconstruct what the agent did. "
                   "This defeats incident response, audit, and accountability entirely."),
        nist_ai_rmf=["MEASURE-2.8", "MANAGE-4.1"],
        iso_42001=["A.6.2.8 (AI system recording of event logs)", "A.6.2.6 (AI system operation and monitoring)"],
        owasp_llm=[],  # logging is not an OWASP LLM Top 10 (2025) entry
        check=_chk_action_logging_enabled,
        remediation=("Enable full action/tool-invocation tracing to a durable log sink "
                     "(e.g. CloudTrail + agent trace) before production use."),
    ),
    Control(
        id="AAC-LOG-02",
        title="Audit logs are tamper-evident",
        domain=Domain.LOGGING,
        severity=Severity.HIGH,
        rationale=("Mutable logs can be altered post-incident, destroying evidentiary value and "
                   "failing SOC 2 / ISO logging-integrity expectations."),
        nist_ai_rmf=["MEASURE-2.8", "MANAGE-4.1"],
        iso_42001=["A.6.2.8 (AI system recording of event logs)", "Clause 9.1 (Monitoring, measurement, analysis)"],
        owasp_llm=[],
        check=_chk_log_immutability,
        remediation=("Store logs in an immutable/object-locked destination with retention controls "
                     "and restricted delete permissions."),
    ),
    Control(
        id="AAC-LOG-03",
        title="Decisions are attributable to model + version + prompt",
        domain=Domain.LOGGING,
        severity=Severity.MEDIUM,
        rationale=("To govern an agent you must be able to answer 'which model, which version, on "
                   "what input made this decision'. Missing attribution blocks root-cause analysis."),
        nist_ai_rmf=["MEASURE-2.9", "MANAGE-4.1"],
        iso_42001=["A.6.2.8 (AI system recording of event logs)", "A.4.4 (Tooling resources)"],
        owasp_llm=[],
        check=_chk_decision_attribution,
        remediation=("Extend log schema to capture model_id, model_version, and a prompt hash on "
                     "every agent action."),
    ),
    # ---- RESILIENCE ----
    Control(
        id="AAC-RES-01",
        title="Input guardrails against prompt injection",
        domain=Domain.RESILIENCE,
        severity=Severity.HIGH,
        rationale=("Prompt injection is the top LLM risk. An agent with tool access and no input "
                   "filtering can be steered into unintended actions by hostile input."),
        nist_ai_rmf=["MEASURE-2.7", "MANAGE-2.2"],
        iso_42001=["A.6.2.6 (AI system operation and monitoring — AI-specific threats)", "A.6.2.2 (AI system requirements and specification)"],
        owasp_llm=["LLM01: Prompt Injection"],
        check=_chk_prompt_injection_controls,
        remediation=("Configure input guardrails (e.g. Bedrock Guardrails) with injection/jailbreak "
                     "filters and denied-topic policies scoped to the agent's role."),
    ),
    Control(
        id="AAC-RES-02",
        title="Agent output validated before downstream execution",
        domain=Domain.RESILIENCE,
        severity=Severity.HIGH,
        rationale=("When agent output triggers downstream actions, treating it as trusted lets a "
                   "manipulated model inject commands/queries into other systems. Undeclared "
                   "downstream execution is assumed present (fail-closed)."),
        nist_ai_rmf=["MEASURE-2.7", "MANAGE-2.2"],
        iso_42001=["A.6.2.6 (AI system operation and monitoring)", "A.6.2.2 (AI system requirements and specification)"],
        owasp_llm=["LLM05: Improper Output Handling"],
        check=_chk_output_handling,
        remediation=("Validate, encode, or schema-constrain agent output before it reaches "
                     "downstream executors (DB, shell, API), or explicitly declare the absence "
                     "of downstream execution."),
    ),
    # ---- OVERSIGHT ----
    Control(
        id="AAC-OVS-01",
        title="Human approval gates high-risk actions",
        domain=Domain.OVERSIGHT,
        severity=Severity.CRITICAL,
        rationale=("High-impact actions (payments, deletions, external comms) executed with no "
                   "human checkpoint remove the accountability the EU AI Act and NIST require."),
        nist_ai_rmf=["MANAGE-2.3", "GOVERN-1.4"],
        iso_42001=["A.9.2 (Processes for responsible use — human oversight)", "A.9.3 (Objectives for responsible use of AI system)"],
        owasp_llm=["LLM06: Excessive Agency"],
        check=_chk_human_checkpoint_high_risk,
        remediation=("Define the set of high-risk actions and require documented human approval "
                     "(HITL) before the agent executes any of them."),
    ),
    Control(
        id="AAC-OVS-02",
        title="Kill switch / pause mechanism exists",
        domain=Domain.OVERSIGHT,
        severity=Severity.HIGH,
        rationale=("Operators must be able to stop a misbehaving agent immediately. No kill switch "
                   "means no bounded blast radius."),
        nist_ai_rmf=["MANAGE-2.3", "MANAGE-4.1"],
        iso_42001=["A.9.2 (Processes for responsible use — pause/stop conditions)", "A.6.2.6 (AI system operation and monitoring)"],
        owasp_llm=["LLM06: Excessive Agency"],
        check=_chk_kill_switch,
        remediation=("Implement and document a tested mechanism to pause/disable the agent and "
                     "revoke its credentials on demand."),
    ),
    # ---- LIFECYCLE ----
    Control(
        id="AAC-LC-01",
        title="Model version is pinned",
        domain=Domain.LIFECYCLE,
        severity=Severity.MEDIUM,
        rationale=("A 'latest' model reference means the decision-making system can change silently. "
                   "Governance requires reproducibility of which model produced which decision."),
        nist_ai_rmf=["MAP-2.3", "MANAGE-4.1"],
        iso_42001=["A.4.4 (Tooling resources — reproducibility)", "A.6.2.5 (AI system deployment)"],
        owasp_llm=["LLM03: Supply Chain"],
        check=_chk_model_pinned,
        remediation=("Pin the agent to a specific model id and version. Promote new versions only "
                     "through the change-review process."),
    ),
    Control(
        id="AAC-LC-02",
        title="Model/prompt changes go through review",
        domain=Domain.LIFECYCLE,
        severity=Severity.MEDIUM,
        rationale=("Uncontrolled prompt/model changes are drift. A documented review gate is the "
                   "AI-system equivalent of change management."),
        nist_ai_rmf=["MANAGE-4.1", "GOVERN-1.5"],
        iso_42001=["A.6.2.5 (AI system deployment — release criteria)", "A.6.1.3 (Processes for responsible design & development)"],
        owasp_llm=[],
        check=_chk_change_review,
        remediation=("Require documented review/approval for model and system-prompt changes "
                     "before they reach production."),
    ),
]


def control_count_by_severity() -> dict[str, int]:
    out: dict[str, int] = {}
    for c in CONTROLS:
        out[c.severity.value] = out.get(c.severity.value, 0) + 1
    return out


if __name__ == "__main__":
    print(f"A-ACAF rubric loaded: {len(CONTROLS)} controls")
    print("By severity:", control_count_by_severity())
    frameworks = {"NIST AI RMF": set(), "ISO 42001": set(), "OWASP LLM (2025)": set()}
    for c in CONTROLS:
        frameworks["NIST AI RMF"].update(c.nist_ai_rmf)
        frameworks["ISO 42001"].update(c.iso_42001)
        frameworks["OWASP LLM (2025)"].update(c.owasp_llm)
    for f, items in frameworks.items():
        print(f"  {f}: {len(items)} distinct controls mapped")
