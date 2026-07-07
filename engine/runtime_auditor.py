"""
A-ACAF Phase 2 — Runtime evaluator
-------------------------------------------------------------------------------
Evaluates a stream of ObservedAction records against the runtime dimension of
the control set. Where v1 asked "is the control configured?", this asks "did the
agent's actual behavior violate the control?" — and every finding carries a
timestamp and the model/prompt attribution from the trace.

The control IDs are identical to rubric/controls.py on purpose: config posture
and runtime behavior are two views of the same contract.
-------------------------------------------------------------------------------
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.runtime_schema import ObservedAction, AgentRuntimeContext

# Reuse the same severity weighting as the static engine so posture and
# behavioral scores are directly comparable.
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3}


@dataclass
class RuntimeFinding:
    control_id: str
    title: str
    severity: str
    timestamp: str
    evidence: str            # timestamped, with model/prompt attribution
    action: str
    resource: str
    remediation: str


@dataclass
class AgentRuntimeResult:
    agent_id: str
    window_actions: int
    behavioral_score: int    # 0-100, higher = cleaner observed behavior
    findings: list = field(default_factory=list)

    def by_severity(self) -> dict:
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


# --- runtime checks: each returns a RuntimeFinding or None for one action -----
# They mirror the static controls but judge observed behavior.

def _rt_destructive_on_sensitive(a: ObservedAction, ctx: AgentRuntimeContext):
    if a.is_destructive() and a.data_classification in ("PHI", "PII", "sensitive"):
        return RuntimeFinding(
            "AAC-ACCESS-02", "Destructive action executed on sensitive data", "CRITICAL",
            a.timestamp,
            f"Agent invoked {a.action} on {a.data_classification}-classified {a.resource} "
            f"(model {a.model_id or '?'}@{a.model_version or '?'}, prompt {a.prompt_hash or 'n/a'}).",
            a.action, a.resource,
            "Remove destructive permissions on sensitive resources; route writes through a reviewed service.")
    return None


def _rt_out_of_scope(a: ObservedAction, ctx: AgentRuntimeContext):
    if not ctx.action_in_scope(a.action):
        return RuntimeFinding(
            "AAC-ACCESS-01", "Agent acted outside its declared action scope", "HIGH",
            a.timestamp,
            f"Agent executed {a.action} on {a.resource}, which is outside its declared allow-list "
            f"{ctx.allowed_actions}.",
            a.action, a.resource,
            "Scope the execution role to the declared action set; investigate why the agent reached for this action.")
    return None


def _rt_high_risk_no_approval(a: ObservedAction, ctx: AgentRuntimeContext):
    if a.is_high_risk and not a.human_approval:
        return RuntimeFinding(
            "AAC-OVS-01", "High-risk action executed without human approval", "CRITICAL",
            a.timestamp,
            f"High-risk action {a.action} executed with no human approval recorded in the trace "
            f"(model {a.model_id or '?'}@{a.model_version or '?'}).",
            a.action, a.resource,
            "Require documented human-in-the-loop approval before the agent executes high-risk actions.")
    return None


def _rt_guardrail_absent(a: ObservedAction, ctx: AgentRuntimeContext):
    # Only meaningful for model-driven (Bedrock) actions; CloudTrail alone can't see guardrails.
    if a.source == "bedrock" and a.guardrail_result == "ABSENT":
        return RuntimeFinding(
            "AAC-RES-01", "Model action ran with no guardrail evaluation", "HIGH",
            a.timestamp,
            f"Action {a.action} was produced by the model with no input/output guardrail evaluated "
            f"(prompt {a.prompt_hash or 'n/a'}).",
            a.action, a.resource,
            "Attach input/output guardrails to the agent so every model-driven action is filtered.")
    return None


def _rt_attribution_gap(a: ObservedAction, ctx: AgentRuntimeContext):
    # A logged action you can't attribute to a model+version+prompt fails traceability.
    if a.source == "bedrock" and (not a.model_version or not a.prompt_hash):
        missing = [n for n, v in (("model_version", a.model_version), ("prompt_hash", a.prompt_hash)) if not v]
        return RuntimeFinding(
            "AAC-LOG-03", "Executed action is not fully attributable", "MEDIUM",
            a.timestamp,
            f"Action {a.action} logged without {', '.join(missing)} — cannot fully reconstruct the decision.",
            a.action, a.resource,
            "Ensure the trace captures model id, version, and prompt hash on every action.")
    return None


PER_ACTION_CHECKS = [
    _rt_destructive_on_sensitive,
    _rt_out_of_scope,
    _rt_high_risk_no_approval,
    _rt_guardrail_absent,
    _rt_attribution_gap,
]


def _model_drift_check(actions: list, ctx: AgentRuntimeContext):
    """Cross-action check: did the agent run on an unpinned or drifting model?"""
    findings = []
    versions = {a.model_version for a in actions if a.model_version}
    if ctx.pinned_model_version and versions - {ctx.pinned_model_version}:
        drifted = ", ".join(sorted(versions - {ctx.pinned_model_version}))
        ts = next((a.timestamp for a in actions if a.model_version and a.model_version != ctx.pinned_model_version), "")
        findings.append(RuntimeFinding(
            "AAC-LC-01", "Agent ran on a model version other than the pinned one", "MEDIUM", ts,
            f"Observed model version(s) {drifted}; pinned version is {ctx.pinned_model_version}. "
            f"Decisions across versions are not reproducible.",
            "model_invocation", "-",
            "Pin the agent to a single model version; promote changes only through change review."))
    return findings


def evaluate_runtime(actions: list, ctx: AgentRuntimeContext) -> AgentRuntimeResult:
    agent_actions = [a for a in actions if a.agent_id == ctx.agent_id]
    findings = []
    for a in agent_actions:
        for chk in PER_ACTION_CHECKS:
            f = chk(a, ctx)
            if f:
                findings.append(f)
    findings.extend(_model_drift_check(agent_actions, ctx))

    # Behavioral score: start at 100, subtract severity-weighted penalty per finding,
    # normalized against the number of actions observed so a busy agent isn't unfairly
    # crushed by volume. Floor at 0.
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    denom = max(len(agent_actions), 1) * 40  # 40 = one critical per action = score 0
    score = max(0, round(100 * (1 - min(penalty / denom, 1.0))))

    findings.sort(key=lambda f: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[f.severity], f.timestamp))
    return AgentRuntimeResult(
        agent_id=ctx.agent_id,
        window_actions=len(agent_actions),
        behavioral_score=score,
        findings=findings,
    )
