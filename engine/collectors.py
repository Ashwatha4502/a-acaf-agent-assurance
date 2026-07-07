"""
A-ACAF Phase 2 — Collectors
-------------------------------------------------------------------------------
Map raw trace records from each source into the normalized ObservedAction.
Modeled on the real shapes of AWS CloudTrail events and Bedrock agent traces so
that swapping synthetic data for a live boto3/CloudTrail feed is a drop-in.
-------------------------------------------------------------------------------
"""

import hashlib
import re
from typing import Optional

from engine.runtime_schema import ObservedAction


# Maps a resource ARN (or bucket/table name) to its data classification.
# In production this comes from a resource inventory / tagging; here it's a dict.
def classify_resource(resource: str, classification_map: dict) -> Optional[str]:
    for key, cls in classification_map.items():
        if key in resource:
            return cls
    return None


def _prompt_hash(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _role_to_agent_id(arn: str, role_agent_map: dict) -> str:
    # arn:aws:sts::123:assumed-role/hc-claims-agent-role/session -> agent id via map
    m = re.search(r"assumed-role/([^/]+)/", arn or "")
    role = m.group(1) if m else arn
    return role_agent_map.get(role, role)


def from_cloudtrail(event: dict, classification_map: dict, role_agent_map: dict,
                    high_risk_actions: list) -> ObservedAction:
    """Normalize one CloudTrail event.

    CloudTrail tells us what API call the agent's *role* actually made. It has no
    model/prompt context (guardrail_result stays ABSENT unless a Bedrock trace
    correlates it), which is itself a useful signal for the attribution control.
    """
    source_svc = event.get("eventSource", "").split(".")[0]  # "s3.amazonaws.com" -> "s3"
    action = f"{source_svc}:{event.get('eventName', 'Unknown')}"
    resources = event.get("resources") or []
    resource = resources[0].get("ARN") if resources else (
        event.get("requestParameters", {}).get("bucketName", "unknown"))
    agent_id = _role_to_agent_id(event.get("userIdentity", {}).get("arn", ""), role_agent_map)
    return ObservedAction(
        agent_id=agent_id,
        timestamp=event.get("eventTime", ""),
        action=action,
        resource=resource,
        source="cloudtrail",
        data_classification=classify_resource(resource, classification_map),
        guardrail_result="ABSENT",
        human_approval=False,
        is_high_risk=action in high_risk_actions,
    )


def from_bedrock_trace(rec: dict, classification_map: dict,
                       high_risk_actions: list) -> ObservedAction:
    """Normalize one Bedrock agent trace record.

    Bedrock traces carry the rich context CloudTrail lacks: model id/version, the
    prompt (which we hash, never store raw), the guardrail outcome, and whether a
    human approval step ran.
    """
    orch = rec.get("trace", {}).get("orchestrationTrace", {})
    prompt = orch.get("modelInvocationInput", {}).get("text")
    agi = orch.get("actionGroupInvocation", {}) or {}
    func = agi.get("function", "unknown")
    action = func  # business-level action name, e.g. "deny_claim"
    resource = agi.get("parameters", {}).get("resource", rec.get("agentId", "unknown"))
    gr = rec.get("guardrailAction", "ABSENT")
    guardrail_result = {"NONE": "NONE", "INTERVENED": "INTERVENED"}.get(gr, "ABSENT")
    return ObservedAction(
        agent_id=rec.get("agentId", "unknown"),
        timestamp=rec.get("timestamp", ""),
        action=action,
        resource=resource,
        source="bedrock",
        data_classification=classify_resource(str(resource), classification_map),
        model_id=rec.get("modelId"),
        model_version=rec.get("modelVersion"),
        prompt_hash=_prompt_hash(prompt),
        guardrail_result=guardrail_result,
        human_approval=bool(rec.get("humanApproval", False)),
        is_high_risk=action in high_risk_actions,
    )


def collect(cloudtrail_events: list, bedrock_records: list, classification_map: dict,
            role_agent_map: dict, high_risk_actions: list) -> list:
    """Normalize and merge all trace sources into one time-ordered stream."""
    actions = []
    for e in cloudtrail_events:
        actions.append(from_cloudtrail(e, classification_map, role_agent_map, high_risk_actions))
    for r in bedrock_records:
        actions.append(from_bedrock_trace(r, classification_map, high_risk_actions))
    actions.sort(key=lambda a: a.timestamp)
    return actions
