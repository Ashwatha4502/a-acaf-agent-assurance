"""
A-ACAF Phase 2 — Runtime schema
-------------------------------------------------------------------------------
The normalized record every trace source (CloudTrail, Bedrock agent traces,
guardrail logs) is mapped into. The runtime evaluator only ever sees
ObservedAction records, so adding a new trace source means writing one
collector, not touching the control logic.
-------------------------------------------------------------------------------
"""

from dataclasses import dataclass, field, asdict
from typing import Optional


# Destructive action prefixes reused by the runtime checks.
DESTRUCTIVE_PREFIXES = ("s3:Delete", "s3:Put", "dynamodb:Delete", "rds:Delete",
                        "dynamodb:DeleteTable")


@dataclass
class ObservedAction:
    """One thing an agent actually did, normalized from any trace source."""
    agent_id: str
    timestamp: str                     # ISO 8601
    action: str                        # e.g. "s3:DeleteObject"
    resource: str                      # ARN or resource id
    source: str                        # "cloudtrail" | "bedrock" | ...
    data_classification: Optional[str] = None   # PHI | PII | sensitive | internal | None
    model_id: Optional[str] = None
    model_version: Optional[str] = None
    prompt_hash: Optional[str] = None
    guardrail_result: str = "ABSENT"   # NONE (ran, no intervention) | INTERVENED | ABSENT (not evaluated)
    human_approval: bool = False
    is_high_risk: bool = False         # flagged high-risk action (payment, delete, external comms)

    def is_destructive(self) -> bool:
        return any(self.action.startswith(p) for p in DESTRUCTIVE_PREFIXES)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AgentRuntimeContext:
    """Per-agent declared expectations, used to judge observed actions.

    In production this comes from the agent's registered config; here it lets
    the runtime checks know what the agent was *supposed* to be scoped to, so
    'did it act outside its declared boundary' is answerable.
    """
    agent_id: str
    allowed_actions: list = field(default_factory=list)   # declared action allow-list (prefixes ok)
    allowed_classifications: list = field(default_factory=list)
    high_risk_actions: list = field(default_factory=list)
    pinned_model_version: Optional[str] = None

    def action_in_scope(self, action: str) -> bool:
        if not self.allowed_actions:
            return True  # nothing declared -> can't judge scope here (AAC-DATA-01 covers that)
        for a in self.allowed_actions:
            if action == a or (a.endswith("*") and action.startswith(a[:-1])):
                return True
        return False
