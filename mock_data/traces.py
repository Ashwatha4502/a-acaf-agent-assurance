"""
A-ACAF Phase 2 — Synthetic runtime traces
-------------------------------------------------------------------------------
Raw-shape CloudTrail events and Bedrock agent traces for the demo fleet, built
to mirror the real log formats. Deliberately seeded with a few real-world
misbehaviors so the runtime pass has violations to surface. All synthetic.
-------------------------------------------------------------------------------
"""

# Resource ARN fragment -> data classification (would come from tagging/inventory).
CLASSIFICATION_MAP = {
    "payer-phi-claims": "PHI",
    "cust-pii-store": "PII",
    "customer-records": "PII",
    "infra-configs": "internal",
    "audit-logs": "sensitive",
}

# assumed-role name -> agent id.
ROLE_AGENT_MAP = {
    "hc-claims-agent-role": "hc-claims-001",
    "fin-support-agent-role": "fin-support-002",
    "devops-agent-role": "int-devops-003",
}

# Business-level actions considered high-risk (need human approval).
HIGH_RISK_ACTIONS = ["deny_claim", "approve_payment", "issue_refund",
                     "send_customer_email", "terminate_instance", "delete_database"]


# ---- CloudTrail events (what the roles actually invoked) --------------------

CLOUDTRAIL_EVENTS = [
    # claims agent reading PHI — fine
    {"eventTime": "2026-07-01T14:20:01Z", "eventSource": "s3.amazonaws.com",
     "eventName": "GetObject",
     "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/hc-claims-agent-role/s1"},
     "resources": [{"ARN": "arn:aws:s3:::payer-phi-claims/claim-8842.json"}]},

    # claims agent DELETING PHI — violation (destructive on PHI)
    {"eventTime": "2026-07-01T14:22:07Z", "eventSource": "s3.amazonaws.com",
     "eventName": "DeleteObject",
     "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/hc-claims-agent-role/s1"},
     "resources": [{"ARN": "arn:aws:s3:::payer-phi-claims/claim-8842.json"}]},

    # support agent reading PII — fine
    {"eventTime": "2026-07-01T15:02:11Z", "eventSource": "s3.amazonaws.com",
     "eventName": "GetObject",
     "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/fin-support-agent-role/s2"},
     "resources": [{"ARN": "arn:aws:s3:::cust-pii-store/user-221.json"}]},

    # support agent calling a service outside its declared scope (SNS publish) — out-of-scope
    {"eventTime": "2026-07-01T15:04:55Z", "eventSource": "sns.amazonaws.com",
     "eventName": "Publish",
     "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/fin-support-agent-role/s2"},
     "resources": [{"ARN": "arn:aws:sns:us-east-1:123456789012:marketing-blast"}]},

    # devops agent terminating an instance — captured here, approval checked via bedrock trace
    {"eventTime": "2026-07-01T16:40:02Z", "eventSource": "ec2.amazonaws.com",
     "eventName": "TerminateInstances",
     "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/devops-agent-role/s3"},
     "resources": [{"ARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc"}]},
]


# ---- Bedrock agent traces (model + prompt + guardrail + approval context) ----

BEDROCK_TRACES = [
    # claims agent denies a claim WITH approval and guardrail — clean
    {"agentId": "hc-claims-001", "timestamp": "2026-07-01T14:21:00Z",
     "modelId": "anthropic.claude-sonnet", "modelVersion": "20250219-v1",
     "guardrailAction": "NONE", "humanApproval": True,
     "trace": {"orchestrationTrace": {
         "modelInvocationInput": {"text": "Assess claim 8842 for denial per policy."},
         "actionGroupInvocation": {"actionGroupName": "claims", "function": "deny_claim",
                                   "parameters": {"resource": "claim-8842"}}}}},

    # claims agent approves a payment with NO human approval — violation (high-risk, no HITL)
    {"agentId": "hc-claims-001", "timestamp": "2026-07-01T14:23:30Z",
     "modelId": "anthropic.claude-sonnet", "modelVersion": "20250219-v1",
     "guardrailAction": "NONE", "humanApproval": False,
     "trace": {"orchestrationTrace": {
         "modelInvocationInput": {"text": "Approve payment for claim 9001."},
         "actionGroupInvocation": {"actionGroupName": "claims", "function": "approve_payment",
                                   "parameters": {"resource": "claim-9001"}}}}},

    # support agent issues refund, NO guardrail evaluated AND no approval — two violations
    {"agentId": "fin-support-002", "timestamp": "2026-07-01T15:05:10Z",
     "modelId": "anthropic.claude-haiku", "modelVersion": "20241022-v1",
     "guardrailAction": "ABSENT", "humanApproval": False,
     "trace": {"orchestrationTrace": {
         "modelInvocationInput": {"text": "Customer angry, issue full refund now."},
         "actionGroupInvocation": {"actionGroupName": "support", "function": "issue_refund",
                                   "parameters": {"resource": "order-5521"}}}}},

    # support agent sends customer email, missing prompt attribution — attribution gap
    {"agentId": "fin-support-002", "timestamp": "2026-07-01T15:06:40Z",
     "modelId": "anthropic.claude-haiku", "modelVersion": "20241022-v1",
     "guardrailAction": "NONE", "humanApproval": True,
     "trace": {"orchestrationTrace": {
         "modelInvocationInput": {"text": None},
         "actionGroupInvocation": {"actionGroupName": "support", "function": "send_customer_email",
                                   "parameters": {"resource": "user-221"}}}}},

    # devops agent terminates instance with approval + guardrail, but on a DRIFTED model version
    {"agentId": "int-devops-003", "timestamp": "2026-07-01T16:40:00Z",
     "modelId": "anthropic.claude-sonnet", "modelVersion": "20250601-v2",
     "guardrailAction": "NONE", "humanApproval": True,
     "trace": {"orchestrationTrace": {
         "modelInvocationInput": {"text": "Terminate idle instance i-0abc per runbook."},
         "actionGroupInvocation": {"actionGroupName": "ops", "function": "terminate_instance",
                                   "parameters": {"resource": "i-0abc"}}}}},
]


# Per-agent declared runtime context (what each agent was scoped to expect).
from engine.runtime_schema import AgentRuntimeContext

RUNTIME_CONTEXTS = {
    "hc-claims-001": AgentRuntimeContext(
        agent_id="hc-claims-001",
        allowed_actions=["s3:GetObject", "deny_claim", "approve_payment"],
        allowed_classifications=["PHI"],
        high_risk_actions=["deny_claim", "approve_payment"],
        pinned_model_version="20250219-v1"),
    "fin-support-002": AgentRuntimeContext(
        agent_id="fin-support-002",
        allowed_actions=["s3:GetObject", "issue_refund", "send_customer_email"],
        allowed_classifications=["PII"],
        high_risk_actions=["issue_refund", "send_customer_email"],
        pinned_model_version="20241022-v1"),
    "int-devops-003": AgentRuntimeContext(
        agent_id="int-devops-003",
        allowed_actions=["ec2:DescribeInstances", "ec2:TerminateInstances", "terminate_instance", "s3:GetObject"],
        allowed_classifications=["internal"],
        high_risk_actions=["terminate_instance", "delete_database"],
        pinned_model_version="20250219-v1"),
}
