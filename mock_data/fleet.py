"""
Synthetic agent fleet for A-ACAF demonstration.

Three realistic AI agents modeled on common enterprise deployments, each in a
"before" (as first deployed) and "after" (remediated) state. No real accounts,
ARNs, or data — all synthetic. This drives the before/after demo narrative.
"""

# ---------------------------------------------------------------------------
# AGENT 1: Claims-processing agent in a healthcare payer (touches PHI)
# ---------------------------------------------------------------------------

CLAIMS_AGENT_BEFORE = {
    "agent_id": "hc-claims-001",
    "agent_name": "claims-triage-agent",
    "environment": "production",
    "iam_policy": {
        "statements": [
            {"actions": ["s3:*", "dynamodb:*"], "resources": ["*"]},
        ]
    },
    "accessible_resources": [
        {"arn": "arn:aws:s3:::payer-phi-claims", "data_classification": "PHI"},
        {"arn": "arn:aws:s3:::payer-audit-logs", "data_classification": "sensitive"},
    ],
    "data_boundary": {"mode": "unrestricted"},
    "logging": {"action_trace_enabled": False},
    "guardrails": {},
    "has_downstream_execution": True,
    "human_oversight": {},
    "high_risk_actions": ["deny_claim", "approve_payment"],
    "model": {"model_id": "anthropic.claude", "version": "latest"},
    "lifecycle": {},
}

CLAIMS_AGENT_AFTER = {
    "agent_id": "hc-claims-001",
    "agent_name": "claims-triage-agent",
    "environment": "production",
    "iam_policy": {
        "statements": [
            {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::payer-phi-claims/*"]},
            {"actions": ["dynamodb:GetItem", "dynamodb:Query"],
             "resources": ["arn:aws:dynamodb:us-east-1:*:table/claims-index"]},
        ]
    },
    "accessible_resources": [
        {"arn": "arn:aws:s3:::payer-phi-claims", "data_classification": "PHI"},
    ],
    "data_boundary": {
        "mode": "restricted",
        "allowed_classifications": ["PHI"],
        "processing_basis": "HIPAA treatment/payment/operations (45 CFR 164.506)",
    },
    "logging": {
        "action_trace_enabled": True,
        "sink": "cloudtrail+bedrock-trace",
        "immutable_store": True,
        "captured_fields": ["model_id", "model_version", "prompt_hash", "timestamp", "principal"],
    },
    "guardrails": {"input_filtering": True, "output_validation": True, "provider": "bedrock-guardrails"},
    "has_downstream_execution": True,
    "human_oversight": {
        "approval_required_for": ["deny_claim", "approve_payment"],
        "kill_switch": True,
    },
    "high_risk_actions": ["deny_claim", "approve_payment"],
    "model": {"model_id": "anthropic.claude-sonnet", "version": "20250219-v1"},
    "lifecycle": {"change_review": True},
}

# ---------------------------------------------------------------------------
# AGENT 2: Customer-support agent in fintech (touches PII, sends comms)
# ---------------------------------------------------------------------------

SUPPORT_AGENT_BEFORE = {
    "agent_id": "fin-support-002",
    "agent_name": "customer-support-agent",
    "environment": "production",
    "iam_policy": {
        "statements": [
            {"actions": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "ses:SendEmail"],
             "resources": ["*"]},
        ]
    },
    "accessible_resources": [
        {"arn": "arn:aws:s3:::cust-pii-store", "data_classification": "PII"},
    ],
    "data_boundary": {"mode": "restricted", "allowed_classifications": ["PII"]},
    "logging": {"action_trace_enabled": True, "sink": "cloudtrail", "immutable_store": False,
                "captured_fields": ["timestamp", "principal"]},
    "guardrails": {"input_filtering": False},
    "has_downstream_execution": True,
    "human_oversight": {"kill_switch": True},
    "high_risk_actions": ["issue_refund", "send_customer_email"],
    "model": {"model_id": "anthropic.claude-haiku", "version": "latest"},
    "lifecycle": {"change_review": False},
}

SUPPORT_AGENT_AFTER = {
    "agent_id": "fin-support-002",
    "agent_name": "customer-support-agent",
    "environment": "production",
    "iam_policy": {
        "statements": [
            {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::cust-pii-store/*"]},
            {"actions": ["ses:SendEmail"], "resources": ["arn:aws:ses:us-east-1:*:identity/support@*"]},
        ]
    },
    "accessible_resources": [
        {"arn": "arn:aws:s3:::cust-pii-store", "data_classification": "PII"},
    ],
    "data_boundary": {
        "mode": "restricted",
        "allowed_classifications": ["PII"],
        "processing_basis": "GDPR Art.6(1)(b) contract performance",
    },
    "logging": {"action_trace_enabled": True, "sink": "cloudtrail", "immutable_store": True,
                "captured_fields": ["model_id", "model_version", "prompt_hash", "timestamp", "principal"]},
    "guardrails": {"input_filtering": True, "output_validation": True, "provider": "bedrock-guardrails"},
    "has_downstream_execution": True,
    "human_oversight": {
        "approval_required_for": ["issue_refund", "send_customer_email"],
        "kill_switch": True,
    },
    "high_risk_actions": ["issue_refund", "send_customer_email"],
    "model": {"model_id": "anthropic.claude-haiku", "version": "20241022-v1"},
    "lifecycle": {"change_review": True},
}

# ---------------------------------------------------------------------------
# AGENT 3: Internal DevOps assistant (no sensitive data, but powerful)
# ---------------------------------------------------------------------------

DEVOPS_AGENT_BEFORE = {
    "agent_id": "int-devops-003",
    "agent_name": "devops-assistant-agent",
    "environment": "production",
    "iam_policy": {
        "statements": [
            {"actions": ["ec2:*", "rds:Delete*", "s3:GetObject"], "resources": ["*"]},
        ]
    },
    "accessible_resources": [
        {"arn": "arn:aws:s3:::infra-configs", "data_classification": "internal"},
    ],
    "data_boundary": {"mode": "restricted", "allowed_classifications": ["internal"]},
    "logging": {"action_trace_enabled": True, "sink": "cloudtrail", "immutable_store": True,
                "captured_fields": ["model_id", "timestamp", "principal"]},
    "guardrails": {"input_filtering": True, "provider": "bedrock-guardrails"},
    "has_downstream_execution": True,
    "human_oversight": {"kill_switch": False},
    "high_risk_actions": ["terminate_instance", "delete_database"],
    "model": {"model_id": "anthropic.claude-sonnet", "version": "20250219-v1"},
    "lifecycle": {"change_review": True},
}

DEVOPS_AGENT_AFTER = {
    "agent_id": "int-devops-003",
    "agent_name": "devops-assistant-agent",
    "environment": "production",
    "iam_policy": {
        "statements": [
            {"actions": ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"],
             "resources": ["arn:aws:ec2:us-east-1:*:instance/*"]},
            {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::infra-configs/*"]},
        ]
    },
    "accessible_resources": [
        {"arn": "arn:aws:s3:::infra-configs", "data_classification": "internal"},
    ],
    "data_boundary": {"mode": "restricted", "allowed_classifications": ["internal"]},
    "logging": {"action_trace_enabled": True, "sink": "cloudtrail", "immutable_store": True,
                "captured_fields": ["model_id", "model_version", "prompt_hash", "timestamp", "principal"]},
    "guardrails": {"input_filtering": True, "output_validation": True, "provider": "bedrock-guardrails"},
    "has_downstream_execution": True,
    "human_oversight": {
        "approval_required_for": ["terminate_instance", "delete_database"],
        "kill_switch": True,
    },
    "high_risk_actions": ["terminate_instance", "delete_database"],
    "model": {"model_id": "anthropic.claude-sonnet", "version": "20250219-v1"},
    "lifecycle": {"change_review": True},
}


FLEET_BEFORE = [CLAIMS_AGENT_BEFORE, SUPPORT_AGENT_BEFORE, DEVOPS_AGENT_BEFORE]
FLEET_AFTER = [CLAIMS_AGENT_AFTER, SUPPORT_AGENT_AFTER, DEVOPS_AGENT_AFTER]
