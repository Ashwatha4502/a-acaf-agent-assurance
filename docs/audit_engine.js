/*
 * A-ACAF audit engine — browser port.
 * Faithful JavaScript port of rubric/controls.py + engine/auditor.py so the
 * live console can score agent configs client-side, with no backend.
 * Exposes window.AACAF.auditAgent(config) and window.AACAF.SAMPLE.
 */
(function () {
  "use strict";

  const SEVERITY_WEIGHT = { CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 3, INFO: 0 };

  const asList = v => (v == null ? [] : Array.isArray(v) ? v : [v]);
  const get = (o, k, d) => (o && o[k] !== undefined ? o[k] : d);

  // ---- check functions (mirror the Python one-for-one) --------------------

  function chkNoWildcard(a) {
    // Not assessable if no IAM policy is provided — absence of evidence is
    // not a pass; the agent's permissions simply cannot be audited.
    if (!("iam_policy" in a))
      return [null, "Not assessable: no IAM policy provided for this agent."];
    const offending = [];
    for (const s of get(get(a, "iam_policy", {}), "statements", [])) {
      for (const act of asList(s.actions)) {
        if (act === "*" || act.endsWith(":*")) offending.push(act);
      }
    }
    if (offending.length)
      return [false, "Wildcard actions granted to agent role: " +
        [...new Set(offending)].sort().join(", ")];
    return [true, "No wildcard actions found in agent execution role."];
  }

  // Mirrors _action_is_destructive in controls.py: a '*' or 'service:*' grant
  // is a superset of every destructive action in that service, so wildcards are
  // treated as destructive — otherwise an agent with s3:* would pass a control
  // that an agent with s3:DeleteObject fails.
  const DESTRUCTIVE_PREFIXES = ["s3:Delete", "s3:Put", "dynamodb:Delete", "rds:Delete"];
  const DESTRUCTIVE_SERVICES = ["s3", "dynamodb", "rds"];

  function actionIsDestructive(action) {
    if (action === "*") return true;
    if (action.endsWith(":*") && DESTRUCTIVE_SERVICES.includes(action.split(":")[0])) return true;
    return DESTRUCTIVE_PREFIXES.some(p => action.startsWith(p));
  }

  function chkNoDestructiveOnSensitive(a) {
    if (!("iam_policy" in a))
      return [null, "Not assessable: no IAM policy provided for this agent."];
    const sensitive = new Set(
      asList(get(a, "accessible_resources", []))
        .filter(r => ["PHI", "PII", "sensitive"].includes(r.data_classification))
        .map(r => r.arn));
    const hits = [];
    for (const s of get(get(a, "iam_policy", {}), "statements", [])) {
      for (const act of asList(s.actions)) {
        if (actionIsDestructive(act)) {
          for (const r of asList(s.resources)) {
            if (r === "*" || sensitive.has(r)) hits.push(act + " on " + r);
          }
        }
      }
    }
    if (hits.length)
      return [false, "Destructive permissions (incl. wildcard supersets) on sensitive data: " + hits.join("; ")];
    return [true, "No destructive permissions on PHI/PII/sensitive resources."];
  }

  function chkDataBoundary(a) {
    const b = get(a, "data_boundary", null);
    if (!b || b.mode === "unrestricted")
      return [false, "Agent has no declared data boundary (unrestricted data access)."];
    const scopes = asList(b.allowed_classifications);
    return [true, "Data boundary declared. Allowed classifications: " +
      (scopes.join(", ") || "none") + "."];
  }

  function chkProcessingBasis(a) {
    // Fail-closed: check what the agent can actually REACH, not just what it
    // declares — an undeclared (unrestricted) boundary must not dodge the control.
    const b = get(a, "data_boundary", null) || {};
    const declared = asList(b.allowed_classifications);
    const reachable = asList(get(a, "accessible_resources", [])).map(r => r.data_classification);
    const touches = [...declared, ...reachable].some(c => c === "PII" || c === "PHI");
    if (touches && !b.processing_basis)
      return [false, "Agent can reach PII/PHI but declares no processing basis (GDPR Art.6 / HIPAA)."];
    return [true, "PII/PHI processing basis declared or no PII/PHI in scope."];
  }

  function chkActionLogging(a) {
    const l = get(a, "logging", {});
    if (!l.action_trace_enabled)
      return [false, "Agent action tracing is disabled — invocations are not auditable."];
    return [true, "Action tracing enabled (sink: " + get(l, "sink", "unknown") + ")."];
  }

  function chkLogImmutability(a) {
    const l = get(a, "logging", {});
    // Not assessable when tracing is disabled — there are no logs to protect,
    // and that failure is already captured (CRITICAL) by AAC-LOG-01.
    if (!l.action_trace_enabled)
      return [null, "Not assessable: action tracing is disabled (see AAC-LOG-01)."];
    if (!l.immutable_store)
      return [false, "Action logs are mutable — no object-lock / immutability guarantee."];
    return [true, "Audit logs stored in immutable / tamper-evident store."];
  }

  function chkAttribution(a) {
    const l = get(a, "logging", {});
    if (!l.action_trace_enabled)
      return [null, "Not assessable: action tracing is disabled (see AAC-LOG-01)."];
    const captured = new Set(asList(l.captured_fields));
    const required = ["model_id", "model_version", "prompt_hash"];
    const missing = required.filter(f => !captured.has(f));
    if (missing.length)
      return [false, "Log records missing attribution fields: " + missing.join(", ") + "."];
    return [true, "Logs capture model id, version, and prompt hash for full attribution."];
  }

  function chkInjection(a) {
    const g = get(a, "guardrails", {});
    if (!g.input_filtering)
      return [false, "No input filtering / injection guardrail configured (OWASP LLM01)."];
    return [true, "Input guardrail active (provider: " + get(g, "provider", "unknown") + ")."];
  }

  function chkOutputHandling(a) {
    const g = get(a, "guardrails", {});
    // Fail-closed: if downstream execution is undeclared, assume it exists.
    let downstream = a.has_downstream_execution;
    if (downstream === undefined || downstream === null) downstream = true;
    if (downstream && !g.output_validation)
      return [false, "Agent output drives downstream actions with no output validation (OWASP LLM05)."];
    return [true, "Output validation configured or downstream execution explicitly absent."];
  }

  function chkHumanCheckpoint(a) {
    // Not assessable if the high-risk action set was never declared — a
    // config cannot vacuously pass this control by omitting the declaration.
    if (!("high_risk_actions" in a))
      return [null, "Not assessable: no high-risk action declaration provided."];
    const h = get(a, "human_oversight", {});
    const gated = new Set(asList(h.approval_required_for));
    const ungated = asList(get(a, "high_risk_actions", [])).filter(x => !gated.has(x));
    if (ungated.length)
      return [false, "High-risk actions run without human approval: " + ungated.join(", ") + "."];
    return [true, "All declared high-risk actions gated by human approval."];
  }

  function chkKillSwitch(a) {
    const h = get(a, "human_oversight", {});
    if (!h.kill_switch)
      return [false, "No documented kill switch / pause mechanism for the agent."];
    return [true, "Kill switch / pause mechanism documented and available."];
  }

  function chkModelPinned(a) {
    const m = get(a, "model", {});
    const ver = String(get(m, "version", "")).toLowerCase();
    if (ver === "" || ver === "latest" || ver === "auto")
      return [false, "Model version not pinned (='" + (ver || "unset") + "') — decisions not reproducible."];
    return [true, "Model pinned to " + get(m, "model_id", "?") + " @ " + get(m, "version", "?") + "."];
  }

  function chkChangeReview(a) {
    const lc = get(a, "lifecycle", {});
    if (!lc.change_review)
      return [false, "No change-review process for model/prompt updates (uncontrolled drift risk)."];
    return [true, "Model/prompt changes gated by documented review process."];
  }

  // ---- control catalog (mirrors CONTROLS in controls.py) ------------------

  const CONTROLS = [
    { id: "AAC-ACCESS-01", title: "Agent execution role avoids wildcard permissions",
      domain: "Access & Least Privilege", severity: "HIGH", check: chkNoWildcard,
      rationale: "An agent role granting '*' or 'service:*' actions violates least privilege. Because agents act autonomously, an over-broad role converts a single prompt injection into arbitrary account actions.",
      remediation: "Scope the agent role to the explicit set of actions required for its task. Replace wildcards with enumerated actions and resource ARNs.",
      nist_ai_rmf: ["MANAGE-2.1", "GOVERN-1.2"], iso_42001: ["A.9.4 (Intended use of the AI system)", "Clause 8.1 (Operational planning & control)"], owasp_llm: ["LLM06: Excessive Agency"] },
    { id: "AAC-ACCESS-02", title: "No destructive permissions over sensitive data",
      domain: "Access & Least Privilege", severity: "CRITICAL", check: chkNoDestructiveOnSensitive,
      rationale: "Delete/overwrite permissions on PHI/PII/sensitive stores let an autonomous or manipulated agent cause irreversible data loss or integrity compromise. Wildcard grants count — 's3:*' is a superset of every destructive S3 action.",
      remediation: "Remove Delete*/Put* actions on sensitive resources. Grant read-only where the workflow allows; route writes through a reviewed service, not the agent.",
      nist_ai_rmf: ["MANAGE-2.1", "MEASURE-2.6"], iso_42001: ["A.9.4 (Intended use of the AI system)", "A.7.4 (Quality of data for AI systems)"], owasp_llm: ["LLM06: Excessive Agency", "LLM02: Sensitive Information Disclosure"] },
    { id: "AAC-DATA-01", title: "Explicit data boundary is declared",
      domain: "Data Governance & Boundaries", severity: "HIGH", check: chkDataBoundary,
      rationale: "Governance requires knowing exactly which data an agent may touch. An unrestricted agent cannot be assessed for data-handling compliance.",
      remediation: "Define an explicit data boundary: allowed classifications and source systems. Default-deny any data domain not enumerated.",
      nist_ai_rmf: ["MAP-4.1", "GOVERN-1.3"], iso_42001: ["A.4.3 (Data resources)", "A.9.4 (Intended use of the AI system)"], owasp_llm: ["LLM02: Sensitive Information Disclosure"] },
    { id: "AAC-DATA-02", title: "Lawful processing basis for PII/PHI",
      domain: "Data Governance & Boundaries", severity: "HIGH", check: chkProcessingBasis,
      rationale: "If the agent processes personal or health data, a documented processing basis (GDPR Art.6 / HIPAA permitted use) is a hard compliance requirement.",
      remediation: "Record the lawful/processing basis for each sensitive data class the agent touches, or remove that class from the agent's boundary.",
      nist_ai_rmf: ["MAP-4.1", "GOVERN-1.1"], iso_42001: ["A.7.3 (Acquisition of data — data rights)", "A.2.3 (Alignment with other organisational policies)"], owasp_llm: ["LLM02: Sensitive Information Disclosure"] },
    { id: "AAC-LOG-01", title: "Agent action tracing is enabled",
      domain: "Auditability & Traceability", severity: "CRITICAL", check: chkActionLogging,
      rationale: "Without a complete action trace you cannot reconstruct what the agent did. This defeats incident response, audit, and accountability entirely.",
      remediation: "Enable full action/tool-invocation tracing to a durable log sink (e.g. CloudTrail + agent trace) before production use.",
      nist_ai_rmf: ["MEASURE-2.8", "MANAGE-4.1"], iso_42001: ["A.6.2.8 (AI system recording of event logs)", "A.6.2.6 (AI system operation and monitoring)"], owasp_llm: [] },
    { id: "AAC-LOG-02", title: "Audit logs are tamper-evident",
      domain: "Auditability & Traceability", severity: "HIGH", check: chkLogImmutability,
      rationale: "Mutable logs can be altered post-incident, destroying evidentiary value and failing SOC 2 / ISO logging-integrity expectations.",
      remediation: "Store logs in an immutable/object-locked destination with retention controls and restricted delete permissions.",
      nist_ai_rmf: ["MEASURE-2.8", "MANAGE-4.1"], iso_42001: ["A.6.2.8 (AI system recording of event logs)", "Clause 9.1 (Monitoring, measurement, analysis)"], owasp_llm: [] },
    { id: "AAC-LOG-03", title: "Decisions are attributable to model + version + prompt",
      domain: "Auditability & Traceability", severity: "MEDIUM", check: chkAttribution,
      rationale: "To govern an agent you must be able to answer 'which model, which version, on what input made this decision'. Missing attribution blocks root-cause analysis.",
      remediation: "Extend log schema to capture model_id, model_version, and a prompt hash on every agent action.",
      nist_ai_rmf: ["MEASURE-2.9", "MANAGE-4.1"], iso_42001: ["A.6.2.8 (AI system recording of event logs)", "A.4.4 (Tooling resources)"], owasp_llm: [] },
    { id: "AAC-RES-01", title: "Input guardrails against prompt injection",
      domain: "Adversarial Resilience", severity: "HIGH", check: chkInjection,
      rationale: "Prompt injection is the top LLM risk. An agent with tool access and no input filtering can be steered into unintended actions by hostile input.",
      remediation: "Configure input guardrails (e.g. Bedrock Guardrails) with injection/jailbreak filters and denied-topic policies scoped to the agent's role.",
      nist_ai_rmf: ["MEASURE-2.7", "MANAGE-2.2"], iso_42001: ["A.6.2.6 (AI system operation and monitoring — AI-specific threats)", "A.6.2.2 (AI system requirements and specification)"], owasp_llm: ["LLM01: Prompt Injection"] },
    { id: "AAC-RES-02", title: "Agent output validated before downstream execution",
      domain: "Adversarial Resilience", severity: "HIGH", check: chkOutputHandling,
      rationale: "When agent output triggers downstream actions, treating it as trusted lets a manipulated model inject commands/queries into other systems.",
      remediation: "Validate, encode, or schema-constrain agent output before it reaches downstream executors (DB, shell, API).",
      nist_ai_rmf: ["MEASURE-2.7", "MANAGE-2.2"], iso_42001: ["A.6.2.6 (AI system operation and monitoring)", "A.6.2.2 (AI system requirements and specification)"], owasp_llm: ["LLM05: Improper Output Handling"] },
    { id: "AAC-OVS-01", title: "Human approval gates high-risk actions",
      domain: "Human Oversight & Control", severity: "CRITICAL", check: chkHumanCheckpoint,
      rationale: "High-impact actions (payments, deletions, external comms) executed with no human checkpoint remove the accountability the EU AI Act and NIST require.",
      remediation: "Define the set of high-risk actions and require documented human approval (HITL) before the agent executes any of them.",
      nist_ai_rmf: ["MANAGE-2.3", "GOVERN-1.4"], iso_42001: ["A.9.2 (Processes for responsible use — human oversight)", "A.9.3 (Objectives for responsible use of AI system)"], owasp_llm: ["LLM06: Excessive Agency"] },
    { id: "AAC-OVS-02", title: "Kill switch / pause mechanism exists",
      domain: "Human Oversight & Control", severity: "HIGH", check: chkKillSwitch,
      rationale: "Operators must be able to stop a misbehaving agent immediately. No kill switch means no bounded blast radius.",
      remediation: "Implement and document a tested mechanism to pause/disable the agent and revoke its credentials on demand.",
      nist_ai_rmf: ["MANAGE-2.3", "MANAGE-4.1"], iso_42001: ["A.9.2 (Processes for responsible use — pause/stop conditions)", "A.6.2.6 (AI system operation and monitoring)"], owasp_llm: ["LLM06: Excessive Agency"] },
    { id: "AAC-LC-01", title: "Model version is pinned",
      domain: "Model Lifecycle & Change Mgmt", severity: "MEDIUM", check: chkModelPinned,
      rationale: "A 'latest' model reference means the decision-making system can change silently. Governance requires reproducibility of which model produced which decision.",
      remediation: "Pin the agent to a specific model id and version. Promote new versions only through the change-review process.",
      nist_ai_rmf: ["MAP-2.3", "MANAGE-4.1"], iso_42001: ["A.4.4 (Tooling resources — reproducibility)", "A.6.2.5 (AI system deployment)"], owasp_llm: ["LLM03: Supply Chain"] },
    { id: "AAC-LC-02", title: "Model/prompt changes go through review",
      domain: "Model Lifecycle & Change Mgmt", severity: "MEDIUM", check: chkChangeReview,
      rationale: "Uncontrolled prompt/model changes are drift. A documented review gate is the AI-system equivalent of change management.",
      remediation: "Require documented review/approval for model and system-prompt changes before they reach production.",
      nist_ai_rmf: ["MANAGE-4.1", "GOVERN-1.5"], iso_42001: ["A.6.2.5 (AI system deployment — release criteria)", "A.6.1.3 (Processes for responsible design & development)"], owasp_llm: [] },
  ];

  function grade(score) {
    if (score >= 90) return "A - Deployment-ready";
    if (score >= 75) return "B - Minor gaps";
    if (score >= 60) return "C - Remediate before scale";
    if (score >= 40) return "D - Significant exposure";
    return "F - Not fit for production";
  }

  function auditAgent(agent) {
    const findings = [];
    let penalty = 0, maxPenalty = 0;
    for (const c of CONTROLS) {
      const w = SEVERITY_WEIGHT[c.severity];
      const [result, evidence] = c.check(agent);
      // result is true (pass), false (fail), or null (not assessable).
      // N/A controls are excluded from the denominator: they neither reward
      // nor punish, so disabling a parent control (e.g. logging) can never
      // improve the score via its dependent controls.
      let status;
      if (result === null) {
        status = "N/A";
      } else if (result) {
        status = "PASS";
        maxPenalty += w;
      } else {
        status = "FAIL";
        maxPenalty += w;
        penalty += w;
      }
      findings.push({
        control_id: c.id, title: c.title, domain: c.domain,
        status,
        severity: status === "FAIL" ? c.severity : "-",
        evidence,
        business_risk: status === "FAIL" ? c.rationale
          : status === "N/A" ? "Control not assessable for this configuration."
          : "Control satisfied.",
        remediation: status === "FAIL" ? c.remediation : "-",
        nist_ai_rmf: c.nist_ai_rmf, iso_42001: c.iso_42001, owasp_llm: c.owasp_llm,
      });
    }
    const score = maxPenalty ? Math.round(100 * (1 - penalty / maxPenalty)) : 100;
    const fails = findings.filter(f => f.status === "FAIL");
    const notAssessable = findings.filter(f => f.status === "N/A").length;
    const summary = {
      total_controls: findings.length,
      passed: findings.length - fails.length - notAssessable,
      failed: fails.length,
      not_assessable: notAssessable,
      critical: fails.filter(f => f.severity === "CRITICAL").length,
      high: fails.filter(f => f.severity === "HIGH").length,
      medium: fails.filter(f => f.severity === "MEDIUM").length,
      low: fails.filter(f => f.severity === "LOW").length,
    };
    return {
      agent_id: get(agent, "agent_id", "unknown"),
      agent_name: get(agent, "agent_name", "unnamed-agent"),
      environment: get(agent, "environment", "unknown"),
      assessed_at: new Date().toISOString().slice(0, 19),
      assurance_score: score, grade: grade(score),
      findings, summary,
    };
  }

  // a friendly, deliberately-imperfect sample so users see findings immediately
  const SAMPLE = {
    agent_id: "my-agent-001",
    agent_name: "my-first-agent",
    environment: "production",
    iam_policy: { statements: [{ actions: ["s3:GetObject", "s3:PutObject"], resources: ["*"] }] },
    accessible_resources: [{ arn: "arn:aws:s3:::customer-data", data_classification: "PII" }],
    data_boundary: { mode: "restricted", allowed_classifications: ["PII"] },
    logging: { action_trace_enabled: true, sink: "cloudtrail", immutable_store: false, captured_fields: ["timestamp"] },
    guardrails: { input_filtering: false },
    has_downstream_execution: true,
    human_oversight: { kill_switch: false },
    high_risk_actions: ["send_email", "issue_refund"],
    model: { model_id: "anthropic.claude", version: "latest" },
    lifecycle: { change_review: false },
  };

  window.AACAF = { auditAgent, CONTROLS, SAMPLE };
})();
