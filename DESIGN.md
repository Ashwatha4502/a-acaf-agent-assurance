# A-ACAF Design Decisions

This document records *why* the framework works the way it does, so every
scoring and mapping choice can be defended in review. The machine-readable
source of truth is [`rubric/controls.py`](rubric/controls.py); this explains it.

## 1. Checks fail closed

An audit tool must treat missing evidence as risk, never as compliance.
Concretely:

- **Wildcards are supersets.** `s3:*` grants every destructive S3 action, so
  it fails the destructive-permissions control (AAC-ACCESS-02) exactly as
  `s3:DeleteObject` would. An earlier version matched only enumerated
  `Delete`/`Put` prefixes, which meant the *broadest possible grant* passed a
  control that a narrower explicit grant failed. `tests/test_auditor.py::
  test_wildcard_never_scores_higher_than_enumerated_delete` pins the fix.
- **Undeclared risk is assumed present.** If a config doesn't state whether
  agent output drives downstream execution, the engine assumes it does
  (AAC-RES-02). If an agent can *reach* PII/PHI resources, the lawful-basis
  control applies even when the data boundary is undeclared (AAC-DATA-02) —
  otherwise leaving the boundary undeclared would dodge the control.
- **Absence of a section is not a pass.** An empty config used to score 47/100
  (grade D) because "no IAM policy found" meant "no wildcards found." It now
  scores 13/100 (F), with the unprovable controls reported as N/A.

## 2. N/A ("not assessable") semantics

A check returns one of three results: pass, fail, or **not assessable**.
N/A is used in exactly two situations:

1. **Dependent controls.** Log immutability (AAC-LOG-02) and decision
   attribution (AAC-LOG-03) are meaningless when action tracing is disabled —
   there are no logs to protect or inspect. That failure is already captured,
   at CRITICAL, by AAC-LOG-01. Marking the dependents N/A prevents a perverse
   incentive the original design had: disabling logging entirely made two
   controls pass for free, so *enabling* logging could lower an agent's score.
2. **Missing evidence.** If the config omits the IAM policy or the high-risk
   action declaration, those controls cannot be evaluated in either direction.

N/A controls are **excluded from the score denominator**: they neither reward
nor punish. The invariant, enforced by tests: fixing a parent control can
never reduce the score via its dependents.

## 3. Scoring model

```
score = round(100 × (1 − penalty / max_penalty))
```

where `max_penalty` sums the severity weights of all *assessable* controls
and `penalty` sums the weights of failed ones.

Severity weights — CRITICAL 40, HIGH 20, MEDIUM 8:

- A CRITICAL is worth two HIGHs. Each CRITICAL control (destructive access to
  regulated data, no action trace, no human gate on high-impact actions)
  represents an *unrecoverable or unaccountable* failure mode: data that can't
  be restored, an incident that can't be reconstructed, an action no human
  approved. HIGH failures are serious but bounded or detectable.
- MEDIUM (8) is deliberately less than half of HIGH: reproducibility gaps
  (unpinned model, no change review) create drift risk over time rather than
  immediate exposure.
- The ratio, not the absolute numbers, is the design choice. A flat pass/fail
  percentage would let ten trivial passes mask one catastrophic failure.

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40. A single CRITICAL failure on
an otherwise perfect agent scores in the mid-80s — deliberately below the
A ("deployment-ready") line.

## 4. Framework mapping principles

- **2025 OWASP numbering only.** The 2023 and 2025 lists renumbered several
  entries (Excessive Agency moved from LLM08 to LLM06; LLM08:2025 is Vector
  and Embedding Weaknesses). Mixing versions is a credibility failure in a
  GRC tool, so a test (`test_owasp_mappings_use_2025_numbering_only`) rejects
  any LLM08 reference outright.
- **No forced mappings.** Logging and change management are not OWASP LLM
  Top 10 entries, so those controls carry an empty OWASP mapping ("—") rather
  than a stretched one. An honest gap beats a wrong citation.
- **ISO/IEC 42001:2023** references use Annex A control numbers with their
  actual titles (e.g. A.6.2.8 *AI system recording of event logs*, A.9.2
  *Processes for responsible use of AI systems*). Clause references (8.1, 9.1)
  cover management-system requirements that Annex A doesn't.
- **NIST AI RMF 1.0** references use function-subcategory identifiers
  (e.g. MANAGE-2.1). The mapping doc table is generated from
  `rubric/controls.py` by `export_dashboard_data.py` so it can't drift.

## 5. Static posture is necessary, not sufficient

Phase 1 audits *configuration*: what the agent **can** do. It bounds blast
radius and is the prevent/posture floor. It cannot see what the agent
**actually does** — agents choose actions at runtime through the model, so an
agent can hold a perfect posture score while behaving out of scope. Phase 2
(runtime behavioral audit) evaluates observed action streams from CloudTrail
and Bedrock traces against runtime versions of the same control IDs, producing
a separate behavioral score. The two scores are reported side by side because
they answer different questions; the demo case where every agent scores 100 on
posture while failing behaviorally is the point, not a bug.

Some controls exist on only one side by design: change review and lawful
basis are documentation controls (posture-only); scope conformance and model
drift are only observable at runtime.

## 6. Known limitations

- Runs on synthetic configs and traces; not yet wired to a live AWS account.
- Detective, not preventive: Phase 2 catches violations after the fact. It is
  not a real-time decision gate.
- The normalized config schema is an abstraction; a production collector
  would build it from IAM, Bedrock agent definitions, and CloudTrail settings
  via boto3.
