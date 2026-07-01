# Framework Mapping

Every A-ACAF control maps to one or more governance frameworks. This document is the human-readable version of the machine-checkable mapping in [`rubric/controls.py`](../rubric/controls.py).

## Frameworks referenced

- **NIST AI RMF 1.0** — the four functions (GOVERN, MAP, MEASURE, MANAGE) and their subcategories.
- **ISO/IEC 42001:2023** — AI Management System clauses and Annex A controls.
- **OWASP LLM Top 10 (2025)** — the top risk categories for LLM-based applications.

## Control catalog

| Control ID | Title | Severity | NIST AI RMF | ISO/IEC 42001 | OWASP LLM |
|---|---|---|---|---|---|
| AAC-ACCESS-01 | Agent execution role avoids wildcard permissions | HIGH | MANAGE-2.1, GOVERN-1.2 | A.6.2.2, Clause 8.1 | LLM06 |
| AAC-ACCESS-02 | No destructive permissions over sensitive data | CRITICAL | MANAGE-2.1, MEASURE-2.6 | A.6.2.2, A.7.4 | LLM06, LLM02 |
| AAC-DATA-01 | Explicit data boundary is declared | HIGH | MAP-4.1, GOVERN-1.3 | A.7.2, Clause 6.1 | LLM02 |
| AAC-DATA-02 | Lawful processing basis for PII/PHI | HIGH | MAP-4.1, GOVERN-1.1 | A.7.2, A.9.2 | LLM02 |
| AAC-LOG-01 | Agent action tracing is enabled | CRITICAL | MEASURE-2.8, MANAGE-4.1 | A.6.2.6, Clause 9.1 | LLM08 |
| AAC-LOG-02 | Audit logs are tamper-evident | HIGH | MEASURE-2.8, MANAGE-4.1 | A.6.2.6, Clause 9.1 | LLM08 |
| AAC-LOG-03 | Decisions attributable to model + version + prompt | MEDIUM | MEASURE-2.9, MANAGE-4.1 | A.6.2.6, A.6.2.8 | LLM08 |
| AAC-RES-01 | Input guardrails against prompt injection | HIGH | MEASURE-2.7, MANAGE-2.2 | A.6.2.4, Clause 8.1 | LLM01 |
| AAC-RES-02 | Agent output validated before downstream execution | HIGH | MEASURE-2.7, MANAGE-2.2 | A.6.2.4 | LLM05 |
| AAC-OVS-01 | Human approval gates high-risk actions | CRITICAL | MANAGE-2.3, GOVERN-1.4 | A.9.2, A.6.2.7, Clause 8.1 | LLM06 |
| AAC-OVS-02 | Kill switch / pause mechanism exists | HIGH | MANAGE-2.3, MANAGE-4.1 | A.6.2.7, Clause 8.1 | LLM06 |
| AAC-LC-01 | Model version is pinned | MEDIUM | MAP-2.3, MANAGE-4.1 | A.6.2.5, A.6.2.8 | LLM08 |
| AAC-LC-02 | Model/prompt changes go through review | MEDIUM | MANAGE-4.1, GOVERN-1.5 | A.6.2.5, Clause 8.1 | LLM08 |

## How to read a finding

Each failed control produces a finding with five parts:

1. **Severity** — how much the failure lowers the assurance score.
2. **Evidence** — the specific condition observed in the agent config.
3. **Business risk** — why it matters, in audit language.
4. **Remediation** — the concrete fix.
5. **Mapped controls** — the framework references the finding satisfies.

This structure mirrors how a real GRC assessment documents findings, so the output can flow directly into an audit workpaper or a remediation ticket.

## Note on framework citations

Control identifiers (e.g. NIST `MANAGE-2.1`, ISO Annex A clauses, OWASP `LLM01`) are referenced for mapping purposes. Framework texts are owned by their respective bodies (NIST, ISO/IEC, OWASP); this project cites identifiers only and does not reproduce framework content.
