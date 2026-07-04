# Framework Mapping

Every A-ACAF control maps to one or more governance frameworks. This document is the human-readable version of the machine-checkable mapping in [`rubric/controls.py`](../rubric/controls.py).

## Frameworks referenced

- **NIST AI RMF 1.0** — the four functions (GOVERN, MAP, MEASURE, MANAGE) and their subcategories.
- **ISO/IEC 42001:2023** — AI Management System clauses and Annex A controls.
- **OWASP LLM Top 10 (2025)** — the top risk categories for LLM-based applications. Mappings use the **2025 numbering only** (the 2023 and 2025 lists renumbered several entries — e.g. Excessive Agency moved from LLM08 to LLM06). A "—" means the control has no honest OWASP equivalent: logging and change management are not OWASP LLM Top 10 entries, and an honest gap beats a stretched citation.

The table below is **generated from `rubric/controls.py`** by `export_dashboard_data.py`, so it cannot drift from the engine. See [DESIGN.md](../DESIGN.md) for the mapping principles.

## Control catalog

| Control ID | Title | Severity | NIST AI RMF | ISO/IEC 42001 | OWASP LLM (2025) |
|---|---|---|---|---|---|
| AAC-ACCESS-01 | Agent execution role avoids wildcard permissions | HIGH | MANAGE-2.1, GOVERN-1.2 | A.9.4, Clause 8.1 | LLM06: Excessive Agency |
| AAC-ACCESS-02 | No destructive permissions over sensitive data | CRITICAL | MANAGE-2.1, MEASURE-2.6 | A.9.4, A.7.4 | LLM06: Excessive Agency, LLM02: Sensitive Information Disclosure |
| AAC-DATA-01 | Explicit data boundary is declared | HIGH | MAP-4.1, GOVERN-1.3 | A.4.3, A.9.4 | LLM02: Sensitive Information Disclosure |
| AAC-DATA-02 | Lawful processing basis for PII/PHI | HIGH | MAP-4.1, GOVERN-1.1 | A.7.3, A.2.3 | LLM02: Sensitive Information Disclosure |
| AAC-LOG-01 | Agent action tracing is enabled | CRITICAL | MEASURE-2.8, MANAGE-4.1 | A.6.2.8, A.6.2.6 | — |
| AAC-LOG-02 | Audit logs are tamper-evident | HIGH | MEASURE-2.8, MANAGE-4.1 | A.6.2.8, Clause 9.1 | — |
| AAC-LOG-03 | Decisions are attributable to model + version + prompt | MEDIUM | MEASURE-2.9, MANAGE-4.1 | A.6.2.8, A.4.4 | — |
| AAC-RES-01 | Input guardrails against prompt injection | HIGH | MEASURE-2.7, MANAGE-2.2 | A.6.2.6, A.6.2.2 | LLM01: Prompt Injection |
| AAC-RES-02 | Agent output validated before downstream execution | HIGH | MEASURE-2.7, MANAGE-2.2 | A.6.2.6, A.6.2.2 | LLM05: Improper Output Handling |
| AAC-OVS-01 | Human approval gates high-risk actions | CRITICAL | MANAGE-2.3, GOVERN-1.4 | A.9.2, A.9.3 | LLM06: Excessive Agency |
| AAC-OVS-02 | Kill switch / pause mechanism exists | HIGH | MANAGE-2.3, MANAGE-4.1 | A.9.2, A.6.2.6 | LLM06: Excessive Agency |
| AAC-LC-01 | Model version is pinned | MEDIUM | MAP-2.3, MANAGE-4.1 | A.4.4, A.6.2.5 | LLM03: Supply Chain |
| AAC-LC-02 | Model/prompt changes go through review | MEDIUM | MANAGE-4.1, GOVERN-1.5 | A.6.2.5, A.6.1.3 | — |

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
