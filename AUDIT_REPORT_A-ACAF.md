# AUDIT REPORT — A-ACAF (AI Agent Control Assurance Framework)

**Audited:** 2026-07-10
**Location (canonical):** `C:\Users\ashwa\Downloads\a-acaf-project\a-acaf-agent-assurance`
**Python:** tested on 3.13

> **Note on source location.** The home `~/a-acaf` directory contains only docs
> (`USER_GUIDE`, `TECHNICAL_DEEP_DIVE`). The actual code exists in several
> Downloads copies. This audit used `a-acaf-project/a-acaf-agent-assurance` — it
> is the only git repository, the most recent (2026-07-07), and the most complete
> (includes Phase 2 runtime auditor). The other copies (`a-acaf-new`,
> `a-acaf-phase2-source`) are older duplicates; `a-acaf-fix` is a different,
> smaller layout. **Recommend consolidating to a single canonical checkout** to
> avoid future divergence.

## Executive summary

A-ACAF is a mature, well-reasoned static config auditor. The control rubric is
the single source of truth, checks are fail-closed with an explicit N/A
(not-assessable) state that is correctly excluded from the score denominator, and
the framework mappings (NIST AI RMF / ISO 42001 / OWASP LLM 2025) are honest
(empty where no mapping applies). Prior fixes for the wildcard bypass and N/A
scoring are in place and regression-tested.

One real crash bug was found and fixed. After the sweep: **21 tests pass**
(was 19).

## Issues found

### Fixed

| Sev | Area | Issue |
| --- | --- | --- |
| HIGH | `rubric/controls.py` | `_chk_no_destructive_on_sensitive` used `r["arn"]` — a `KeyError` on any sensitive resource missing `arn` crashed the whole audit. Reachable via `--agents my.json`. Now skips arn-less resources. Regression tests added. |

Reproduction (pre-fix):
```python
agent = {"iam_policy": {"statements": [{"actions": ["s3:DeleteObject"], "resources": ["*"]}]},
         "accessible_resources": [{"data_classification": "PII"}]}   # no 'arn'
audit_agent(agent)   # → KeyError: 'arn'  (entire audit aborts)
```
Post-fix: audit completes; `AAC-ACCESS-02` correctly FAILs on the `*` grant.

### Observations (not yet actioned — ranked by value)

1. **Input schema is not validated.** `audit_agent` consumes a raw dict and each
   check defends (or, as above, failed to defend) individually. A single
   normalization/validation pass over the agent config — coercing types, checking
   that `accessible_resources` items are dicts, that `iam_policy.statements` is a
   list — would centralize robustness and prevent the next `r["arn"]`-class bug.
   **Highest-value hardening.** Consider a small dataclass/`TypedDict` or a
   `pydantic` model (AIOST already depends on pydantic; A-ACAF could too).
2. **`sys.path.insert` import hack** in `engine/auditor.py` and `run_audit.py`.
   The project has no `pyproject.toml`/`setup.py`, so modules are wired together
   via `sys.path` manipulation. Packaging it (like A-ACAF-RT and AIOST) would make
   imports clean and the tool `pip install`-able.
3. **`_action_is_destructive` prefix list is S3/DynamoDB/RDS-only.** Destructive
   actions in other services (`ec2:TerminateInstances`, `iam:DeleteRole`,
   `lambda:DeleteFunction`, `kms:ScheduleKeyDeletion`) are not caught unless
   expressed as a wildcard. Reasonable for a demo scope, but worth expanding the
   `_DESTRUCTIVE_PREFIXES`/`_DESTRUCTIVE_SERVICES` sets for real fleets. Documented
   as a known limitation would suffice short-term.
4. **No coverage tooling.** Tests are good (adversarial cases, scoring extremes,
   parity) but coverage isn't measured. Add `pytest-cov`.
5. **Phase 2 runtime auditor** (`engine/runtime_auditor.py`, `runtime_schema.py`)
   was not deeply audited in this pass — flagged for a follow-up review since it
   is the newest code.

## What was verified as correct (no change needed)

- **Scoring** (`engine/auditor.py`) — severity-weighted penalty over assessable
  controls only; N/A excluded from denominator so disabling a parent control
  (e.g. logging) can't inflate the score via dependents. Regression-tested.
- **Wildcard handling** (`_action_is_destructive`, `_chk_no_wildcard_actions`) —
  `*` and `service:*` are treated as supersets of destructive actions; a wildcard
  grant never scores better than an enumerated destructive one. Regression-tested.
- **N/A semantics** for dependent logging controls (`AAC-LOG-02/03` become N/A
  when tracing is off). Correct and tested.

## Metrics

- Tests: **21 passed** (was 19). Coverage not currently measured.
