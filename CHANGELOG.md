# Changelog

All notable changes to A-ACAF are documented here.

## [Unreleased] — 2026-07-10

### Fixed
- **Audit crashed on user-supplied resources missing an `arn`.** Control
  `AAC-ACCESS-02` (`_chk_no_destructive_on_sensitive`) built its sensitive-resource
  set with a hard `r["arn"]` subscript. A resource that declares a sensitive
  `data_classification` (`PHI`/`PII`/`sensitive`) but omits `arn` raised
  `KeyError`, aborting the entire audit — directly violating the rubric's
  fail-closed contract that a malformed config must be *assessed*, not fatal.
  This is reachable via the "audit your own fleet" path (`--agents my.json`).
  Fix: skip resources without an `arn` when building the match set (they cannot
  be matched to a specific-resource grant; wildcard `*` grants still hit).
  Regression tests added (`test_resource_missing_arn_does_not_crash`,
  `test_resource_missing_arn_specific_resource_is_ignored`).

### Notes
- Full suite: **21 passed** (was 19). See `AUDIT_REPORT_A-ACAF.md`.
