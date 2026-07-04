#!/usr/bin/env python3
"""
Regenerate the derived artifacts that must stay in lockstep with the Python
engine (rubric/controls.py + engine/auditor.py — the single source of truth):

  1. docs/audit_data.js — pre-computed demo-fleet results consumed by the
     GitHub Pages console (so the static page loads instantly).
  2. The control-catalog table inside docs/FRAMEWORK_MAPPING.md.

The dashboard's "Audit your own" mode runs a JS port of the engine live in
the browser; tests/test_engine_parity.py guards that the port agrees with
Python. This script guards everything pre-computed.

Usage:
    python export_dashboard_data.py
"""

import json
import os
import re
import sys
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.auditor import audit_fleet
from mock_data.fleet import FLEET_BEFORE, FLEET_AFTER
from rubric.controls import CONTROLS

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_OUT = os.path.join(ROOT, "docs", "audit_data.js")
MAPPING_DOC = os.path.join(ROOT, "docs", "FRAMEWORK_MAPPING.md")


def _short(refs: list[str]) -> str:
    """Strip parenthetical titles for the compact table view."""
    return ", ".join(re.sub(r"\s*\(.*?\)", "", r).strip() for r in refs) or "—"


def export_dashboard_data() -> None:
    data = {
        "before": [asdict(r) for r in audit_fleet(FLEET_BEFORE)],
        "after": [asdict(r) for r in audit_fleet(FLEET_AFTER)],
    }
    with open(DATA_OUT, "w") as f:
        f.write("window.AUDIT_DATA = " + json.dumps(data) + ";\n")
    for state in ("before", "after"):
        scores = [r["assurance_score"] for r in data[state]]
        print(f"{state:6}: {scores}")
    print(f"wrote {DATA_OUT}")


def export_mapping_table() -> None:
    rows = ["| Control ID | Title | Severity | NIST AI RMF | ISO/IEC 42001 | OWASP LLM (2025) |",
            "|---|---|---|---|---|---|"]
    for c in CONTROLS:
        rows.append(f"| {c.id} | {c.title} | {c.severity.value} | "
                    f"{_short(c.nist_ai_rmf)} | {_short(c.iso_42001)} | "
                    f"{_short(c.owasp_llm)} |")
    table = "\n".join(rows)

    doc = open(MAPPING_DOC).read()
    # Replace everything between '## Control catalog' and the next '##' heading
    new_doc, n = re.subn(
        r"(## Control catalog\n\n).*?(\n\n## )",
        r"\g<1>" + table.replace("\\", "\\\\") + r"\g<2>",
        doc, flags=re.S)
    assert n == 1, "could not locate control catalog table in FRAMEWORK_MAPPING.md"
    open(MAPPING_DOC, "w").write(new_doc)
    print(f"wrote control table ({len(CONTROLS)} controls) to {MAPPING_DOC}")


def main() -> None:
    export_dashboard_data()
    export_mapping_table()


if __name__ == "__main__":
    main()
