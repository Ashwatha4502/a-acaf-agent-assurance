#!/usr/bin/env python3
"""
A-ACAF Phase 2 — Runtime behavioral audit runner.

Ingests agent traces (CloudTrail + Bedrock), evaluates what each agent actually
did against the control set, and reports timestamped findings plus a behavioral
score per agent — alongside the v1 config posture score for a combined view.

Usage:
    python run_runtime.py                 # runtime audit of the demo fleet traces
    python run_runtime.py --json out.json # also export runtime findings as JSON

The traces are synthetic (mock_data/traces.py). To run against real agents, feed
CloudTrail events and Bedrock traces into engine/collectors.collect().
"""

import argparse
import json
import os
import sys
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.collectors import collect
from engine.runtime_auditor import evaluate_runtime
from engine.auditor import audit_agent
from mock_data.traces import (CLOUDTRAIL_EVENTS, BEDROCK_TRACES, CLASSIFICATION_MAP,
                              ROLE_AGENT_MAP, HIGH_RISK_ACTIONS, RUNTIME_CONTEXTS)
from mock_data.fleet import FLEET_AFTER

RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"

SEV_C = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": "\033[95m", "LOW": DIM}


def color_score(s):
    c = GRN if s >= 90 else YEL if s >= 60 else RED
    return f"{c}{s:>3}{RESET}"


def main():
    ap = argparse.ArgumentParser(description="A-ACAF runtime behavioral audit")
    ap.add_argument("--json", dest="json_out", help="export runtime findings to this JSON path")
    args = ap.parse_args()

    # posture (config) scores from the remediated fleet, for the combined view
    posture = {a["agent_id"]: audit_agent(a).assurance_score for a in FLEET_AFTER}

    actions = collect(CLOUDTRAIL_EVENTS, BEDROCK_TRACES, CLASSIFICATION_MAP,
                      ROLE_AGENT_MAP, HIGH_RISK_ACTIONS)

    print(f"\n{BOLD}A-ACAF Phase 2 — Runtime Behavioral Audit{RESET}")
    print(f"{DIM}{len(actions)} observed actions across {len(RUNTIME_CONTEXTS)} agents "
          f"· sources: CloudTrail + Bedrock traces{RESET}\n")
    print(f"  {DIM}{'agent':20} {'posture':>7} {'behavior':>9}   findings{RESET}")

    export = []
    for aid, ctx in RUNTIME_CONTEXTS.items():
        r = evaluate_runtime(actions, ctx)
        sev = r.by_severity()
        fstr = f"C{sev['CRITICAL']} H{sev['HIGH']} M{sev['MEDIUM']}"
        print(f"  {aid:20} {color_score(posture.get(aid,0))}/100 "
              f"{color_score(r.behavioral_score)}/100   {fstr}  {DIM}({r.window_actions} actions){RESET}")
        export.append({"agent_id": aid, "posture_score": posture.get(aid, 0),
                       "behavioral_score": r.behavioral_score,
                       "findings": [asdict(f) for f in r.findings]})

    print(f"\n{BOLD}  Timestamped runtime findings{RESET}")
    for row in export:
        if not row["findings"]:
            continue
        print(f"\n  {BOLD}{row['agent_id']}{RESET}")
        for f in row["findings"]:
            c = SEV_C.get(f["severity"], "")
            print(f"    {c}{f['severity']:8}{RESET} {f['control_id']:14} {DIM}{f['timestamp']}{RESET}")
            print(f"             {f['evidence']}")

    print(f"\n  {DIM}posture = how the agent is configured (v1) · "
          f"behavior = what it actually did (v2){RESET}\n")

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(export, f, indent=2)
        print(f"  → runtime findings written to {args.json_out}\n")


if __name__ == "__main__":
    main()
