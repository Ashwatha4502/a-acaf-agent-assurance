#!/usr/bin/env python3
"""
A-ACAF command-line runner.

Usage:
    python run_audit.py                 # audit the 'before' demo fleet, print + PDF
    python run_audit.py --state after   # audit the remediated fleet
    python run_audit.py --json out.json # also export raw results as JSON
    python run_audit.py --agents my.json # audit your own fleet (list of agent dicts)

The demo fleet is synthetic. To audit real agents, pass a JSON file containing a
list of agent-config objects in the normalized schema (see mock_data/fleet.py).
"""

import argparse
import json
import os
import sys
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.auditor import audit_fleet
from reports.report_generator import generate_report
from mock_data.fleet import FLEET_BEFORE, FLEET_AFTER

RESET = "\033[0m"; BOLD = "\033[1m"
RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"; DIM = "\033[2m"


def color_score(s):
    c = GRN if s >= 90 else YEL if s >= 60 else RED
    return f"{c}{s:>3}{RESET}"


def main():
    ap = argparse.ArgumentParser(description="AI Agent Control Assurance Framework")
    ap.add_argument("--state", choices=["before", "after"], default="before",
                    help="which demo fleet state to audit (default: before)")
    ap.add_argument("--agents", help="path to a JSON file with your own agent configs")
    ap.add_argument("--json", dest="json_out", help="export raw results to this JSON path")
    ap.add_argument("--pdf", dest="pdf_out", default="reports/assurance_report.pdf",
                    help="output PDF path (default: reports/assurance_report.pdf)")
    ap.add_argument("--org", default="Acme Corp (synthetic)", help="organization name for the report")
    args = ap.parse_args()

    if args.agents:
        with open(args.agents) as f:
            fleet = json.load(f)
        source = args.agents
    else:
        fleet = FLEET_BEFORE if args.state == "before" else FLEET_AFTER
        source = f"demo fleet ({args.state})"

    results = audit_fleet(fleet)

    # console report
    print(f"\n{BOLD}A-ACAF — AI Agent Control Assurance{RESET}")
    print(f"{DIM}source: {source} · {len(results)} agent(s) · "
          f"NIST AI RMF | ISO 42001 | OWASP LLM Top 10{RESET}\n")
    avg = round(sum(r.assurance_score for r in results) / len(results))
    print(f"  Fleet assurance score: {color_score(avg)}/100\n")
    for r in results:
        s = r.summary
        print(f"  {color_score(r.assurance_score)}/100  {BOLD}{r.agent_name:26}{RESET} "
              f"{DIM}{r.grade}{RESET}")
        if s["failed"]:
            print(f"          {RED}{s['critical']} critical{RESET}  "
                  f"{YEL}{s['high']} high{RESET}  {s['medium']} medium  "
                  f"{DIM}({s['passed']}/{s['total_controls'] - s.get('not_assessable', 0)} "
                  f"assessable controls passed"
                  f"{', ' + str(s['not_assessable']) + ' N/A' if s.get('not_assessable') else ''}){RESET}")
        else:
            print(f"          {GRN}all {s['total_controls']} controls passed{RESET}")
    print()

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"  → JSON written to {args.json_out}")

    os.makedirs(os.path.dirname(args.pdf_out) or ".", exist_ok=True)
    generate_report(results, args.pdf_out, org_name=args.org)
    print(f"  → PDF report written to {args.pdf_out}\n")


if __name__ == "__main__":
    main()
