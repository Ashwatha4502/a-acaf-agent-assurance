"""
Parity test: the JavaScript engine port (docs/audit_engine.js, which powers the
'Audit your own' mode on the live console) must produce byte-identical scores
and per-control statuses to the Python engine for the same input.

Skipped automatically if Node.js is not installed.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.auditor import audit_agent
from mock_data.fleet import FLEET_BEFORE, FLEET_AFTER

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NODE_RUNNER = """
global.window = {};
require(process.argv[1]);
const fleet = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = fleet.map(a => {
  const r = window.AACAF.auditAgent(a);
  return {
    score: r.assurance_score,
    grade: r.grade,
    statuses: Object.fromEntries(r.findings.map(f => [f.control_id, f.status])),
    summary: r.summary,
  };
});
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("fleet", [FLEET_BEFORE, FLEET_AFTER],
                         ids=["before", "after"])
def test_js_engine_matches_python(fleet):
    js_path = os.path.join(ROOT, "docs", "audit_engine.js")
    proc = subprocess.run(
        ["node", "-e", NODE_RUNNER, js_path],
        input=json.dumps(fleet), capture_output=True, text=True, check=True,
    )
    js_results = json.loads(proc.stdout)

    for agent, js in zip(fleet, js_results):
        py = audit_agent(agent)
        assert js["score"] == py.assurance_score, agent["agent_name"]
        assert js["grade"] == py.grade
        py_statuses = {f.control_id: f.status for f in py.findings}
        assert js["statuses"] == py_statuses, agent["agent_name"]
        for key in ("passed", "failed", "not_assessable", "critical", "high"):
            assert js["summary"][key] == py.summary[key], (agent["agent_name"], key)
