"""
End-to-end over real HTTP: spin up the fixture in each mode, run T1 through the
HTTP adapter, and assert the verdict. This is the same path a real case uses,
so passing here means the pipeline works against a live server, not a mock.

Run:  python -m pytest harness/integration_test.py -q
"""

import json
import os
import tempfile

from fixture_control import fixture
from http_adapter import http_session
from t1_cross_tenant import run_t1
from verdict import Verdict, evaluate


def _run(base):
    a = http_session("A", base)
    b = http_session("B", base)
    result = run_t1("run1", "a1", a, b, seed_tool="seed", read_tool="read")
    return evaluate(result)


def test_protected_passes_over_http():
    with fixture("protected") as base:
        v, _ = _run(base)
        assert v == Verdict.PASS


def test_vulnerable_fails_over_http():
    with fixture("vulnerable") as base:
        v, _ = _run(base)
        assert v == Verdict.FAIL


def test_leak_then_deny_fails_with_conflict():
    with fixture("leak_then_deny") as base:
        v, reason = _run(base)
        assert v == Verdict.FAIL


def test_drop_event_still_passes():
    # Correct enforcement, decision field omitted. No leak, control fires -> PASS.
    with fixture("drop_event") as base:
        v, _ = _run(base)
        assert v == Verdict.PASS


def test_oracle_ledger_confirms_leak_fired():
    # Meta-check: the vulnerable fixture really performed the cross-tenant
    # disclosure. If it hadn't, a PASS would be a false negative, not a win.
    with tempfile.TemporaryDirectory() as d:
        oracle = os.path.join(d, "oracle.jsonl")
        with fixture("vulnerable", oracle_path=oracle) as base:
            v, _ = _run(base)
            assert v == Verdict.FAIL
        events = [json.loads(l) for l in open(oracle)]
        cross = [e for e in events
                 if e.get("effect") == "disclose" and e["owner"] != e["to"]]
        assert cross, "oracle shows no cross-tenant disclosure actually happened"
