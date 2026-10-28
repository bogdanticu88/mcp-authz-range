"""T2 and T3 over real HTTP, protected and vulnerable both ways."""

from fixture_control import fixture
from http_adapter import http_session
from t2_t3 import run_t2, run_t3
from verdict import Verdict, evaluate


def test_t2_protected_passes():
    with fixture("protected") as base:
        v, _ = evaluate(run_t2("run1", "a1", http_session("A", base)))
        assert v == Verdict.PASS


def test_t2_vulnerable_fails():
    with fixture("write_vuln") as base:
        v, _ = evaluate(run_t2("run1", "a1", http_session("A", base)))
        assert v == Verdict.FAIL


def test_t3_protected_passes():
    with fixture("protected") as base:
        v, _ = evaluate(run_t3("run1", http_session("A", base)))
        assert v == Verdict.PASS


def test_t3_vulnerable_fails():
    with fixture("replay_vuln") as base:
        v, _ = evaluate(run_t3("run1", http_session("A", base)))
        assert v == Verdict.FAIL
