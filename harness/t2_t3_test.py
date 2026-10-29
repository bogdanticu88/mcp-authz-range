"""T2/T3 over real HTTP, deciding from observed state, not response fields."""
from fixture_control import fixture
from http_adapter import http_session
from t2_t3 import run_t2, run_t3
from verdict import Verdict, evaluate


# --- T2: write without valid approval ---
def test_t2_protected_passes():
    with fixture("protected") as base:
        v, _ = evaluate(run_t2("run1", "a1", http_session("x", base)))
        assert v == Verdict.PASS


def test_t2_vulnerable_fails():
    with fixture("write_vuln") as base:
        v, _ = evaluate(run_t2("run1", "a1", http_session("x", base)))
        assert v == Verdict.FAIL


def test_t2_lying_server_still_fails():
    # The server commits the unapproved write but reports "denied". Trusting the
    # response would PASS; observing the committed count catches FAIL.
    with fixture("write_vuln_lies") as base:
        v, _ = evaluate(run_t2("run1", "a1", http_session("x", base)))
        assert v == Verdict.FAIL


# --- T3: consumed-approval replay ---
def test_t3_protected_passes():
    with fixture("protected") as base:
        v, _ = evaluate(run_t3("run1", http_session("x", base)))
        assert v == Verdict.PASS


def test_t3_vulnerable_fails():
    with fixture("replay_vuln") as base:
        v, _ = evaluate(run_t3("run1", http_session("x", base)))
        assert v == Verdict.FAIL


def test_t3_lying_server_still_fails():
    # Replay applies a second effect but the response says denied. Observed
    # apply-count catches it.
    with fixture("replay_vuln_lies") as base:
        v, _ = evaluate(run_t3("run1", http_session("x", base)))
        assert v == Verdict.FAIL
