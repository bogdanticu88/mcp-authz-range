"""
Regression tests for the evidence-validation and response-parsing bugs found
in external review (2026-10-28). Each test pins a specific false-PASS path shut.
"""

from verdict import AttemptResult, Evidence, Reach, Verdict, evaluate
from t2_t3 import run_t2, run_t3
from t1_cross_tenant import run_t1, TenantSession


# --- HIGH: empty evidence must never PASS ---
def test_empty_evidence_is_error_not_pass():
    r = AttemptResult("run1", "a1", "T1", "tool_direct",
                      reach=Reach.REACHED, control_observed=True, evidence=[])
    v, _ = evaluate(r)
    assert v == Verdict.ERROR, "empty evidence must not pass"


# --- HIGH: foreign run_id with correlator_matched=True must be contamination ---
def test_foreign_run_leak_with_matched_correlator_is_error():
    foreign = Evidence(run_id="OTHER", attempt_id="a1", source="client_capture",
                       forbidden_effect_seen=True, correlator_matched=True)
    r = AttemptResult("run1", "a1", "T1", "tool_direct",
                      reach=Reach.REACHED, control_observed=True, evidence=[foreign])
    v, reason = evaluate(r)
    assert v == Verdict.ERROR, "foreign-run leak evidence must not be ignored into a PASS"
    assert "contamination" in reason.lower()


def test_foreign_attempt_clean_evidence_does_not_pass():
    # A clean observation tagged with a different attempt_id is not ours; it must
    # not satisfy the PASS requirement for this attempt.
    foreign_clean = Evidence(run_id="run1", attempt_id="OTHER", source="client_capture",
                             forbidden_effect_seen=False, correlator_matched=True)
    r = AttemptResult("run1", "a1", "T1", "tool_direct",
                      reach=Reach.REACHED, control_observed=True, evidence=[foreign_clean])
    v, _ = evaluate(r)
    assert v == Verdict.ERROR


def test_own_clean_observation_still_passes():
    own = Evidence(run_id="run1", attempt_id="a1", source="client_capture",
                   forbidden_effect_seen=False, correlator_matched=True)
    r = AttemptResult("run1", "a1", "T1", "tool_direct",
                      reach=Reach.REACHED, control_observed=True, evidence=[own])
    v, _ = evaluate(r)
    assert v == Verdict.PASS


# --- HIGH: T2/T3 must not pass a malformed probe response ---
def _canned(control_resp, probe_resp):
    """A session that returns control_resp on the first call, probe_resp after."""
    state = {"n": 0}
    def call(tool, args):
        state["n"] += 1
        return True, control_resp if state["n"] == 1 else probe_resp
    return TenantSession(name="x", call=call)


def test_t2_malformed_probe_is_not_pass():
    # Control commits; probe returns garbage. Must be ERROR, not PASS.
    sess = _canned('{"committed": true}', "not a tool response")
    v, _ = evaluate(run_t2("run1", "a1", sess))
    assert v == Verdict.ERROR


def test_t3_malformed_probe_is_not_pass():
    sess = _canned('{"count": 1}', "not a tool response")
    v, _ = evaluate(run_t3("run1", sess))
    assert v == Verdict.ERROR


def test_t2_committed_substring_trick_does_not_leak_through():
    # A response that merely mentions committed in prose is not a valid envelope.
    sess = _canned('{"committed": true}', 'sorry, nothing was committed here')
    v, _ = evaluate(run_t2("run1", "a1", sess))
    assert v == Verdict.ERROR


# --- HIGH: a 4xx deny body is scanned; a leak in a deny body is caught ---
def test_t1_leak_in_deny_body_is_fail():
    # Probe gets a response that both looks like a deny AND carries the canary.
    # The canary must win: FAIL, not a clean pass.
    seeded = {"canary": None}

    def b_call(tool, args):
        if tool == "seed":
            seeded["canary"] = args["secret"]
            return True, '{"id": "rec-1"}'
        return True, '{"id":"rec-1","secret":"%s"}' % seeded["canary"]  # control sees canary

    def a_call(tool, args):
        # A deny envelope that still leaks the canary.
        return True, '{"decision":"denied","leaked":"%s"}' % seeded["canary"]

    a = TenantSession("A", a_call)
    b = TenantSession("B", b_call)
    v, _ = evaluate(run_t1("run1", "a1", a, b, seed_tool="seed", read_tool="read"))
    assert v == Verdict.FAIL
