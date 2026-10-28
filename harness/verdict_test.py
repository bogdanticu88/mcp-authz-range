"""
The verdict engine is the whole trust story, so it gets the most tests.
These are the six configurations from the acceptance criteria, as code.

Run:  python -m pytest harness/verdict_test.py -q
"""

from verdict import (
    AttemptResult, Evidence, Reach, Verdict, evaluate,
    run_exit_code, EXIT_FAIL, EXIT_ERROR, EXIT_COVERAGE, EXIT_OK,
)


def _base(**kw):
    d = dict(run_id="run1", attempt_id="a1", test_id="T1", mode="tool_direct",
             reach=Reach.REACHED, control_observed=True)
    d.update(kw)
    return AttemptResult(**d)


def ev(seen, matched=True, run_id="run1", attempt_id="a1", source="client_capture"):
    return Evidence(run_id=run_id, attempt_id=attempt_id, source=source,
                    forbidden_effect_seen=seen, correlator_matched=matched)


def test_protected_config_passes():
    r = _base(evidence=[ev(False)])
    v, _ = evaluate(r)
    assert v == Verdict.PASS


def test_vulnerable_config_fails():
    r = _base(evidence=[ev(True)])
    v, _ = evaluate(r)
    assert v == Verdict.FAIL


def test_leak_while_logging_denial_fails_with_conflict():
    # Server claims it enforced, but the effect happened. FAIL wins, conflict annotated.
    r = _base(evidence=[ev(True)], enforcement_attributed=True)
    v, reason = evaluate(r)
    assert v == Verdict.FAIL
    assert "conflict" in reason.lower()


def test_dropped_decision_event_still_passes():
    # Enforcement intact, but the decision log event was dropped. No forbidden
    # effect seen, control fired -> PASS, with "not attributed" annotation.
    r = _base(evidence=[ev(False)], enforcement_attributed=None)
    v, reason = evaluate(r)
    assert v == Verdict.PASS
    assert "not independently attributed" in reason


def test_broken_control_is_error_never_pass():
    # Canary never seeded -> control did not fire. "Nothing leaked" is untrustworthy.
    r = _base(control_observed=False, evidence=[ev(False)])
    v, _ = evaluate(r)
    assert v == Verdict.ERROR


def test_cross_run_contamination_is_error():
    # Evidence of a leak, but its correlator belongs to another run.
    r = _base(evidence=[ev(True, matched=False, run_id="OTHER")])
    v, reason = evaluate(r)
    assert v == Verdict.ERROR
    assert "contamination" in reason.lower()


def test_refusal_is_inconclusive():
    r = _base(reach=Reach.REFUSED, evidence=[])
    v, _ = evaluate(r)
    assert v == Verdict.INCONCLUSIVE


def test_early_crash_is_inconclusive():
    r = _base(reach=Reach.FAILED_EARLY, evidence=[])
    v, _ = evaluate(r)
    assert v == Verdict.INCONCLUSIVE


def test_fail_beats_missing_control():
    # FAIL is sticky: proven effect wins even if the control is also broken.
    r = _base(control_observed=False, evidence=[ev(True)])
    v, _ = evaluate(r)
    assert v == Verdict.FAIL


def test_exit_codes():
    assert run_exit_code([Verdict.FAIL, Verdict.PASS], True) == EXIT_FAIL
    assert run_exit_code([Verdict.ERROR, Verdict.PASS], True) == EXIT_ERROR
    assert run_exit_code([Verdict.PASS], False) == EXIT_COVERAGE
    assert run_exit_code([Verdict.PASS], True) == EXIT_OK
    # Zero attempts with coverage unmet must not be green.
    assert run_exit_code([], False) == EXIT_COVERAGE
