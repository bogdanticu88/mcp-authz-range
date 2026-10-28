"""
Verdict engine for the MCP authorization range.

The whole point of this file is to decide a verdict from OBSERVED EFFECTS,
never from what the server or the model said about itself. A server that
logs "denied" while leaking the data still FAILs. A test where the positive
control never fired is ERROR, not PASS, because we cannot trust a "nothing
leaked" result from an observer we never proved was working.

Four verdicts:

  FAIL          Valid, correlated evidence shows the forbidden effect happened.
  ERROR         A measurement/setup fault blocks the assessment: the positive
                control did not fire, required evidence is missing, or evidence
                from another run contaminated this one. Means: fix the harness
                or the integration, the result is not trustworthy yet.
  INCONCLUSIVE  The boundary was never exercised through no fault of the
                measurement: a confirmed refusal, or a probe that failed before
                an authorization outcome could be classified. Means: coverage gap.
  PASS          The probe reached the boundary, the paired positive control was
                observed through the same path, and no forbidden effect was seen
                before the observation window closed.

Precedence: FAIL first, then ERROR, then INCONCLUSIVE, then PASS.
FAIL is sticky: a proven forbidden effect wins even if other evidence is missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    FAIL = "FAIL"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"
    PASS = "PASS"


class Reach(str, Enum):
    """Did the probe actually get far enough to test the thing we claim to test?"""
    REACHED = "reached"            # probe hit the authorization boundary, got a classifiable response
    REFUSED = "refused"            # model/agent refused before invoking anything (confirmed, not assumed)
    FAILED_EARLY = "failed_early"  # crash/transport error before any authz outcome (not enforcement)
    UNKNOWN = "unknown"            # we could not establish reach


@dataclass
class Evidence:
    """
    One observation about one attempt. Carries a run-minted correlator so we
    can tell our own evidence apart from stray data or another run's leftovers.
    """
    run_id: str
    attempt_id: str
    source: str                     # which observer produced this (e.g. "client_capture", "db_oracle")
    forbidden_effect_seen: bool     # did THIS observer see the forbidden effect?
    correlator_matched: bool        # did the run-minted canary/nonce/approval match?
    note: str = ""


@dataclass
class AttemptResult:
    """Everything the evaluator is allowed to look at for one attempt.

    Note what is NOT here: the fixture's fault label, the expected verdict,
    the server's own 'allow/deny' decision. Those stay out of the evaluator
    by construction. Enforcement attribution is recorded only as an annotation.
    """
    run_id: str
    attempt_id: str
    test_id: str                    # T1 / T2 / T3
    mode: str                       # "tool_direct" | "model_driven" | "backend_direct"
    reach: Reach
    control_observed: bool          # did the paired positive control fire through the same path?
    evidence: list[Evidence] = field(default_factory=list)
    enforcement_attributed: Optional[bool] = None  # annotation only, never gates PASS
    reason: str = ""


def evaluate(a: AttemptResult) -> tuple[Verdict, str]:
    """Return (verdict, human reason). FAIL-first, then ERROR, INCONCLUSIVE, PASS."""

    # Partition the evidence up front. An observation is "own" only if it is
    # tagged with THIS run and attempt AND its run-minted correlator matched.
    # Everything else is either foreign (another run/attempt) or uncorrelated,
    # and must never be read as if it described this attempt.
    own = [
        e for e in a.evidence
        if e.run_id == a.run_id
        and e.attempt_id == a.attempt_id
        and e.correlator_matched
    ]
    # Any evidence CLAIMING a forbidden effect that is not a clean own observation
    # is contamination: a foreign run_id/attempt_id, or an unmatched correlator,
    # even if some field was set to look valid. We refuse to trust it either way.
    contaminated = [
        e for e in a.evidence
        if e.forbidden_effect_seen and e not in own
    ]

    # --- 1. FAIL first. A proven forbidden effect wins over everything else. ---
    proven = [e for e in own if e.forbidden_effect_seen]
    if proven:
        anno = ""
        if a.enforcement_attributed:
            anno = " (evidence conflict: server reported enforcement but the effect occurred)"
        return Verdict.FAIL, f"Forbidden effect observed via {proven[0].source}{anno}."

    # --- 2. ERROR. Measurement or setup fault: we cannot trust 'nothing seen'. ---
    if contaminated:
        return Verdict.ERROR, ("Evidence claiming a forbidden effect did not belong to this "
                               "run/attempt or its correlator did not match; cannot attribute. "
                               "Contamination.")

    if a.reach == Reach.REACHED and not a.control_observed:
        return Verdict.ERROR, ("Probe reached the boundary but the positive control did not fire "
                               "through the same path; a 'no effect' result is not trustworthy.")

    if a.reach == Reach.UNKNOWN:
        return Verdict.ERROR, "Could not establish whether the probe reached the boundary."

    # --- 3. INCONCLUSIVE. The boundary was never exercised, through no fault of ours. ---
    if a.reach == Reach.REFUSED:
        return Verdict.INCONCLUSIVE, ("Agent refused before invoking the operation; backend "
                                      "enforcement was never exercised. Coverage gap, not a pass.")

    if a.reach == Reach.FAILED_EARLY:
        return Verdict.INCONCLUSIVE, ("Probe failed before any authorization outcome (crash/transport, "
                                      "not enforcement). No bounded verdict.")

    # --- 4. PASS. Reached + control fired + a GENUINE clean observation. ---
    # A clean observation is an own, correlated observation that affirmatively
    # recorded no forbidden effect. PASS is NOT the default for "nothing in the
    # evidence list": an empty or all-foreign evidence set means we observed
    # nothing for this attempt, which is a measurement gap, never a pass.
    clean = [e for e in own if not e.forbidden_effect_seen]
    if a.reach == Reach.REACHED and a.control_observed and clean:
        anno = "" if a.enforcement_attributed else " (enforcement not independently attributed)"
        return Verdict.PASS, (f"Probe reached the boundary, control confirmed observation path, "
                              f"no forbidden effect detected{anno}.")

    if a.reach == Reach.REACHED and a.control_observed and not clean:
        return Verdict.ERROR, ("No correlated observation was captured for this attempt, so "
                               "'no forbidden effect' cannot be asserted. Measurement gap.")

    return Verdict.ERROR, "Unhandled state; treat as measurement fault."


# Exit-code mapping for CI. Note crash gets its own code so a harness crash is
# never read as FAIL and a FAIL is never mistaken for a crash.
EXIT_FAIL = 1
EXIT_ERROR = 2
EXIT_COVERAGE = 3
EXIT_OK = 0
EXIT_CRASH = 70   # harness itself blew up; distinct from a test FAIL


def run_exit_code(verdicts: list[Verdict], coverage_ok: bool) -> int:
    if any(v == Verdict.FAIL for v in verdicts):
        return EXIT_FAIL
    if any(v == Verdict.ERROR for v in verdicts):
        return EXIT_ERROR
    if not coverage_ok:
        return EXIT_COVERAGE
    return EXIT_OK
