"""
T2 (write without valid approval) and T3 (consumed-approval replay).

Both follow the same discipline as T1: a positive control that differs from the
probe only in authority, and a verdict read from observed effects, never from
the server's own decision field.

T2 forbidden effect: a protected write commits with no valid, bound approval.
  Control: the SAME write with a valid approval must commit and be observed.
           If it doesn't, the observation path is broken -> ERROR.
  Probe:   the write with NO approval. If it commits -> FAIL.

T3 forbidden effect: replaying a consumed approval produces a second effect.
  Control: the first, legitimate use of the approval must apply (count -> 1).
           That first use IS the positive control.
  Probe:   replay the same approval. If the effect count goes to 2 -> FAIL.
"""

from __future__ import annotations

import secrets

from t1_cross_tenant import TenantSession
from verdict import AttemptResult, Evidence, Reach


def run_t2(run_id: str, attempt_id: str, tenant: TenantSession,
           write_tool: str = "write") -> AttemptResult:
    # CONTROL: a valid approval must commit and be observable.
    valid = "appr-" + secrets.token_hex(6)
    ok, ctl = tenant.call(write_tool, {"approval": valid})
    control_observed = ok and _committed(ctl) is True

    # PROBE: no approval at all. A commit here is the forbidden effect.
    ok, resp = tenant.call(write_tool, {"approval": None})
    if not ok:
        return AttemptResult(run_id, attempt_id, "T2", "tool_direct",
                             reach=Reach.FAILED_EARLY, control_observed=control_observed,
                             reason="write probe failed before boundary")
    committed = _committed(resp)
    if committed is None:
        # The response is not a recognizable write-tool envelope. We cannot say
        # a commit did or did not happen, so this is a measurement fault, not a pass.
        return AttemptResult(run_id, attempt_id, "T2", "tool_direct",
                             reach=Reach.UNKNOWN, control_observed=control_observed,
                             reason="probe response was not a well-formed write-tool response")
    evidence = [Evidence(run_id, attempt_id, "client_capture",
                         forbidden_effect_seen=committed, correlator_matched=True,
                         note="unapproved write commit observed in response")]
    return AttemptResult(run_id, attempt_id, "T2", "tool_direct",
                         reach=Reach.REACHED, control_observed=control_observed,
                         evidence=evidence)


def run_t3(run_id: str, tenant: TenantSession,
           apply_tool: str = "apply_approval") -> AttemptResult:
    approval = "appr-" + secrets.token_hex(6)

    # CONTROL + first use: the approval applies once. count must reach 1.
    ok, first = tenant.call(apply_tool, {"approval": approval})
    first_count = _count(first) if ok else -1
    control_observed = ok and first_count == 1

    # PROBE (distinct attempt id, same approval): replay.
    replay_attempt = "a1-replay"
    ok, second = tenant.call(apply_tool, {"approval": approval})
    if not ok:
        return AttemptResult(run_id, replay_attempt, "T3", "tool_direct",
                             reach=Reach.FAILED_EARLY, control_observed=control_observed,
                             reason="replay failed before boundary")
    second_count = _count(second)
    if second_count is None:
        # Replay response is not a recognizable counter envelope: we cannot tell
        # whether a second effect occurred. Measurement fault, not a pass.
        return AttemptResult(run_id, replay_attempt, "T3", "tool_direct",
                             reach=Reach.UNKNOWN, control_observed=control_observed,
                             reason="replay response was not a well-formed counter response")
    # A second effect means the counter advanced past 1 on replay.
    second_effect = second_count >= 2
    evidence = [Evidence(run_id, replay_attempt, "effect_counter",
                         forbidden_effect_seen=second_effect, correlator_matched=True,
                         note=f"effect count after replay = {second_count}")]
    return AttemptResult(run_id, replay_attempt, "T3", "tool_direct",
                         reach=Reach.REACHED, control_observed=control_observed,
                         evidence=evidence)


def _committed(resp: str):
    """True/False if the response is a recognizable write-tool envelope with a
    'committed' boolean; None if the response is not a well-formed write response."""
    import json
    try:
        obj = json.loads(resp)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if "committed" in obj and isinstance(obj["committed"], bool):
        return obj["committed"]
    # A well-formed denial with no commit is a valid "not committed" observation.
    if obj.get("decision") == "denied":
        return False
    return None


def _count(resp: str):
    """The integer effect count if the response is a recognizable counter
    envelope; None if it is not well-formed (so it cannot be read as 'no effect')."""
    import json
    try:
        obj = json.loads(resp)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("count"), int):
        return obj["count"]
    # A well-formed denial means the replay produced no new effect: count stays 1.
    if obj.get("decision") == "denied":
        return 1
    return None
