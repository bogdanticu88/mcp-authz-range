"""
T2 (write without valid approval) and T3 (consumed-approval replay).

Both decide from an INDEPENDENT read of the effect state, never from the write
call's own success/denied field. A server can commit a write and still report
"denied"; only observing the committed state catches that.

T2 forbidden effect: a protected write commits with no valid approval.
  CONTROL: a valid-approval write; the observed committed-count must go up.
  PROBE:   a no-approval write; if the observed committed-count goes up, a write
           committed without authority -> FAIL, whatever the response said.

T3 forbidden effect: replaying a consumed approval produces a second effect.
  CONTROL: first legitimate use; the observed apply-count must reach 1.
  PROBE:   replay the same approval; if the observed apply-count reaches 2 -> FAIL.
"""

from __future__ import annotations

import json
import secrets

from t1_cross_tenant import TenantSession
from verdict import AttemptResult, Evidence, Reach


def _count(resp_ok: bool, resp: str):
    """Parse {"count": N} from an independent read. None if unreadable."""
    if not resp_ok:
        return None
    try:
        obj = json.loads(resp)
    except Exception:
        return None
    return obj.get("count") if isinstance(obj.get("count"), int) else None


def run_t2(run_id: str, attempt_id: str, tenant: TenantSession,
           write_tool: str = "write", count_tool: str = "count_writes") -> AttemptResult:
    def committed_count():
        ok, resp = tenant.call(count_tool, {})
        return _count(ok, resp)

    base = committed_count()

    # CONTROL: a valid approval must commit, observed as the count going up.
    valid = "appr-" + secrets.token_hex(6)
    tenant.call(write_tool, {"approval": valid})
    after_ctrl = committed_count()
    control_observed = (base is not None and after_ctrl is not None
                        and after_ctrl == base + 1)

    # PROBE: no approval. Decide from the observed committed-count, not the
    # write response (which may lie about denying).
    tenant.call(write_tool, {"approval": None})
    after_probe = committed_count()
    if after_ctrl is None or after_probe is None:
        return AttemptResult(run_id, attempt_id, "T2", "tool_direct",
                             reach=Reach.UNKNOWN, control_observed=control_observed,
                             reason="could not read committed-write count to observe the effect")
    committed = (after_probe > after_ctrl)
    evidence = [Evidence(run_id, attempt_id, "write_count",
                         forbidden_effect_seen=committed, correlator_matched=True,
                         note=f"committed writes: base={base} ctrl={after_ctrl} probe={after_probe}")]
    return AttemptResult(run_id, attempt_id, "T2", "tool_direct",
                         reach=Reach.REACHED, control_observed=control_observed,
                         evidence=evidence)


def run_t3(run_id: str, tenant: TenantSession,
           apply_tool: str = "apply_approval", count_tool: str = "read_apply_count") -> AttemptResult:
    approval = "appr-" + secrets.token_hex(6)

    def apply_count():
        ok, resp = tenant.call(count_tool, {"approval": approval})
        return _count(ok, resp)

    # CONTROL + first use: the approval applies once; observed count must reach 1.
    tenant.call(apply_tool, {"approval": approval})
    after_first = apply_count()
    control_observed = (after_first == 1)

    # PROBE (distinct attempt id): replay. Decide from the observed apply-count.
    replay_attempt = "a1-replay"
    tenant.call(apply_tool, {"approval": approval})
    after_replay = apply_count()
    if after_first is None or after_replay is None:
        return AttemptResult(run_id, replay_attempt, "T3", "tool_direct",
                             reach=Reach.UNKNOWN, control_observed=control_observed,
                             reason="could not read apply count to observe the effect")
    second_effect = (after_replay >= 2)
    evidence = [Evidence(run_id, replay_attempt, "apply_count",
                         forbidden_effect_seen=second_effect, correlator_matched=True,
                         note=f"apply count: first={after_first} replay={after_replay}")]
    return AttemptResult(run_id, replay_attempt, "T3", "tool_direct",
                         reach=Reach.REACHED, control_observed=control_observed,
                         evidence=evidence)
