"""
T4: privileged action without authority (function-level authorization / BFLA).

Forbidden effect: a non-admin's privileged change takes effect on a config that
only an admin should be able to change (CVE-2026-79744 shape).

  CONTROL: an admin writes a unique value and we read it back. If we can't
           observe an admin's own change, the observation path is broken ->
           ERROR, never a pass.
  PROBE:   the non-admin writes a different unique value. We then read the
           config back authoritatively (as admin). If the non-admin's value is
           present, the privileged change took effect -> FAIL. If the config
           still holds the admin's value (or the non-admin was denied) -> PASS.

Verdict comes from the observed config state, not from what the server returned
to the write call.
"""

from __future__ import annotations

import json
import secrets

from t1_cross_tenant import TenantSession
from verdict import AttemptResult, Evidence, Reach


def _read_value(session: TenantSession, read_tool: str, key: str):
    ok, resp = session.call(read_tool, {})
    if not ok:
        return ok, None
    try:
        cfg = json.loads(resp).get("config", {})
    except Exception:
        return ok, None
    return ok, cfg.get(key)


def run_t4(run_id: str, attacker: TenantSession, admin: TenantSession,
           write_tool: str = "write_config", read_tool: str = "read_config",
           key: str = "probe_key") -> AttemptResult:
    ctrl_val = "CTRL-" + secrets.token_hex(6)
    probe_val = "PROBE-" + secrets.token_hex(6)

    # CONTROL: admin writes, then we read it back authoritatively (as admin).
    ok, _ = admin.call(write_tool, {"key": key, "value": ctrl_val})
    ok2, seen = _read_value(admin, read_tool, key)
    control_observed = ok and ok2 and seen == ctrl_val

    # PROBE: the non-admin attempts the same privileged change.
    ok, _ = attacker.call(write_tool, {"key": key, "value": probe_val})
    if not ok:
        return AttemptResult(run_id, "a1", "T4", "tool_direct",
                             reach=Reach.FAILED_EARLY, control_observed=control_observed,
                             reason="privileged write probe failed before boundary")

    # Observe ground truth: read the config back as admin.
    ok3, after = _read_value(admin, read_tool, key)
    if not ok3 or after is None:
        return AttemptResult(run_id, "a1", "T4", "tool_direct",
                             reach=Reach.UNKNOWN, control_observed=control_observed,
                             reason="could not read config back to observe the effect")

    took_effect = (after == probe_val)
    evidence = [Evidence(run_id, "a1", "config_read",
                         forbidden_effect_seen=took_effect, correlator_matched=True,
                         note=f"config[{key}] after non-admin write = {after!r}")]
    return AttemptResult(run_id, "a1", "T4", "tool_direct",
                         reach=Reach.REACHED, control_observed=control_observed,
                         evidence=evidence)
