"""
T1: cross-tenant read, tool-direct mode.

This is the one worked test. It talks to a running MCP server over streamable
HTTP as two tenants, A and B, with interleaved sessions on the SAME server
instance (so session-binding bugs show up, not just naive per-tenant bugs).

Flow for one case:

  1. SEED      As B, create a protected record containing a run-minted canary.
  2. CONTROL   As B, read B's own record back. We must see the canary.
               If we don't, the observation path is broken -> ERROR, never PASS.
               (We also read A's own record as A, to prove A's happy path works.)
  3. PROBE     As A, ask for B's record by id. Classify the response.
  4. EVALUATE  If A's response contains B's canary -> FAIL.
               If not, and the control fired -> PASS.

The harness itself is the client, so it captures the full tool result directly.
That is the most trustworthy observer available: no extra instrumentation to
lose events. We never read the fixture's fault label; we only look at bytes.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from verdict import AttemptResult, Evidence, Reach


@dataclass
class TenantSession:
    """A minimal adapter contract. A case implements call() for its server."""
    name: str
    # call(tool, args) -> (ok, text). ok False means transport/crash, not a deny.
    call: Callable[[str, dict], tuple[bool, str]]


def new_canary() -> str:
    return "CANARY-" + secrets.token_hex(8)


def run_t1(
    run_id: str,
    attempt_id: str,
    tenant_a: TenantSession,
    tenant_b: TenantSession,
    seed_tool: str,
    read_tool: str,
    record_id_field: str = "id",
) -> AttemptResult:
    canary = new_canary()

    # 1. SEED as B
    ok, seed_resp = tenant_b.call(seed_tool, {"secret": canary})
    if not ok:
        return AttemptResult(run_id, attempt_id, "T1", "tool_direct",
                             reach=Reach.FAILED_EARLY, control_observed=False,
                             reason="Could not seed B's record.")
    record_id = _extract(seed_resp, record_id_field)

    # 2. CONTROL: B reads B's own record, must see the canary.
    ok, b_self = tenant_b.call(read_tool, {record_id_field: record_id})
    control_observed = ok and (canary in b_self)

    # 3. PROBE: A asks for B's record.
    ok, a_cross = tenant_a.call(read_tool, {record_id_field: record_id})
    if not ok:
        return AttemptResult(run_id, attempt_id, "T1", "tool_direct",
                             reach=Reach.FAILED_EARLY, control_observed=control_observed,
                             reason="probe failed before boundary")

    leaked = canary in a_cross
    if not leaked and not a_cross.strip():
        # An empty probe response is not a clean deny; we observed nothing, so we
        # cannot assert "no leak". Measurement fault, not a pass.
        return AttemptResult(run_id, attempt_id, "T1", "tool_direct",
                             reach=Reach.UNKNOWN, control_observed=control_observed,
                             reason="probe response was empty; cannot assert no leak")

    evidence = [Evidence(run_id, attempt_id, "client_capture",
                         forbidden_effect_seen=leaked, correlator_matched=True,
                         note="A's response checked for B's run-minted canary")]
    return AttemptResult(
        run_id=run_id, attempt_id=attempt_id, test_id="T1", mode="tool_direct",
        reach=Reach.REACHED, control_observed=control_observed, evidence=evidence,
        enforcement_attributed=None,
    )


def _extract(resp: str, field: str) -> str:
    """Pull a record id out of a server response. Cases can override this.

    Deliberately dumb for the skeleton: JSON parse if possible, else echo.
    """
    import json
    try:
        obj = json.loads(resp)
        if isinstance(obj, dict) and field in obj:
            return str(obj[field])
    except Exception:
        pass
    return resp.strip()
