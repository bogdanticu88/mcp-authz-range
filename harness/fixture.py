"""
A real HTTP fixture server, zero dependencies (stdlib only).

This stands in for an MCP tool server. It speaks a tiny JSON-over-HTTP tool
protocol: POST /tool with {"tool": ..., "args": ..., "tenant": ...}. It exists
so the harness can be exercised over the wire against servers whose behaviour we
control, including deliberately broken ones.

Two things make it trustworthy as a test target:

  1. MODES. It can be configured to behave correctly or to fail in a specific,
     named way. The mode is set by env var FIXTURE_MODE. The harness never reads
     that env var; it only sees bytes on the wire.

  2. ORACLE LEDGER. Every protected effect the server actually performs, and
     every protected byte it actually returns, is appended to a ledger file
     (env FIXTURE_ORACLE). The evaluator cannot read this file. It is used only
     by the mutation/meta tests to confirm a fault really fired, so a fault that
     silently failed to trigger is not mistaken for a clean PASS.

Modes:
  protected      correct: a tenant only reads its own records.
  vulnerable     T1 bug: any tenant reads any record (confused deputy).
  leak_then_deny T1 bug: returns the record but also stamps "decision":"denied".
  drop_event     correct enforcement, but omits the decision field entirely.
  write_vuln     T2 bug: commits a write with no valid approval.
  replay_vuln    T3 bug: a consumed approval can be used again.

Run standalone:  FIXTURE_MODE=vulnerable python fixture.py 8099
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class State:
    def __init__(self, mode: str, oracle_path: str | None):
        self.mode = mode
        self.oracle_path = oracle_path
        self.records: dict[str, dict] = {}   # id -> {owner, secret}
        self.counter = 0
        self.effects: dict[str, int] = {}     # approval_id -> times applied
        self.consumed: set[str] = set()        # approvals already used once
        self.lock = threading.Lock()

    def oracle(self, event: dict):
        if not self.oracle_path:
            return
        with open(self.oracle_path, "a") as f:
            f.write(json.dumps(event) + "\n")


def _mutant_decision(name: str, tenant: str, owner: str) -> bool:
    """The authorization check, and its mutants. Used by mutation testing to
    confirm the detector catches every variant that actually leaks."""
    if name == "correct":
        return tenant == owner
    if name == "always_true":
        return True
    if name == "always_false":
        return False
    if name == "not_owner":
        return tenant != owner
    if name == "prefix_match":
        return owner.startswith(tenant) or tenant.startswith(owner)
    if name == "ignore_owner":
        return True  # comparison dropped entirely
    return tenant == owner  # unknown mutant -> correct


class Handler(BaseHTTPRequestHandler):
    state: State = None  # set by make_server

    def log_message(self, *a):  # keep the test output clean
        pass

    def _send(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad json"})

        tool = req.get("tool")
        args = req.get("args", {})
        tenant = req.get("tenant")
        st = self.state

        if tool == "seed":
            with st.lock:
                st.counter += 1
                rid = f"rec-{st.counter}"
                st.records[rid] = {"owner": tenant, "secret": args.get("secret", "")}
            return self._send(200, {"id": rid})

        if tool == "read":
            rid = args.get("id")
            rec = st.records.get(rid)
            if not rec:
                return self._send(200, {"error": "not found"})
            owner = rec["owner"]
            allowed = (tenant == owner)

            if st.mode in ("vulnerable", "leak_then_deny"):
                allowed = True  # the bug: ownership not enforced on read
            elif st.mode.startswith("mutant:"):
                allowed = _mutant_decision(st.mode.split(":", 1)[1], tenant, owner)

            if not allowed:
                return self._send(200, {"decision": "denied"})

            # Returning the secret is a protected effect; record it in the oracle
            # keyed by WHO actually received it, so a cross-tenant read is visible.
            st.oracle({"effect": "disclose", "record": rid,
                       "owner": owner, "to": tenant, "secret": rec["secret"]})
            body = {"id": rid, "secret": rec["secret"]}
            if st.mode == "leak_then_deny":
                body["decision"] = "denied"   # lies about enforcing
            elif st.mode != "drop_event":
                body["decision"] = "allowed"
            # drop_event: correct data, but no decision field at all
            return self._send(200, body)

        if tool == "write":
            approval = args.get("approval")
            valid = bool(approval) and approval.startswith("appr-") and st.mode != "write_vuln"
            # write_vuln commits regardless; correct mode requires a valid approval
            if valid or st.mode == "write_vuln":
                with st.lock:
                    st.counter += 1
                    wid = f"write-{st.counter}"
                st.oracle({"effect": "write", "id": wid, "approval": approval,
                           "valid_approval": valid})
                return self._send(200, {"id": wid, "committed": True})
            return self._send(200, {"decision": "denied", "committed": False})

        if tool == "apply_approval":
            approval = args.get("approval")
            with st.lock:
                replay = approval in st.consumed
                if replay and st.mode != "replay_vuln":
                    return self._send(200, {"decision": "denied", "applied": False})
                st.consumed.add(approval)
                st.effects[approval] = st.effects.get(approval, 0) + 1
                count = st.effects[approval]
            st.oracle({"effect": "apply", "approval": approval,
                       "count": count, "replay": replay})
            return self._send(200, {"applied": True, "count": count})

        return self._send(404, {"error": "unknown tool"})


def make_server(port: int, mode: str, oracle_path: str | None) -> ThreadingHTTPServer:
    handler = type("H", (Handler,), {"state": State(mode, oracle_path)})
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    mode = os.environ.get("FIXTURE_MODE", "protected")
    oracle = os.environ.get("FIXTURE_ORACLE")
    srv = make_server(port, mode, oracle)
    print(f"fixture up on :{port} mode={mode}", flush=True)
    srv.serve_forever()
