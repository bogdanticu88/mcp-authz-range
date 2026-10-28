"""
Bring-your-own-server adapter template (T1: cross-tenant read).

Copy this file, fill in the four TODOs for YOUR MCP server, and run:

    range run my-server --adapter ./byos_adapter.py --version vulnerable

The harness will, through the sessions you define here:
  1. SEED   a protected record as tenant B, carrying a run-minted canary.
  2. CONTROL read it back as B and confirm the canary is visible
            (proves your read path and the observer actually work).
  3. PROBE  try to read B's record as tenant A, who must NOT be allowed.

Verdict (decided from observed effect, not from what your server says):
  FAIL         tenant A received B's canary -> cross-tenant read is possible.
  PASS         A was denied, and the control confirmed the observation path.
  ERROR        the control did not fire, or a response was unreadable: your
               setup or this adapter needs fixing before the result can be
               trusted. ERROR is never a quiet pass.

What you must provide: two sessions, each able to call two logical tools,
"seed" and "read", as a specific, really-authenticated tenant. Authority must
come from the session's real credentials, NOT from any argument the model
could set. A and B must be genuinely different principals on your server.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# TODO 1: how your server is reached, and how each tenant authenticates.
# Replace these with your real base URL and two real tenant credentials.
BASE_URL = "http://127.0.0.1:PORT"
TENANT_A = {"name": "alice", "token": "REPLACE_WITH_A_REAL_TOKEN_FOR_A"}
TENANT_B = {"name": "bob", "token": "REPLACE_WITH_A_REAL_TOKEN_FOR_B"}

# A sentinel so an unfilled template fails loudly instead of giving a fake PASS.
_UNFILLED = "REPLACE_WITH_A_REAL_TOKEN"


def _http(method: str, path: str, token: str, body: dict | None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL.rstrip("/") + path, data=data, method=method,
        headers={
            "Content-Type": "application/json",
            # TODO 2: set YOUR server's auth header. Example uses a bearer token.
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return True, r.read().decode()
    except urllib.error.HTTPError as e:
        # Return the REAL body on a 4xx (a deny can still leak bytes; the harness
        # scans it). Treat 5xx as an early failure, not a reached boundary.
        body_txt = ""
        try:
            body_txt = e.read().decode()
        except Exception:
            pass
        if 400 <= e.code < 500:
            return True, body_txt or json.dumps({"status": e.code})
        return False, f"http {e.code}: {body_txt}"
    except Exception as exc:
        return False, f"transport error: {exc}"


def _make_session(tenant: dict):
    # Imported lazily so the template can be read without the harness on PATH.
    from t1_cross_tenant import TenantSession

    def call(tool: str, args: dict):
        token = tenant["token"]
        if tool == "seed":
            # TODO 3: create a protected record OWNED BY TENANT B that carries
            # args["secret"] (the run-minted canary), and return a response the
            # read step can locate. Adjust path/shape to your server.
            return _http("POST", "/api/records", token,
                         {"content": args["secret"]})
        if tool == "read":
            # TODO 4: read the SAME record by the identity your server uses.
            # The record id travels in args[...] from what "seed" returned; map
            # it to your server's read route. Authority is the token alone.
            rid = args.get("id", "")
            return _http("GET", f"/api/records/{rid}", token, None)
        return False, f"unknown tool {tool}"

    return TenantSession(name=tenant["name"], call=call)


def sessions():
    if any(_UNFILLED in t for t in (TENANT_A["token"], TENANT_B["token"])):
        raise NotImplementedError(
            "byos_adapter.py is still a template. Fill in BASE_URL, the two "
            "tenant tokens, and the seed/read routes (TODOs 1-4) for your server."
        )
    # A is the attacker session, B owns the record and is the positive control.
    return _make_session(TENANT_A), _make_session(TENANT_B)
