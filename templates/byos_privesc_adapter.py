"""
Bring-your-own-server adapter template (T4: privilege escalation).

Copy this file, fill in the TODOs for YOUR MCP server, and run:

    range run my-server --adapter ./byos_privesc_adapter.py --test T4 --version vulnerable

The harness, through the sessions you define here:
  CONTROL: an admin performs a privileged change (sets a config value) and we
           read it back. If an admin's own change cannot be observed, the
           observation path is broken -> ERROR, never a pass.
  PROBE:   a NON-admin attempts the same privileged change. We read the config
           back as admin. If the non-admin's value landed, the privileged action
           took effect without authority -> FAIL. If the admin's value still
           stands (or the non-admin was denied) -> PASS.

Verdict comes from the observed config state, not from what the write call
returned. Authority must come from each session's real credentials, not from any
argument the model could set. The two sessions must be a genuine non-admin and a
genuine admin on your server.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# TODO 1: your server, an admin, and a non-admin principal.
BASE_URL = "http://127.0.0.1:PORT"
ADMIN = {"name": "admin", "token": "REPLACE_WITH_A_REAL_ADMIN_TOKEN"}
ATTACKER = {"name": "mallory", "token": "REPLACE_WITH_A_REAL_NON_ADMIN_TOKEN"}

# TODO 2: pick ONE observable, harmless config field that only an admin should
# be able to change, and that you can read back. Everything below maps the
# harness's logical key "probe_key" onto this real field.
_UNFILLED = "REPLACE_WITH_A_REAL"


def _http(method, path, token, body):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL.rstrip("/") + path, data=data, method=method,
        headers={"Content-Type": "application/json",
                 # TODO 3: your server's auth header.
                 "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return True, r.read().decode()
    except urllib.error.HTTPError as e:
        body_txt = ""
        try:
            body_txt = e.read().decode()
        except Exception:
            pass
        # A 403 here is the fixed server correctly denying the non-admin.
        if 400 <= e.code < 500:
            return True, body_txt or json.dumps({"status": e.code})
        return False, f"http {e.code}: {body_txt}"
    except Exception as exc:
        return False, f"transport error: {exc}"


def _make_session(principal):
    from t1_cross_tenant import TenantSession

    def call(tool, args):
        token = principal["token"]
        if tool == "write_config":
            # TODO 4a: perform the privileged change. args["value"] is a unique
            # value the harness wants written to your chosen field.
            return _http("PUT", "/api/your-admin-config", token,
                         {"your_field": args["value"]})
        if tool == "read_config":
            # TODO 4b: read the config back and return it under the logical key
            # "probe_key" so the harness can observe the effect. Extract YOUR
            # field's current value and present it like this:
            ok, resp = _http("GET", "/api/your-settings", token, None)
            if not ok:
                return ok, resp
            try:
                current = json.loads(resp)["your_field"]   # map to your shape
            except Exception:
                current = None
            return True, json.dumps({"config": {"probe_key": current}})
        return False, f"unknown tool {tool}"

    return TenantSession(name=principal["name"], call=call)


def sessions():
    if any(_UNFILLED in t for t in (ADMIN["token"], ATTACKER["token"])):
        raise NotImplementedError(
            "byos_privesc_adapter.py is still a template. Fill in BASE_URL, the "
            "admin and non-admin tokens, the auth header, and the privileged "
            "write/read for your server (TODOs 1-4)."
        )
    # The harness runs T4 as run_t4(attacker=<first>, admin=<second>).
    return _make_session(ATTACKER), _make_session(ADMIN)
