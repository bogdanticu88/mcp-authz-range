"""
Real HTTP tenant session, zero dependencies.

A TenantSession whose call() goes over the wire to a server speaking the tiny
JSON tool protocol (POST /tool). The MCPHub-style real adapter will be a thin
variant of this that maps onto that server's actual tool-execution endpoint.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from t1_cross_tenant import TenantSession


def http_session(name: str, base_url: str) -> TenantSession:
    def call(tool: str, args: dict) -> tuple[bool, str]:
        payload = json.dumps({"tool": tool, "args": args, "tenant": name}).encode()
        req = urllib.request.Request(
            base_url.rstrip("/") + "/tool", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return True, r.read().decode()
        except urllib.error.HTTPError as e:
            # Read the REAL body, never a synthetic denial: a 4xx can still carry
            # leaked bytes (leak-then-deny), and the classifier must see them.
            body = ""
            try:
                body = e.read().decode()
            except Exception:
                pass
            if 400 <= e.code < 500:
                # A classifiable response at the boundary (e.g. a 403 deny). Return
                # the body so the test can scan it for the canary before trusting it.
                return True, body or json.dumps({"status": e.code})
            # 5xx (or anything else) is a server failure, not an enforcement
            # decision: surface it as an early failure, keeping the body for logs.
            return False, f"http {e.code}: {body}"
        except Exception as exc:
            # Transport/crash, not a deny. Reach -> FAILED_EARLY downstream.
            return False, f"transport error: {exc}"
    return TenantSession(name=name, call=call)
