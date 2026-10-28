"""
Spin a fixture server up in a subprocess for a given mode, wait until it
answers, and tear it down. Used by the runner and the meta tests.

Each fixture gets its own oracle ledger file in a temp dir. The evaluator never
receives that path; only the meta tests read it.
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import time
import urllib.request


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def fixture(mode: str, oracle_path: str | None = None):
    port = _free_port()
    env = dict(os.environ, FIXTURE_MODE=mode)
    if oracle_path:
        env["FIXTURE_ORACLE"] = oracle_path
    here = os.path.dirname(__file__)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(here, "fixture.py"), str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_ready(base, proc)
        yield base
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)


def _wait_ready(base: str, proc, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("fixture exited before becoming ready")
        try:
            req = urllib.request.Request(
                base + "/tool", data=b'{"tool":"__ping__"}',
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=1).read()
            return
        except urllib.error.HTTPError:
            # Any HTTP status (e.g. 404 for the ping tool) means the server is up.
            return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError("fixture did not become ready in time")
