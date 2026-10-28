"""
range CLI. Thin: load a case, bring up the pinned server via its adapter,
run the test, print the verdict, exit with the CI code.

For the skeleton this ships with a --mock mode so the whole pipeline runs with
no Docker and no network, which is also how the blind-evaluator test drives it.
Real cases implement adapter.py to replace the mock sessions.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from verdict import Verdict, evaluate, run_exit_code, EXIT_CRASH
from t1_cross_tenant import run_t1, TenantSession

def _find_cases_dir() -> str:
    """Locate the cases/ directory, in priority order:
      1. $RANGE_CASES_DIR if set (explicit override),
      2. ./cases under the current working directory (running from a clone),
      3. cases/ next to the harness/ package (the repo layout / editable install).
    This keeps `range` working both from a git clone and after an install,
    where the harness modules may live apart from the cases tree.
    """
    env = os.environ.get("RANGE_CASES_DIR")
    if env and os.path.isdir(env):
        return env
    cwd_cases = os.path.join(os.getcwd(), "cases")
    if os.path.isdir(cwd_cases):
        return cwd_cases
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cases")


CASES_DIR = _find_cases_dir()


def _discover_cases() -> dict[str, dict]:
    """Return {case_id: metadata} by reading each cases/<id>/case.yaml.

    Minimal line-based parse of the top-level scalar keys we care about, so the
    CLI has no third-party dependency.
    """
    out: dict[str, dict] = {}
    if not os.path.isdir(CASES_DIR):
        return out
    for name in sorted(os.listdir(CASES_DIR)):
        cdir = os.path.join(CASES_DIR, name)
        cyaml = os.path.join(cdir, "case.yaml")
        if not os.path.isfile(cyaml):
            continue
        meta = {"id": name, "dir": cdir, "has_adapter": os.path.isfile(os.path.join(cdir, "adapter.py"))}
        for line in open(cyaml):
            line = line.rstrip("\n")
            if line.startswith("  ") or not line or line.lstrip().startswith("#"):
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                # Strip an inline comment (but not a '#' inside a quoted value).
                if not v.startswith('"') and "#" in v:
                    v = v.split("#", 1)[0].strip()
                v = v.strip('"')
                if k in ("title", "test", "cve", "status", "transport"):
                    meta[k] = v
        out[name] = meta
    return out


def cmd_list(args) -> int:
    cases = _discover_cases()
    if not cases:
        print(f"No cases found under {CASES_DIR}")
        return EXIT_CRASH
    for cid, m in cases.items():
        status = m.get("status", "unverified")
        adapter = "adapter" if m["has_adapter"] else "no-adapter"
        print(f"{cid}")
        print(f"    {m.get('test','?')}  {m.get('cve','')}  [{status}, {adapter}]")
        if m.get("title"):
            print(f"    {m['title']}")
    return 0


def _mock_sessions(leak: bool):
    """A fake MCP server in-process. leak=True reproduces the vulnerable case."""
    store: dict[str, str] = {}

    def make(name: str):
        def call(tool: str, args: dict):
            if tool == "seed":
                rid = "rec-" + str(len(store) + 1)
                store[rid] = args["secret"]
                return True, json.dumps({"id": rid})
            if tool == "read":
                rid = args["id"]
                secret = store.get(rid, "")
                # Vulnerable server: hands back the record to anyone.
                # Fixed server: only the owning tenant. Here tenant B owns everything seeded.
                if leak or name == "B":
                    return True, json.dumps({"id": rid, "secret": secret})
                return True, json.dumps({"error": "not found"})
            return False, "unknown tool"
        return TenantSession(name=name, call=call)

    return make("A"), make("B")


def _load_adapter_sessions(path: str):
    """Import a case adapter.py and call its sessions() -> (a, b)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("case_adapter", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.sessions()


def cmd_run(args) -> int:
    cases = _discover_cases()
    # An explicit --adapter file is the "bring your own server" path: run it
    # against the test contract without needing a registered case.
    byo = bool(args.adapter) and os.path.isfile(args.adapter)
    if not args.mock and not byo and args.case not in cases:
        known = ", ".join(cases) or "(none)"
        print(f"Unknown case '{args.case}'. Known cases: {known}", file=sys.stderr)
        print("(use --mock for the demo, or --adapter PATH to test your own server)", file=sys.stderr)
        return EXIT_CRASH

    leak = args.version == "vulnerable"
    if args.mock:
        a, b = _mock_sessions(leak)
    else:
        # --adapter wins; otherwise fall back to the named case's own adapter.py.
        adapter_path = args.adapter or os.path.join(cases[args.case]["dir"], "adapter.py")
        if not os.path.isfile(adapter_path):
            print(f"No adapter found at {adapter_path}.", file=sys.stderr)
            return EXIT_CRASH
        a, b = _load_adapter_sessions(adapter_path)

    result = run_t1(
        run_id="run1", attempt_id="a1",
        tenant_a=a, tenant_b=b,
        seed_tool="seed", read_tool="read", record_id_field="id",
    )
    verdict, reason = evaluate(result)

    label = {"T1": "cross-tenant read"}.get(result.test_id, result.test_id)
    print(f"{result.test_id} {label:20} {verdict.value:5}  {reason}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "case": args.case, "version": args.version,
                "test": result.test_id, "mode": result.mode,
                "reach": result.reach.value,
                "control_observed": result.control_observed,
                "verdict": verdict.value, "reason": reason,
                "evidence": [vars(e) for e in result.evidence],
            }, f, indent=2)

    coverage_ok = result.reach.name == "REACHED"  # at least one real probe landed
    return run_exit_code([verdict], coverage_ok)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="range")
    sub = p.add_subparsers(dest="cmd", required=True)

    lst = sub.add_parser("list", help="list available cases")
    lst.set_defaults(func=cmd_list)

    r = sub.add_parser("run", help="run a case")
    r.add_argument("case")
    r.add_argument("--version", choices=["vulnerable", "fixed"], default="vulnerable")
    r.add_argument("--json", metavar="PATH", help="write evidence JSON")
    r.add_argument("--mock", action="store_true", help="in-process mock server (no Docker)")
    r.add_argument("--adapter", metavar="PATH", help="case adapter.py exposing sessions()")
    r.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # harness crash gets its own code, never read as FAIL
        print(f"harness crash: {exc}", file=sys.stderr)
        return EXIT_CRASH


if __name__ == "__main__":
    raise SystemExit(main())
