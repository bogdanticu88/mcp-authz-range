"""
Mutation testing: can the detector be fooled?

Hand-written faults only cover the failures we thought of. Mutation testing
attacks the authorization check itself: it generates variants of the tenant
decision ("mutants"), and for each one asks two independent questions:

  1. Does this mutant ACTUALLY leak? (answered by the oracle ledger, which the
     evaluator never sees.)
  2. What verdict does the harness return?

The contract: every mutant that actually leaks must be caught (FAIL or ERROR),
never PASS. A leaking mutant that slips through as PASS is a hole in the detector.

We inject mutants by running the fixture with a MUTANT env var that the fixture
reads only for this purpose. In a real case the equivalent is mutating the
target's own authz function; here we mutate a self-contained stand-in so the
whole thing runs offline in under a second.
"""

from __future__ import annotations

import json
import os
import tempfile

from fixture_control import fixture
from http_adapter import http_session
from t1_cross_tenant import run_t1
from verdict import Verdict, evaluate


# Each mutant is a rule for who is allowed to read a record, expressed as a
# predicate name the fixture understands. "correct" = owner-only.
MUTANTS = [
    "correct",          # tenant == owner           (should NOT leak)
    "always_true",      # everyone allowed          (leaks)
    "always_false",     # nobody allowed            (no leak, but breaks control)
    "not_owner",        # inverted check            (leaks: A reads B)
    "prefix_match",     # owner.startswith(tenant)  (leaks for some ids)
    "ignore_owner",     # drop the owner comparison (leaks)
]


def _run_mutant(mutant: str):
    with tempfile.TemporaryDirectory() as d:
        oracle = os.path.join(d, "o.jsonl")
        env_mode = f"mutant:{mutant}"
        with fixture(env_mode, oracle_path=oracle) as base:
            a = http_session("A", base)
            b = http_session("B", base)
            result = run_t1("run1", "a1", a, b, seed_tool="seed", read_tool="read")
            verdict, _ = evaluate(result)
        events = [json.loads(l) for l in open(oracle)] if os.path.exists(oracle) else []
        leaked = any(e.get("effect") == "disclose" and e["owner"] != e["to"]
                     for e in events)
        return verdict, leaked


def test_no_leaking_mutant_passes():
    escapes = []
    for m in MUTANTS:
        verdict, leaked = _run_mutant(m)
        if leaked and verdict == Verdict.PASS:
            escapes.append(m)
    assert not escapes, f"leaking mutants slipped through as PASS: {escapes}"


def test_at_least_one_mutant_actually_leaks():
    # Sanity: the mutation set must contain real leaks, or the test above is vacuous.
    assert any(_run_mutant(m)[1] for m in MUTANTS), "no mutant leaked; test is vacuous"


def test_correct_mutant_passes_and_does_not_leak():
    verdict, leaked = _run_mutant("correct")
    assert not leaked
    assert verdict == Verdict.PASS
