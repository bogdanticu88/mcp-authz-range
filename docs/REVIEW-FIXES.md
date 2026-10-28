# Review fixes (2026-10-28)

External review flagged several ways PASS could be earned falsely. All fixed,
each with a regression test in `harness/regression_test.py` or `harness/cli_test.py`.

## High

1. **Empty evidence could PASS.** The verdict engine treated "nothing in the
   evidence list" as "no forbidden effect". Now PASS requires a genuine clean
   observation that belongs to this run/attempt with a matched correlator; empty
   or all-foreign evidence is ERROR (measurement gap).
   Test: `test_empty_evidence_is_error_not_pass`.

2. **Foreign-run evidence with correlator_matched=True was ignored into a PASS.**
   Contamination was keyed only on an unmatched correlator, so leak evidence
   carrying another run_id slipped through. Now any evidence claiming a forbidden
   effect that is not a clean own observation (this run_id AND attempt_id AND a
   matched correlator) is contamination -> ERROR.
   Tests: `test_foreign_run_leak_with_matched_correlator_is_error`,
   `test_foreign_attempt_clean_evidence_does_not_pass`.

3. **T2/T3 passed malformed probe responses.** They substring-matched the raw
   response text. Now both parse JSON and require a recognizable tool-response
   envelope; an unparseable probe response is reach=UNKNOWN -> ERROR, never a
   clean pass. T2 no longer trusts a "committed" substring in prose.
   Tests: `test_t2_malformed_probe_is_not_pass`, `test_t3_malformed_probe_is_not_pass`,
   `test_t2_committed_substring_trick_does_not_leak_through`.

4. **The HTTP adapters discarded error bodies.** Every HTTPError became a
   synthetic denial, which could erase leaked bytes and treat a 500 as a reached
   boundary. Now a 4xx returns its real body (so a leak inside a deny is caught),
   and a 5xx is surfaced as an early failure, not a reached boundary.
   Test: `test_t1_leak_in_deny_body_is_fail`. Applies to `harness/http_adapter.py`
   and the MCPHub case `adapter.py`.

## Medium

5. **CLI was not wired up.** Added `range list` (reads each case.yaml), case-name
   validation on `range run` (unknown case is rejected, not silently mock-run),
   and `--adapter` now defaults to the case's own adapter.py.
   Tests: `harness/cli_test.py`.

6. **The live reproduction was separate from the harness.** `repro.py` used a
   static canary and printed booleans. It now mints a per-run canary (shared with
   the target via REPRO_CANARY) and feeds the observation through the harness
   verdict engine, printing a VERDICT line. Re-verified live: v1.0.29 -> FAIL,
   v1.0.30 -> PASS.

## Still open (not regressions, known limits)

- T2's write observation still reads the tool response, not an independent
  write-journal, in the generic path. The fixture has an oracle ledger; a real
  case should add an independent effect observer where possible.
- The MCPHub victim server is admin-owned (SSRF-guard reason). A non-admin-owned
  victim is the pre-publication refinement.
