# Test your own MCP server

The cases in this repo reproduce known CVEs. This guide is the other direction:
point the same authorization test at a server you run, and get a verdict about
whether one tenant can read another tenant's data through it.

It tests one thing well (T1, cross-tenant read). That is deliberate: a narrow
test with a trustworthy verdict beats a broad one you can't rely on.

## What you need

- Your MCP server reachable over HTTP.
- Two genuinely different tenants/users on it, A and B, each with real
  credentials. Authority must come from those credentials, not from any
  argument the model can set.
- A tool that stores a record owned by a tenant, and a tool that reads it back.

## Steps

1. Copy the template:

   ```
   cp templates/byos_adapter.py ./my_adapter.py
   ```

2. Fill in the four TODOs in `my_adapter.py`:
   - BASE_URL and the two tenant tokens.
   - the auth header your server expects.
   - how tenant B seeds a record carrying the canary, and what the response
     returns so the read step can find it.
   - how a tenant reads that record back.

   The record id returned by your seed step is handed to the read step as
   `args["id"]`. If your server names it differently, map it inside the adapter.

3. Run it:

   ```
   range run my-server --adapter ./my_adapter.py --version vulnerable
   range run my-server --adapter ./my_adapter.py --json result.json
   ```

## Reading the result

- `FAIL`  tenant A received tenant B's canary. Cross-tenant read is possible.
- `PASS`  A was denied, and the control (B reading its own record) fired, so the
          observation path is proven, not assumed.
- `ERROR` the control did not fire, or a response was unreadable. Fix the setup
          or the adapter; this is never a quiet pass.
- `INCONCLUSIVE` the probe never reached the boundary (e.g. it errored out
          before any authorization decision).

A `PASS` is a bounded statement about the path, tenants, and record you tested.
It is not a proof that your server is secure everywhere. The report says so.

## Safety

Test only a server you are authorized to test, with throwaway tenants and
synthetic data. Do not point this at production or at real customer accounts.
See DISCLOSURE.md.
