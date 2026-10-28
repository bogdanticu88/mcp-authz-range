# Adding a case

A case is one real, published, fixed MCP authorization bug, runnable offline.

## Checklist

- [ ] The bug is **public and already fixed**. No zero-days here.
- [ ] You can run the vulnerable and fixed versions **locally, no account**.
- [ ] You pin both versions by exact tag or digest, pulled from **upstream**
      (don't copy their code into this repo; check their license).
- [ ] The test maps to one contract: `T1` cross-tenant read, `T2` write without
      approval, or `T3` consumed-approval replay.
- [ ] There is a **positive control** that differs from the probe only in
      authority, so a broken observer shows up as `ERROR`, not a false `PASS`.
- [ ] You state the expected verdict both ways: `vulnerable: FAIL`, `fixed: PASS`.
- [ ] You list the **limits**: what this case does not cover.

## Folder shape

```
cases/<slug>-CVE-XXXX-YYYYY/
  case.yaml            # metadata, versions, expected verdicts, limits
  docker-compose.yml   # brings up the pinned server(s), offline
  adapter.py           # maps the two tenant sessions onto this server's API
  README.md            # one-paragraph plain-English description + the advisory link
```

## What makes a good case

The best cases are **tool-layer confused deputies**: the server holds a broad
credential and trusts a caller-supplied id or tenant. Those are the ones a
backend authorization test misses, which is the whole point of this range.
