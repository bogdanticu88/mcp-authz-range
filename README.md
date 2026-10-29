# MCP Authorization Range

**Your authorization tests pass. The agent's path doesn't.**

![demo: same command, one word different, FAIL on the vulnerable version, PASS on the patched one](docs/demo.gif)

A range of real, published MCP authorization CVEs you can reproduce on your
laptop. Each one is pinned at its vulnerable and its fixed version; the same
probe runs against both and the harness prints `FAIL` on the vulnerable build
and `PASS` on the patched one, judged by what actually happened, not by what the
server claimed.

Two cases today, covering two different bug classes:

- **Cross-tenant read** (CVE-2026-79750): a non-admin invokes a tool on a server
  owned by someone else and reads their data.
- **Privilege escalation** (CVE-2026-79744): a non-admin changes global system
  config through an endpoint with no authorization check.

Both are in MCPHub, both reproduced end to end. No account, no signup, no
telemetry. It runs offline at run time; only the first build downloads the
target software and its dependencies.

## Try it in 30 seconds

Pure standard library, nothing to install. From a fresh clone, with Python
3.10+:

```
make demo
```

That runs the cross-tenant case in-process (no Docker, no network) and prints:

```
T1 cross-tenant read   FAIL   Forbidden effect observed via client_capture.
T1 cross-tenant read   PASS   Probe reached the boundary, control confirmed ...
```

Same probe, one word different (`--version vulnerable` vs `--version fixed`),
red then green. `make test` runs the full suite (42 tests).

## Why this exists

Most teams test authorization at the backend. The bugs keep showing up one layer
out, in the MCP tool server: it holds a broad credential and takes the tenant or
resource as an argument the caller controls. And an agent that politely refuses
the malicious prompt tells you nothing about whether the path underneath is
actually safe.

This is not hypothetical. The same class shows up across the ecosystem, in
HashiCorp's terraform-mcp-server (CVE-2026-16498, CVSS 10), n8n-mcp
(CVE-2026-54052), the 2025 Asana MCP cross-org exposure, and the two MCPHub
cases reproduced here.

## How it decides

The verdict comes from an observed effect (a leaked canary, a config change that
landed), never from the server's own allow/deny response. Every negative probe
is paired with a **positive control** that differs only in authority: for the
cross-tenant read, the owner reads their own record first and the harness must
see the canary. If that control does not fire, the result is `ERROR`, because a
"nothing leaked" reading from an observer you never proved was working is worth
nothing.

- **FAIL** — correlated evidence shows the forbidden effect happened. A detection.
- **PASS** — the probe reached the boundary, the control confirmed the
  observation path, and no forbidden effect was seen. A bounded claim about the
  path, inputs and identities tested, not a proof the server is secure.
- **ERROR** — the measurement could not be trusted (control did not fire, or
  evidence was contaminated). Fix the setup. Not a pass, and not a detection.
- **INCONCLUSIVE** — the boundary was never exercised (a genuine refusal, or an
  early crash). A coverage gap.

Report `FAIL`s and `ERROR`s separately: only a `FAIL` is a found vulnerability.

## What has actually been verified

- Both cases are reproduced end to end: built from pinned source commits, the
  control fires, and the probe gives `FAIL` on the vulnerable build and `PASS`
  on the fixed one. See each case's `VERIFIED.md`.
- The verdict engine has 42 tests, including regressions for known false-`PASS`
  paths (empty evidence, foreign-run evidence, malformed responses). That is
  "tested against selected cases", not "proven correct".
- A mutation test mutates the fixture's authorization check six ways and
  confirms no mutant that actually leaks is ever reported `PASS`. Evidence the
  detector resists those faults, not proof it cannot be fooled.

## Running it

**The mock demo** (above) needs nothing. For the two paths below:

**Reproduce a real CVE (needs Docker).** Each case ships a one-command verifier
that builds both versions, reproduces the bug, checks the verdicts, and tears
everything down:

```
make verify-mcphub           # cross-tenant read: VULN-1.0.29 FAIL, FIXED-1.0.30 PASS
make verify-mcphub-privesc   # privilege escalation: VULN-1.0.28 FAIL, FIXED-1.0.29 PASS
```

The first build is slow (it compiles the target server). Run it in an isolated
lab; it builds deliberately vulnerable software. See each case's safety notes.

**Test your own server (no Docker).** Point the same tests at an MCP server you
run. Two templates to copy and fill in: `templates/byos_adapter.py` for the
cross-tenant read, and `templates/byos_privesc_adapter.py` for privilege
escalation. See [docs/BRING-YOUR-OWN-SERVER.md](docs/BRING-YOUR-OWN-SERVER.md).

### The `range` command (optional)

`make` and `python3 harness/cli.py` work without installing anything. If you
want `range` on your PATH: `make install` (editable install). If your shell then
says `range: command not found`, pip put it in your user bin dir; add that to
PATH or use `pipx install .`.

## Contributing a case

New MCP authorization CVE? That's a pull request. See
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md): one folder per case, pinned
versions, a positive control, and the expected verdict both ways.

## Safety

This runs deliberately vulnerable software and performs actions that should be
blocked. Run it in an isolated lab, and test only servers you host yourself with
throwaway tenants and synthetic data. See [docs/DISCLOSURE.md](docs/DISCLOSURE.md).

## License

MIT. Built on Ordeal, the author's agent-authorization enforcement engine.
