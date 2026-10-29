# Launch posts (ready to paste)

Repo: https://github.com/bogdanticu88/mcp-authz-range
One-liner: Your authorization tests pass. Here are real MCP CVEs they didn't
catch, and the one command that does.

Record first: the side-by-side GIF (vulnerable FAIL / fixed PASS) for the README
and the posts. See docs/LAUNCH.md for the shot.

---

## Show HN

Title: Show HN: A range of real MCP authorization CVEs you can break on your laptop

Body:

Every few weeks another MCP server ships an authorization bug. Cross-tenant
reads, a non-admin changing global config, a tool server that trusts an id the
caller controls. Your backend authorization tests miss these, because the bug
lives one layer out in the MCP tool server, and an agent that politely refuses
the prompt tells you nothing about whether the path underneath is actually safe.

So I built a local range of these. Each case is a real, published CVE pinned at
its vulnerable and its fixed version. One command builds both and shows FAIL on
the vulnerable one, PASS on the patch. It judges by what actually happened, a
leaked canary, a config change that landed, not by what the server said. If it
can't trust the observation (the positive control didn't fire), it says ERROR
instead of a green check that means nothing.

Two cases so far, two different bug classes: a cross-tenant read (CVE-2026-79750)
and a privilege escalation (CVE-2026-79744), both in MCPHub, both reproduced end
to end. There's also a template to point the same test at your own server.

Offline, no account, MIT. New MCP authorization CVE? That's a pull request.

[repo link] [GIF]

---

## r/netsec

Title: mcp-authz-range: reproduce real MCP authorization CVEs locally, with
evidence-based pass/fail

Body:

A local range of real MCP authorization CVEs, each pinned vulnerable-vs-fixed and
reproduced end to end. Two cases so far in MCPHub: a horizontal IDOR on the tool
execution route (CVE-2026-79750) and a missing-authorization privilege escalation
on the system-config endpoint (CVE-2026-79744).

The point is the verdict model, not the bug list. It decides FAIL/PASS from an
observed effect (a run-minted canary that crossed a tenant boundary, a config
change that actually landed), never from the server's own allow/deny response.
Every negative probe is paired with a positive control that differs only in
authority; if the control doesn't fire, the result is ERROR, not a false PASS.
There's mutation testing over the fixture's auth check to keep the detector
honest.

Runs offline, no account, MIT. Bring-your-own-server adapter included.

[repo link]

---

## LinkedIn

Authorization testing usually stops at the backend. With AI agents, the agent's
path doesn't.

The bug keeps showing up one layer out, in the MCP tool server: it holds a broad
credential and trusts a tenant or resource id the model controls. MCPHub,
n8n-mcp, HashiCorp's terraform-mcp-server at CVSS 10, same shape over and over.
And testing the model doesn't help, because a model that refuses the prompt
tells you nothing about whether enforcement underneath would have stopped it.

So I built a small open-source range: real MCP authorization CVEs, each pinned at
its vulnerable and fixed version, each reproduced with one command. It reports
pass or fail from what actually happened, a leaked record, a config change that
landed, and refuses to show a green check when it couldn't trust the measurement.

Two cases today, two different bug classes, more welcome as pull requests. It's
the practical companion to the agent-authorization chapters I've been writing.

Repo in the comments. If you maintain an MCP server, there's a template to point
it at yours.
