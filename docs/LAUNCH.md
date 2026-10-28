# Launch package (draft)

## The one line

> Your authorization tests pass. Here are real MCP CVEs they didn't catch, and
> the one command that does.

## The 30-second demo (record this)

Two terminal panes, side by side, same command, one word different:

```
range run mcphub-idor-CVE-2026-79750 --version vulnerable   # -> FAIL (red)
range run mcphub-idor-CVE-2026-79750 --version fixed         # -> PASS (green)
```

No narration needed. Red on the left, green on the right, same probe. That's
the hook. Capture it as a GIF for the README and a 30s screen recording for the
posts.

## The optional second clip (why it's not just pytest)

One short clip: an agent is asked, under tenant A, for tenant B's data. It
refuses politely. Then the direct tool call leaks B's data anyway. Caption:
"The model refused. The tool server didn't." This is the ten-second argument
for why prompt-level red teaming isn't authorization testing.

## Where to post (in order)

1. **Show HN** — title: "Show HN: A range of real MCP authorization CVEs you
   can break on your laptop". Lead with the GIF and the one command.
2. **r/netsec** — same, framed around the CVE list and reproduction.
3. **LinkedIn** — your voice, tied to the book chapter on agent authority. This
   is where it feeds Bitwise Defence.
4. **awesome-mcp-servers / awesome-mcp-security** — submit the repo.

## Post skeleton (adapt, don't paste verbatim)

> Every few weeks another MCP server ships a cross-tenant bug. MCPHub, n8n-mcp,
> HashiCorp's terraform-mcp-server at CVSS 10. Same shape every time: the server
> holds a broad credential and trusts an id the caller controls.
>
> Your backend authorization tests don't catch these, because the bug lives one
> layer out, in the tool server. And an agent that refuses the prompt tells you
> nothing about whether the path is safe.
>
> So I rebuilt a handful of these as a local range. Each one is the real CVE,
> pinned vulnerable and fixed. One command shows FAIL on the old version and
> PASS on the patch. Offline, no account, MIT-licensed.
>
> [GIF]
>
> It verdicts on what actually leaked, not on what the server claims. If the
> observation can't be trusted, it says ERROR instead of lying to you with a
> green check.
>
> Repo: [link]. New MCP authz CVE? That's a PR.

## Sequencing note

Launch this 4 to 6 weeks AFTER Overreach, not alongside. Two launches competing
for the same audience in the same week halves both. Let Overreach land, then
this is the second beat of the same story: "Overreach finds the path, the range
proves whether it holds."

## Second wave

While the range is public, quietly test self-hosted multi-tenant MCP servers you
run yourself, using the same harness. Disclose anything you find properly (see
DISCLOSURE.md), wait for fixes, then publish the findings as a second post. That
post, "I found N of these in the wild", is a stronger story than the launch, and
a better talk abstract.
