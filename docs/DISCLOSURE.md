# Responsible use and disclosure

This range exists to test authorization on MCP servers. That power cuts both
ways, so two rules are not optional.

## 1. Only test servers you are allowed to test

Run this against:

- the pinned CVE cases in this repo, which are servers you host yourself, and
- MCP servers you deploy yourself, in tenants you own.

Do **not** point it at a hosted, multi-tenant MCP service you do not operate.
Probing another tenant's data on a shared service is unauthorized access,
whatever your intent, unless a published bug-bounty scope explicitly covers it.
Intent does not make it legal.

## 2. If you find a new bug, disclose it properly

1. Confirm it by hand first. Reproduce it, capture the evidence, and make sure
   it is a real cross-tenant or authorization failure, not a misconfigured test.
2. Report it privately to the maintainer (GitHub security advisory, or their
   stated security contact).
3. Give them time. The usual window is 90 days, or until a fix ships, whichever
   comes first.
4. Only then publish, and add the case to this range once the fix is out.

Never publish a `FAIL` against a named third-party project before you have
reproduced it by hand and given the maintainer notice. One wrong public accusation
does more damage to your credibility than a hundred quiet, correct findings.
