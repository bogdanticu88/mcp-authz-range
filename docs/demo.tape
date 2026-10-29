# Renders docs/demo.gif with vhs (https://github.com/charmbracelet/vhs).
#   brew install vhs     # one time
#   make gif             # or: vhs docs/demo.tape
#
# Shows the hook: same command, one word different, FAIL then PASS. Uses --mock
# so it runs instantly (no Docker) and the GIF stays short.

Output docs/demo.gif
Set Shell bash
Set FontSize 20
Set Width 1150
Set Height 430
Set Padding 22
Set Theme "Dracula"

# Hidden setup: run from repo root, expose `range` without needing it on PATH.
Hide
Type "cd $(git rev-parse --show-toplevel 2>/dev/null || pwd)" Enter
Type "range() { python3 harness/cli.py \"$@\"; }" Enter
Type "clear" Enter
Show

Type "# your authorization tests pass. the agent's path doesn't." Enter
Sleep 1s
Type "range run mcphub-idor-CVE-2026-79750 --version vulnerable" Sleep 600ms Enter
Sleep 2s
Type "range run mcphub-idor-CVE-2026-79750 --version fixed" Sleep 600ms Enter
Sleep 3500ms
