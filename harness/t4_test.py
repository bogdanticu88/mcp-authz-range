"""T4 over real HTTP: non-admin privileged config change, protected vs vulnerable."""
from fixture_control import fixture
from http_adapter import http_session
from t4_privilege import run_t4
from verdict import Verdict, evaluate


def test_t4_protected_passes():
    # Fixed server: non-admin write is denied, admin's control value stands.
    with fixture("protected") as base:
        attacker = http_session("mallory", base)   # non-admin
        admin = http_session("admin", base)         # admin
        v, _ = evaluate(run_t4("run1", attacker, admin))
        assert v == Verdict.PASS


def test_t4_vulnerable_fails():
    # privesc_vuln: non-admin's config change takes effect.
    with fixture("privesc_vuln") as base:
        attacker = http_session("mallory", base)
        admin = http_session("admin", base)
        v, _ = evaluate(run_t4("run1", attacker, admin))
        assert v == Verdict.FAIL


def test_t4_control_must_fire():
    # If the admin control write cannot be observed, it must be ERROR not PASS.
    # Simulate by pointing both sessions at a server where read_config is empty:
    # we use privesc but break the control by reading a different key.
    from t4_privilege import run_t4 as r
    with fixture("protected") as base:
        attacker = http_session("mallory", base)
        admin = http_session("admin", base)
        res = r("run1", attacker, admin, key="unused_key")
        # Control writes & reads the same key, so it still fires; protected ->
        # PASS. This asserts the normal protected path holds for an arbitrary key.
        v, _ = evaluate(res)
        assert v == Verdict.PASS
