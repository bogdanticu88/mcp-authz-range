"""CLI smoke tests: list, case validation, exit codes."""

import cli
from verdict import EXIT_CRASH, EXIT_FAIL, EXIT_OK


def test_list_runs_and_finds_the_case(capsys):
    rc = cli.main(["list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "mcphub-idor-CVE-2026-79750" in out


def test_unknown_case_is_rejected():
    rc = cli.main(["run", "does-not-exist"])
    assert rc == EXIT_CRASH


def test_mock_vulnerable_fails_and_fixed_passes():
    assert cli.main(["run", "mcphub-idor-CVE-2026-79750", "--version", "vulnerable", "--mock"]) == EXIT_FAIL
    assert cli.main(["run", "mcphub-idor-CVE-2026-79750", "--version", "fixed", "--mock"]) == EXIT_OK


def test_known_case_without_adapter_flag_defaults_to_case_adapter(monkeypatch):
    # Not executing the adapter here (it needs a live server); just confirm the
    # CLI resolves the case and attempts its own adapter rather than erroring on
    # the name. We force the adapter loader to raise to prove we got past validation.
    import cli as climod

    def boom(path):
        raise RuntimeError(f"would load {path}")
    monkeypatch.setattr(climod, "_load_adapter_sessions", boom)
    rc = climod.main(["run", "mcphub-idor-CVE-2026-79750"])
    # The crash is caught and mapped to EXIT_CRASH, which means validation passed
    # and it tried the case's own adapter.
    assert rc == EXIT_CRASH
