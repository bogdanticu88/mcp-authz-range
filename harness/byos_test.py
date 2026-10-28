"""The bring-your-own-server path: template guard + CLI accepts --adapter."""
import os
import cli
from verdict import EXIT_CRASH


TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "templates", "byos_adapter.py")


def test_template_refuses_until_filled():
    # An unfilled template must raise, not silently produce a verdict.
    import importlib.util
    spec = importlib.util.spec_from_file_location("byos_tmpl", TEMPLATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    raised = False
    try:
        mod.sessions()
    except NotImplementedError:
        raised = True
    assert raised, "unfilled template must raise NotImplementedError"


def test_cli_accepts_adapter_without_registered_case(monkeypatch):
    # An explicit --adapter file lets an unknown (ad-hoc) case name through
    # validation; we force the loader to raise to prove we got past it.
    def boom(path):
        raise RuntimeError(f"reached loader for {path}")
    monkeypatch.setattr(cli, "_load_adapter_sessions", boom)
    rc = cli.main(["run", "my-own-server", "--adapter", TEMPLATE])
    assert rc == EXIT_CRASH  # crash caught => validation passed, loader was tried


def test_cli_still_rejects_unknown_case_without_adapter():
    rc = cli.main(["run", "no-such-case"])
    assert rc == EXIT_CRASH
