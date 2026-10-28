"""
Guard test: the evaluator must not be able to see the answer key.

The trust story depends on the verdict engine judging only evidence, never the
fixture's fault label or expected verdict. This test proves verdict.py has no
import path to case metadata, by inspecting what its module imports.

If someone later wires case.yaml into the evaluator, this test fails loudly.
"""

import ast
import pathlib


def test_verdict_engine_imports_nothing_case_related():
    src = pathlib.Path(__file__).with_name("verdict.py").read_text()
    tree = ast.parse(src)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [n.name for n in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")

    banned = ("yaml", "case", "cases", "fixture", "oracle", "answer")
    leaks = [m for m in imported if any(b in (m or "").lower() for b in banned)]
    assert not leaks, f"verdict engine must not import case/answer-key modules: {leaks}"


def test_attempt_result_has_no_expected_verdict_field():
    # The evaluator's input type must not carry the expected answer.
    from verdict import AttemptResult
    fields = AttemptResult.__dataclass_fields__.keys()
    for forbidden in ("expected", "fault_label", "answer", "oracle"):
        assert forbidden not in fields, f"{forbidden} must not be visible to the evaluator"
