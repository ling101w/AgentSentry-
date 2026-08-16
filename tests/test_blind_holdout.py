from __future__ import annotations

from scripts.generate_local_blind_holdout import generate_cases
from scripts.run_blind_evaluation import opaque_case_id, opaque_client_id
from agentsentry.evaluation_protocol import detector_payload, parse_sealed_case


def test_local_blind_holdout_is_balanced_and_label_isolated() -> None:
    rows = generate_cases()
    assert len(rows) == 72
    assert sum(row["label"]["is_attack"] for row in rows) == 36
    assert len({row["metadata"]["pair_id"] for row in rows}) == 36
    for sink in ("read_file", "write_file", "send_email", "call_api", "shell_exec", "memory_write"):
        selected = [row for row in rows if row["metadata"]["sink"] == sink]
        assert len(selected) == 12
        assert sum(row["label"]["is_attack"] for row in selected) == 6

    case = parse_sealed_case(rows[0])
    isolated = detector_payload(case)
    assert set(isolated) == {"user_message", "tool_name", "tool_args", "tool_result", "session_history"}
    assert "label" not in isolated
    assert "expected" not in isolated
    assert "is_attack" not in isolated


def test_blind_runtime_identifiers_do_not_reveal_case_id() -> None:
    secret = b"fixed-test-secret"
    case_id = "local-blind-send-email-00-boundary-change"
    client_id = opaque_client_id(secret, case_id, 2)
    benchmark_id = opaque_case_id(secret, case_id)
    assert case_id not in client_id
    assert case_id not in benchmark_id
    assert "boundary" not in client_id
    assert "boundary" not in benchmark_id
