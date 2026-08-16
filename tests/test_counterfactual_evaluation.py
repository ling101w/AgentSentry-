from __future__ import annotations

from collections import Counter

from agentsentry.evaluation_baselines import BaselineCase, baseline_authorization_only, evaluate_baselines
from scripts.generate_counterfactual_dataset import generate_cases
from scripts.run_counterfactual_eval import load_counterfactual_cases, run_counterfactual_case, summarize_pairs


def test_counterfactual_suite_has_sixty_benign_cases_per_sink_and_matched_trusted_text() -> None:
    rows = generate_cases()
    assert len(rows) == 720
    assert Counter(row["sink"] for row in rows if not row["attack"]) == {
        "read_file": 60,
        "write_file": 60,
        "send_email": 60,
        "call_api": 60,
        "shell_exec": 60,
        "memory_write": 60,
    }
    by_pair = {}
    for row in rows:
        by_pair.setdefault(row["pair_id"], []).append(row)
    assert len(by_pair) == 360
    for pair in by_pair.values():
        assert {row["variant"] for row in pair} == {"benign", "attack"}
        trusted = {
            row["detector_input"]["command"]
            for row in pair
        }
        assert len(trusted) == 2
        assert all(
            __import__("json").loads(row["detector_input"]["command"])["trusted_input"]
            == __import__("json").loads(pair[0]["detector_input"]["command"])["trusted_input"]
            for row in pair
        )


def test_authorization_only_is_not_a_prompt_injection_detector() -> None:
    rows = generate_cases()
    summary = evaluate_baselines([
        BaselineCase(
            case_id=row["case_id"],
            attack=row["attack"],
            detector_input=row["detector_input"],
            sink=row["sink"],
            pair_id=row["pair_id"],
        )
        for row in rows
    ])
    authorization = summary["baselines"]["authorization-only"]
    assert authorization["benign_allow_rate"] == 1.0
    assert authorization["protection_rate"] < 1.0
    assert authorization["matched_pair_accuracy"] < 1.0
    assert baseline_authorization_only(rows[0]["detector_input"]) == "allow"


def test_counterfactual_runner_does_not_send_oracle_labels(monkeypatch) -> None:
    row = next(row for row in generate_cases() if row["sink"] == "send_email" and not row["attack"])
    captured = {}

    def fake_post(base_url, path, payload, timeout):
        captured.update(payload)
        return {
            "ok": True,
            "action_projection": {
                "mode": "explicit_actions",
                "supported": True,
                "benchmark_case": True,
                "action_count": 1,
                "tools": ["send_email"],
                "parameter_origins": ["payload_explicit"],
                "envelope": {"status": "valid", "schema": "agentsentry.command-envelope.v1"},
            },
            "decisions": [{"normalized_tool": "send_email", "decision": "allow"}],
            "session": {},
        }

    monkeypatch.setattr("scripts.run_counterfactual_eval.post_json", fake_post)
    result = run_counterfactual_case(
        "http://127.0.0.1:8765",
        row,
        timeout=1.0,
        semantic_judge="off",
        semantic_timeout_ms=4000,
    )

    assert result["allowed_all"] is True
    assert "attack" not in captured
    assert "expectation" not in captured
    assert "oracle" not in captured
    assert captured["benchmarkCaseId"] != row["case_id"]
    assert captured["benchmarkCaseId"].startswith("counterfactual-case-")
    assert captured["clientId"].startswith("counterfactual-client-")
    assert "benign" not in captured["benchmarkCaseId"]
    assert "attack" not in captured["benchmarkCaseId"]
    envelope = __import__("json").loads(captured["command"])
    origin = envelope["untrusted_inputs"][0]["origin"]
    assert row["pair_id"] not in origin
    assert "benign" not in origin
    assert "attack" not in origin
    assert captured["actions"] == row["detector_input"]["actions"]


def test_pair_summary_requires_both_boundary_decisions() -> None:
    rows = generate_cases()[:2]
    first = {
        "pair_id": rows[0]["pair_id"],
        "variant": "benign",
        "sink": rows[0]["sink"],
        "allowed_all": True,
        "protected": False,
        "boundary_correct": True,
        "harness_error": "",
        "action_projection": {"supported": True},
    }
    second = {
        "pair_id": rows[1]["pair_id"],
        "variant": "attack",
        "sink": rows[1]["sink"],
        "allowed_all": False,
        "protected": True,
        "boundary_correct": True,
        "harness_error": "",
        "action_projection": {"supported": True},
    }
    summary = summarize_pairs([first, second])
    assert summary["overall"]["evaluable_pairs"] == 1
    assert summary["overall"]["successful_pairs"] == 1
    assert summary["overall"]["boundary_accuracy"] == 1.0
