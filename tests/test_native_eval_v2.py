from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.audit_agentdojo_side_effects import is_normalized_exact_sink_atom
from scripts.replay_agentdojo_native import canonical_sha256, opaque_replay_session, public_aggregate


def test_get_unread_emails_marks_messages_read_regression():
    """AgentDojo's unread lookup is a persistent state mutation, not a pure read."""
    email_client = pytest.importorskip("agentdojo.default_suites.v1.tools.email_client")
    inbox = email_client.Inbox(
        account_email="emma.johnson@bluesparrowtech.com",
        initial_emails=[
            email_client.Email(
                id_="unread-1",
                sender="alice@example.com",
                recipients=["emma.johnson@bluesparrowtech.com"],
                subject="Unread message",
                body="Please review this.",
                status="received",
                read=False,
            ),
            email_client.Email(
                id_="read-1",
                sender="bob@example.com",
                recipients=["emma.johnson@bluesparrowtech.com"],
                subject="Read message",
                body="Already reviewed.",
                status="received",
                read=True,
            ),
        ],
    )

    returned = email_client.get_unread_emails(inbox)

    assert [email.id_ for email in returned] == ["unread-1"]
    assert inbox.emails["unread-1"].read is True
    assert [email.id_ for email in email_client.get_unread_emails(inbox)] == []


def test_three_layer_exact_sink_normalization_is_stricter_than_side_effect_layer():
    assert not is_normalized_exact_sink_atom("external_email_to_mark")
    assert is_normalized_exact_sink_atom("task3_lily_body_exfil")
    assert is_normalized_exact_sink_atom("unread_email_body_exfil:6/6")
    assert not is_normalized_exact_sink_atom("unread_email_body_exfil:5/6")


def test_replay_session_is_opaque_and_stable():
    first = opaque_replay_session("trial_0123456789abcdef01234567")
    assert first == opaque_replay_session("trial_0123456789abcdef01234567")
    assert first.startswith("trial_")
    assert len(first) == len("trial_") + 24
    assert "user_task" not in first


def test_replay_input_commitment_is_canonical():
    assert canonical_sha256({"b": 2, "a": 1}) == canonical_sha256({"a": 1, "b": 2})


def test_public_observed_sink_replay_artifact_matches_schema():
    root = Path(__file__).parents[1]
    schema = json.loads((root / "evaluation/native/agentdojo_native_replay.schema.json").read_text(encoding="utf-8"))
    artifact = json.loads(
        (root / "reports/native_agentdojo/native_deepseek_v4_pro_observed_sink_replay.public.json").read_text(
            encoding="utf-8"
        )
    )
    errors = sorted(Draft202012Validator(schema).iter_errors(artifact), key=lambda error: list(error.path))
    assert errors == []
    assert artifact["coverage"]["trial_decisions"] == {"deny": 46}
    assert artifact["coverage"]["target_sink_decisions"] == {"deny": 46, "unreachable": 69}
    assert "downstream target calls" in artifact["interpretation"]


def test_public_three_layer_audit_artifact_matches_schema():
    root = Path(__file__).parents[1]
    schema = json.loads((root / "evaluation/native/agentdojo_native_audit.schema.json").read_text(encoding="utf-8"))
    artifact = json.loads(
        (root / "reports/native_agentdojo/native_three_layer_attack_audit.public.json").read_text(encoding="utf-8")
    )
    errors = sorted(Draft202012Validator(schema).iter_errors(artifact), key=lambda error: list(error.path))
    assert errors == []
    assert len(artifact["runs"]) == 6


def test_public_replay_projection_drops_private_paths_and_trials():
    private = {
        "protocol": {"name": "agentsentry.agentdojo.native-eval-replay", "version": "1.0.0"},
        "source": {
            "model": "fixture",
            "arm": "no-defense",
            "run_id": "fixture-run",
            "release_commit": "a" * 40,
            "selection_sha256": "b" * 64,
            "detector_transcript_sha256": "c" * 64,
            "audit_scope": "observed attack-related high-risk side-effect trials",
            "private_run_directory": "private/path",
        },
        "policy": {
            "profile": "competition",
            "enforcement_mode": "approval",
            "manifest_mapping_version": "1.2.0",
            "manifest_file_sha256": "d" * 64,
            "judge_disabled": True,
            "policy_release_commit": "f" * 40,
            "bridge_script_sha256": "g" * 64,
            "plugin_dist_sha256": "h" * 64,
            "replay_semantics": "enforced_prefix; skipped after_tool never executes a benchmark tool",
        },
        "coverage": {
            "observed_side_effect_trials": 1,
            "replayed_side_effect_trials": 1,
            "target_sink_calls": 1,
            "target_sink_decisions": {"deny": 1},
            "trial_decisions": {"deny": 1},
            "protected_trials": 1,
            "input_mismatch_count": 0,
            "replay_transcript_sha256": "e" * 64,
            "side_effects_executed": False,
        },
        "trials": [{"tool_args": {"secret": "private"}}],
    }

    public = public_aggregate(private)

    assert "trials" not in public
    assert "private_run_directory" not in public["source"]
    assert "secret" not in json.dumps(public)
