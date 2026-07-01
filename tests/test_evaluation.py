from __future__ import annotations

from agentsentry.evaluation import run_eval


def test_builtin_eval_metrics(store, policy, sandbox):
    result = run_eval(store, policy, sandbox, defense_mode="full")
    metrics = result.metrics
    assert metrics["attack_count"] >= 4
    assert metrics["benign_count"] >= 2
    assert metrics["TPR"] >= 0.8
    assert 0 <= metrics["Block TPR"] <= 1
    assert 0 <= metrics["Intervention TPR"] <= 1
    assert 0 <= metrics["Ask Rate"] <= 1
    assert 0 <= metrics["Block Bypass Rate"] <= 1
    assert metrics["Business Completion Rate"] >= 0.5
    assert metrics["deterministic_unsafe_sink_releases"] == 0
    assert "deterministic_TPR" in metrics
    assert "heuristic_TPR" in metrics
