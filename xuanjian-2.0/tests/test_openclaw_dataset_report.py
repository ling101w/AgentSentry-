import json

from scripts.openclaw_dataset_report import run


def test_report_validates_snapshot_and_creates_metadata_only_queue(tmp_path):
    input_path = tmp_path / "graphs.jsonl"
    report_path = tmp_path / "report.md"
    queue_path = tmp_path / "queue.jsonl"
    record = {
        "graph_id": "g1",
        "session_id": "s1",
        "label": "unknown",
        "nodes": [
            {
                "node_id": "i1",
                "node_type": "intent",
                "task_type": "file_processing",
            },
            {
                "node_id": "c1",
                "node_type": "tool_call",
                "tool_name": "read_file",
            },
        ],
        "edges": [
            {
                "source": "i1",
                "target": "c1",
                "type": "intent_drives",
                "weight": 1.0,
            }
        ],
    }
    input_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    summary = run(input_path, report_path, queue_path)

    assert summary["records"] == 1
    assert summary["errors"] == []
    assert summary["queued_for_labeling"] == 1
    queue_record = json.loads(queue_path.read_text(encoding="utf-8"))
    assert queue_record["tool_names"] == ["read_file"]
    assert "user_message" not in queue_record
    assert "tool_args" not in queue_record
    assert "observation" not in queue_record
    assert "Validation errors" in report_path.read_text(encoding="utf-8")


def test_report_rejects_duplicate_ids_and_bad_edges(tmp_path):
    input_path = tmp_path / "graphs.jsonl"
    report_path = tmp_path / "report.md"
    queue_path = tmp_path / "queue.jsonl"
    record = {
        "graph_id": "g1",
        "session_id": "s1",
        "label": "unknown",
        "nodes": [{"node_id": "i1", "node_type": "intent", "task_type": "unknown"}],
        "edges": [{"source": "i1", "target": "missing", "type": "bad", "weight": 2}],
    }
    input_path.write_text(
        "\n".join(json.dumps(record) for _ in range(2)) + "\n",
        encoding="utf-8",
    )

    summary = run(input_path, report_path, queue_path)

    assert summary["records"] == 2
    assert len(summary["errors"]) >= 4
