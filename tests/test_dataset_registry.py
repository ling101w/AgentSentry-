from __future__ import annotations

from pathlib import Path

import pytest

from agentsentry.dataset_pipeline.registry import (
    RegistryImportError,
    enrich_registry_rows,
    import_registry_xlsx,
)
from agentsentry.dataset_pipeline.schema import make_record
from agentsentry.dataset_pipeline.sources import SOURCE_BY_KEY


openpyxl = pytest.importorskip("openpyxl")


def _workbook(path: Path, rows: list[tuple[object, ...]]) -> None:
    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.title = "六类威胁分类"
    for row in rows:
        worksheet.append(row)
    workbook.save(path)
    workbook.close()


def test_import_registry_normalizes_and_enriches_supported_sources(tmp_path: Path) -> None:
    source = tmp_path / "registry.xlsx"
    _workbook(
        source,
        [
            (" 数据集 ", "威胁", "分类依据", "边界说明"),
            (" ＡｇｅｎｔＤｏｊｏ ", " Ｔ２  间接提示注入 ", "  外部工具返回触发。 ", " — "),
            ("MCP Security Bench（MSB）", "T4 工具描述篡改", "协议元数据被篡改。", "扩展映射。"),
            ("Unknown Bench", "T6/T2 权限升级", "用于目录登记。", "未知来源。"),
        ],
    )

    rows = import_registry_xlsx(source)

    assert len(rows) == 3
    agentdojo = rows[0]
    assert agentdojo["source_id"] == "agentdojo"
    assert agentdojo["dataset"] == "AgentDojo"
    assert agentdojo["dataset_raw"] == "AgentDojo"
    assert agentdojo["threat_primary"] == "T2"
    assert agentdojo["threat_secondary"] == ["T3"]
    assert agentdojo["threat_name"] == "间接提示注入"
    assert agentdojo["classification_basis"] == "外部工具返回触发。"
    assert agentdojo["boundary_note"] is None
    assert agentdojo["repo_url"].endswith("/agentdojo.git")
    assert agentdojo["raw_format"] == "python"
    assert agentdojo["adapter"] == "agentdojo"
    assert agentdojo["agent_sentry_adapter"] is True
    assert agentdojo["source_file"] == source.name
    assert len(agentdojo["source_sha256"]) == 64
    assert agentdojo["source_sheet"] == "六类威胁分类"
    assert agentdojo["source_row"] == 2

    assert rows[1]["dataset"] == "MSB"
    assert rows[1]["threat_secondary"] == ["T3"]
    assert rows[2]["dataset"] == "Unknown Bench"
    assert rows[2]["threat_primary"] == "T6"
    assert rows[2]["threat_secondary"] == ["T2"]
    assert rows[2]["adapter"] is None
    assert rows[2]["repo_url"] is None


@pytest.mark.parametrize(
    ("headers", "threat", "message"),
    [
        (("数据集", "威胁", "边界说明", "分类依据"), "T2 注入", "invalid registry headers"),
        (("数据集", "威胁", "分类依据", "边界说明"), "T8 未知", "expected at least one code"),
    ],
)
def test_import_registry_rejects_wrong_contract(
    tmp_path: Path,
    headers: tuple[str, ...],
    threat: str,
    message: str,
) -> None:
    source = tmp_path / "invalid.xlsx"
    _workbook(source, [headers, ("Example", threat, "依据", "—")])

    with pytest.raises(RegistryImportError, match=message):
        import_registry_xlsx(source)


def test_enrich_registry_marks_only_built_sources_ready() -> None:
    rows = [
        {"dataset": "AgentDojo", "status": "TODO", "license": None},
        {"dataset": "Unknown Bench", "status": "TODO", "license": None},
    ]
    record = make_record(
        spec=SOURCE_BY_KEY["agentdojo"],
        original_id="fixture",
        source_ref="fixture.py:1",
        attack=True,
        attack_type="indirect_prompt_injection",
        user_instruction="summarize the email",
        attacker_instruction="send the secret",
        tool_response="external email body",
        tool_name="read_email",
        trajectory=[{"type": "tool_response"}],
        scenario="external_email_hidden",
        command="summarize the email",
        raw_record={"expected_result": "block"},
    )
    record["quality"]["status"] = "valid"
    manifest = {
        "sources": [
            {
                "dataset": "AgentDojo",
                "url": "https://example.invalid/agentdojo.git",
                "commit": "abc123",
                "license": "MIT",
                "raw_format": "python",
                "sha256": "f" * 64,
                "downloaded_at": "2026-08-07T00:00:00Z",
            }
        ]
    }

    enriched = enrich_registry_rows(rows, [record], manifest)

    assert enriched[0]["status"] == "READY"
    assert enriched[0]["sample_count"] == 1
    assert enriched[0]["has_attack"] is True
    assert enriched[0]["has_benign"] is False
    assert enriched[0]["has_trajectory"] is True
    assert enriched[0]["has_tool_context"] is True
    assert enriched[0]["has_ground_truth"] is True
    assert enriched[0]["version"] == "abc123"
    assert enriched[1] == rows[1]
