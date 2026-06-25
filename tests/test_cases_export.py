from __future__ import annotations

from fastapi.testclient import TestClient

from agentsentry.app import app
from agentsentry.cases import load_cases
from agentsentry.export import eval_results_to_csv, eval_results_to_markdown


def test_load_chinese_case_suite():
    data = load_cases()
    cases = data["cases"]
    assert data["suite"] == "AgentSentry-M2-Chinese-Cases"
    assert len(cases) >= 7
    assert any(case["category"] == "indirect_prompt_injection" for case in cases)
    assert all("benchmark_mapping" in case for case in cases)


def test_eval_results_to_csv():
    csv_text = eval_results_to_csv(
        [
            {
                "id": "eval_1",
                "created_at": "now",
                "suite": "m2_builtin",
                "defense_mode": "full",
                "metrics": {"ASR": 0, "TPR": 1, "cases": []},
            }
        ]
    )
    assert "eval_id,created_at,suite,defense_mode,metric,value" in csv_text
    assert "eval_1,now,m2_builtin,full,ASR,0" in csv_text
    assert "cases" not in csv_text


def test_eval_results_to_markdown():
    markdown = eval_results_to_markdown(
        [
            {
                "created_at": "now",
                "defense_mode": "full",
                "metrics": {
                    "ASR": 0,
                    "TPR": 1,
                    "FPR": 0,
                    "Business Completion Rate": 1,
                    "Bypass Rate": 0,
                    "deterministic_TPR": 1,
                    "deterministic_unsafe_sink_releases": 0,
                    "heuristic_TPR": 0.5,
                    "avg_latency_ms": 1.5,
                },
            }
        ]
    )
    assert "# AgentSentry 评测结果" in markdown
    assert "确定性TPR" in markdown
    assert "哨兵TPR" in markdown
    assert "| now | full | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 0.5 | 1.5 |" in markdown


def test_cases_and_export_api():
    client = TestClient(app)
    cases = client.get("/api/cases")
    assert cases.status_code == 200
    assert cases.json()["cases"]

    exported = client.get("/api/cases/export.json")
    assert exported.status_code == 200
    assert "agentsentry-cases.json" in exported.headers["content-disposition"]

    client.post("/api/eval/run?defense_mode=full")
    csv_resp = client.get("/api/eval/export.csv")
    assert csv_resp.status_code == 200
    assert "ASR" in csv_resp.text

    report_resp = client.get("/api/eval/report.md")
    assert report_resp.status_code == 200
    assert "AgentSentry 评测结果" in report_resp.text


def test_ablation_api():
    client = TestClient(app)
    response = client.post("/api/eval/ablation")
    assert response.status_code == 200
    body = response.json()
    assert body["suite"] == "m2_ablation"
    assert len(body["rows"]) >= 5
    assert "ASR_reduction_vs_none" in body["summary"]
