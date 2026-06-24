from __future__ import annotations

import csv
import io
import json
from typing import Any


def eval_results_to_csv(results: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["eval_id", "created_at", "suite", "defense_mode", "metric", "value"])
    for result in results:
        metrics = result.get("metrics", {})
        for key, value in metrics.items():
            if key == "cases":
                continue
            writer.writerow(
                [
                    result.get("id", ""),
                    result.get("created_at", ""),
                    result.get("suite", ""),
                    result.get("defense_mode", ""),
                    key,
                    value,
                ]
            )
    return output.getvalue()


def cases_to_json(cases: dict[str, Any]) -> str:
    return json.dumps(cases, ensure_ascii=False, indent=2)


def eval_results_to_markdown(results: list[dict[str, Any]]) -> str:
    lines = [
        "# AgentSentry 评测结果",
        "",
        "| 时间 | 模式 | ASR | TPR | FPR | 业务完成率 | 绕过率 | 平均延迟(ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        metrics = result.get("metrics", {})
        lines.append(
            "| {time} | {mode} | {asr} | {tpr} | {fpr} | {completion} | {bypass} | {latency} |".format(
                time=result.get("created_at", ""),
                mode=result.get("defense_mode", ""),
                asr=metrics.get("ASR", ""),
                tpr=metrics.get("TPR", ""),
                fpr=metrics.get("FPR", ""),
                completion=metrics.get("Business Completion Rate", ""),
                bypass=metrics.get("Bypass Rate", ""),
                latency=metrics.get("avg_latency_ms", ""),
            )
        )
    lines.extend(
        [
            "",
            "## 说明",
            "",
            "- ASR 越低越好，表示攻击成功率。",
            "- TPR 越高越好，表示该阻断的攻击动作被识别或拦截。",
            "- FPR 越低越好，表示良性业务被拒绝的比例。",
            "- 业务完成率越高越好，表示加防护后正常任务仍可完成。",
        ]
    )
    return "\n".join(lines) + "\n"
