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
        "| 时间 | 模式 | ASR | 干预TPR | 硬阻断TPR | FPR | 业务完成率 | 绕过率 | 非硬阻断率 | 审批降级率 | 确定性TPR | 确定性不安全释放 | 哨兵TPR | 平均延迟(ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        metrics = result.get("metrics", {})
        lines.append(
            "| {time} | {mode} | {asr} | {intervention_tpr} | {block_tpr} | {fpr} | {completion} | {bypass} | {block_bypass} | {ask_rate} | {det_tpr} | {unsafe} | {heur_tpr} | {latency} |".format(
                time=result.get("created_at", ""),
                mode=result.get("defense_mode", ""),
                asr=metrics.get("ASR", ""),
                intervention_tpr=metrics.get("Intervention TPR", metrics.get("TPR", "")),
                block_tpr=metrics.get("Block TPR", ""),
                fpr=metrics.get("FPR", ""),
                completion=metrics.get("Business Completion Rate", ""),
                bypass=metrics.get("Bypass Rate", ""),
                block_bypass=metrics.get("Block Bypass Rate", ""),
                ask_rate=metrics.get("Ask Rate", ""),
                det_tpr=metrics.get("deterministic_TPR", ""),
                unsafe=metrics.get("deterministic_unsafe_sink_releases", ""),
                heur_tpr=metrics.get("heuristic_TPR", ""),
                latency=metrics.get("avg_latency_ms", ""),
            )
        )
    lines.extend(
        [
            "",
            "## 说明",
            "",
            "- ASR 越低越好，表示攻击成功率。",
            "- 干预TPR 统计 block 或 ask，硬阻断TPR 只统计 deny/block。",
            "- 绕过率表示完全放行的攻击比例；非硬阻断率包含 ask 和完全放行，用来观察硬拦截强度。",
            "- FPR 越低越好，表示良性业务被拒绝的比例。",
            "- 业务完成率越高越好，表示加防护后正常任务仍可完成。",
        ]
    )
    return "\n".join(lines) + "\n"
