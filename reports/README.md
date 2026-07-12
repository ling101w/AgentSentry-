# 玄鉴 文档索引

更新时间：2026-07-03

评测口径先读 `reports/EVALUATION_METHODOLOGY.md`：历史 840 条均为公开数据映射到 `/command-lab` 的开发回归，不是独立盲测，也不是 AgentDojo/InjecAgent 原生端到端运行。

玄鉴是本参赛作品名称，当前仓库和插件内部仍沿用 `AgentSentry` 作为代码包名。答辩和报告中建议统一使用：

> 玄鉴：面向智能体工具调用链的实时行为监督与风险拦截系统

## 推荐阅读顺序

| 文档 | 用途 |
|---|---|
| `reports/START_HERE.md` | 最短入口：先看什么、benchmark 文件在哪、怎么在 `/command-lab` 逐条测试 |
| `reports/EVALUATION_METHODOLOGY.md` | 评测证据等级、标签隔离、盲测与原生 Benchmark 口径 |
| `reports/competition_report.md` | 正式安全风险分析与行为监督报告 |
| `reports/system_functionality.md` | 系统功能、架构、真实数据来源和限制 |
| `reports/project_name_and_benchmark_summary.md` | 作品命名、公开 benchmark 汇总和核心指标 |
| `reports/feature_algorithm_talk_track.md` | 答辩讲解稿：算法流程、技术亮点、可讲功能 |
| `reports/technical_design_and_algorithms.md` | 技术架构与算法设计：TaskSpec、污点传播、语义动作图、Memory Guard、LLM-Judge |
| `reports/demo_and_reproduction.md` | 演示顺序、复现实验命令和入口说明 |
| `reports/agent_attack_scripts.md` | 对抗样本与智能体攻击脚本 |
| `reports/tool_benchmark_sources.md` | 已调研和接入的公开 benchmark 来源说明 |
| `reports/competition_gap_assessment.md` | 对照比赛要求的完成度与剩余限制 |

## Benchmark 文件位置

| 类型 | 位置 |
|---|---|
| 公开 benchmark 原始仓库 | `third_party/benchmarks/` |
| 可在 `/command-lab` 运行的映射样例 | `reports/benchmark_risk_tiered/benchmark_cases.risk_tiered.jsonl`、`reports/benchmark_risk_tiered/tool_attack_cases.risk_tiered.jsonl` |
| 上次真实评测输出 | `reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json`、`reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json` |

原始 benchmark 通常只有任务、payload、攻击类别或工具定义，不会自带 OpenClaw 回答。OpenClaw/玄鉴 的输出来自实际运行，保存在结果 JSON 和 8765 运行记录中。

## 最新实验结果

| 实验 | 报告 | 原始结果 |
|---|---|---|
| 综合攻击回归，520 条，risk-tiered | `reports/benchmark_risk_tiered/benchmark_eval_report.risk_tiered.md` | `reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json` |
| 非提示注入工具攻击专项，320 条，risk-tiered | `reports/benchmark_risk_tiered/tool_attack_benchmark_report.risk_tiered.md` | `reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json` |
| risk-tiered 长文本留档 | `reports/benchmark_risk_tiered/xuanjian_benchmark_risk_tiered_record.txt` | `reports/benchmark_risk_tiered/` |
| 全量 LLM-Judge 长文本留档 | `reports/benchmark_judge_full/xuanjian_benchmark_full_llm_judge_record.txt` | `reports/benchmark_judge_full/` |
| 开启/关闭对比实验 | `reports/supervision_ablation/supervision_ablation_explained.md` | `reports/supervision_ablation/supervision_ablation_results.json` |
| 完整功能验收 | `reports/full_acceptance/full_acceptance_report.latest.md` | `reports/full_acceptance/full_acceptance_results.latest.json` |

## 当前核心指标

- 综合攻击回归，risk-tiered：520 条，攻击保护率 100.0%，高风险漏放率 0.0%，正常业务放行率 100.0%，误拦率 0.0%，harness error 0。
- 工具攻击专项，risk-tiered：320 条，工具攻击保护率 100.0%，高风险漏放率 0.0%，正常工具放行率 100.0%，误拦率 0.0%，harness error 0。
- LLM-Judge：当前推荐 `risk-tiered` 调度；full Judge 结果仍保留，用于说明全量语义复核的成本和误拦。
- 对比 full Judge：高风险漏放保持 0，误拦从 7 条降为 0 条，总耗时从约 135.2 分钟降到约 76.8 分钟。
- 当前 `8765` 是主展示入口；`8000` 仅作为历史离线实验和辅助入口。

## 保留原则

本目录保留最终报告、最新实验结果和必要复现材料。旧时间戳 benchmark 快照、早期草稿、重复说明文档已清理，避免答辩材料口径混乱。
