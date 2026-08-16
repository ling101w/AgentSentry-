# 玄鉴 文档索引

更新时间：2026-08-14

评测总览先读 `reports/recent_benchmark_detailed_report.md`，证据口径再读 `reports/EVALUATION_METHODOLOGY.md`：历史 840 条和六来源 7,227 条均为公开数据映射到 `/command-lab` 的开发回归；AgentDojo 120/140 case 报告才是原生端到端运行。

玄鉴是本参赛作品名称，当前仓库和插件内部仍沿用 `AgentSentry` 作为代码包名。答辩和报告中建议统一使用：

> 玄鉴：面向智能体工具调用链的实时行为监督与风险拦截系统

## 推荐阅读顺序

| 文档 | 用途 |
|---|---|
| `reports/benchmark_presentation.html` | Benchmark 工作汇报网页：直接打开即可演示，含真实样本切换、三策略对比、证据边界，并支持打印或导出 PDF |
| `outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140_release.md` | 最新发布级后验 arm：DeepSeek V4 Pro、Expanded v1、evidence-gated 140-trial 复跑，含指标、运行恢复说明和证据承诺 |
| `reports/recent_benchmark_detailed_report.md` | 近期各次 benchmark 的数据构成、具体样本、原生工具轨迹、结果和证据边界详解 |
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
| AgentDojo Expanded v1，DeepSeek V4 Pro，预注册 competition 主实验 | `reports/native_agentdojo/native_deepseek_v4_pro_agentsentry_vs_no_defense_expanded_v1_140.md` | `reports/native_agentdojo/native_deepseek_v4_pro_{agentsentry,no_defense}_expanded_v1_140.public.json` |
| AgentDojo Expanded v1，DeepSeek V4 Pro，发布级后验 evidence-gated arm | `outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140_release.md` | `outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140.public.json`、`outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140_manifest.json`、`outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140_three_layer.public.json`、`outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140_provenance.json` |
| AgentDojo 标准选择集，多模型，每个 arm 120 trials | `reports/native_agentdojo/*_agentsentry_vs_no_defense_120.md` | `reports/native_agentdojo/*.public.json` |
| 六来源统一全量/平衡回归，7,227/1,295 条 | `dataset/agentsentry/run_report.{full,balanced}.md` | `dataset/agentsentry/run_results.{full,balanced}.json` |
| 授权反事实，360 对、720 条 | `reports/counterfactual/authorization_report.md` | `runtime/counterfactual/authorization_results.final.json` |
| 综合攻击回归，520 条，risk-tiered | `reports/benchmark_risk_tiered/benchmark_eval_report.risk_tiered.md` | `reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json` |
| 非提示注入工具攻击专项，320 条，risk-tiered | `reports/benchmark_risk_tiered/tool_attack_benchmark_report.risk_tiered.md` | `reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json` |
| risk-tiered 长文本留档 | `reports/benchmark_risk_tiered/xuanjian_benchmark_risk_tiered_record.txt` | `reports/benchmark_risk_tiered/` |
| 全量 LLM-Judge 长文本留档 | `reports/benchmark_judge_full/xuanjian_benchmark_full_llm_judge_record.txt` | `reports/benchmark_judge_full/` |
| 开启/关闭对比实验 | `reports/supervision_ablation/supervision_ablation_explained.md` | `reports/supervision_ablation/supervision_ablation_results.json` |
| 完整功能验收 | `reports/full_acceptance/full_acceptance_report.latest.md` | `reports/full_acceptance/full_acceptance_results.latest.json` |

## 当前核心指标

- AgentDojo Expanded v1 预注册主实验：无防御官方 ASR `61/100`，玄鉴 `competition` 为 `1/100`；真实高危副作用 `63/100` 降至 `1/100`。正常 Utility 由 `35/40` 降至 `27/40`，玄鉴正常 deny 为 `10/40`、ask/deny 合计 `13/40`。
- AgentDojo Expanded v1 发布级后验 arm：玄鉴 `evidence-gated` 三层攻击指标均为 `0/100`，正常 Utility `37/40`，攻击环境任务 Utility `83/100`，正常 deny 与 intervention 均为 `0/40`，provider/harness error `0/140`。该运行 `complete/reportable=true`，但包含 checkpoint 续跑与 Judge 失败 trial 重试，不替代预注册主结果。
- AgentDojo 标准 DeepSeek V4 Pro：无防御官方 ASR `43/60`，玄鉴 `0/60`；正常 FPR `0/60`。GPT-5.5、Qwen 3.7 Plus 和 Qwen 3.5 Plus 的无防御官方 ASR 也为 `0/60`，只能作为当前选择集下的集成/Utility 证据，不能归因成防御收益。
- 六来源统一全量回归：7,227 条记录中 6,683 条投影可评分，544 条 unsupported；可评分攻击 6,424 条、正常 259 条。其结果属于已知公开集的 Command-Lab 映射回归，不是上游原生 ASR。
- 授权反事实：360/360 对授权边界判断正确；该集合由项目脚本受控生成，属于机制验证，不是外部未知集。
- 综合攻击回归，risk-tiered：520 条，攻击保护率 100.0%，高风险漏放率 0.0%，正常业务放行率 100.0%，误拦率 0.0%，harness error 0。
- 工具攻击专项，risk-tiered：320 条，工具攻击保护率 100.0%，高风险漏放率 0.0%，正常工具放行率 100.0%，误拦率 0.0%，harness error 0。
- LLM-Judge：当前推荐 `risk-tiered` 调度；full Judge 结果仍保留，用于说明全量语义复核的成本和误拦。
- 对比 full Judge：高风险漏放保持 0，误拦从 7 条降为 0 条，总耗时从约 135.2 分钟降到约 76.8 分钟。
- 当前 `8765` 是主展示入口；`8000` 仅作为历史离线实验和辅助入口。

## 2026-08-05 代码更新摘要

- TaskSpec 从“最新一句用户消息白名单”升级为“会话授权状态”，支持补充授权合并、闲聊不清空、普通偏好保留和显式禁止项继承。
- `outside TaskSpec` 拆分为低风险只读放行、授权不明确审批、未授权高风险阻断三类。
- 系统巡检、只读系统状态查询、普通记忆偏好和正常 Skill 写入的误拦路径已降低。
- 外部内容和工具返回新增轻量 IFC 分支记录，用于降低全局污染造成的连坐式误拦。
- LLM-Judge 接入用户消息、复杂工具调用、记忆写入和溯源扫描四个环节；`risk-tiered` 模式会跳过低风险健康检查和普通读操作。
- 低风险 shell 只读分类器已在 TaskSpec、检测、System Preflight 和 Judge 调度之间复用，系统健康检查口径保持一致。

## 保留原则

本目录保留最终报告、最新实验结果和必要复现材料。旧时间戳 benchmark 快照、早期草稿、重复说明文档已清理，避免答辩材料口径混乱。
本次 Qwen 3.6 Plus 七类风险完整中文报告：`qwen36plus_security_evaluation_zh.md`，Word 版本：`qwen36plus_security_evaluation_zh.docx`。
