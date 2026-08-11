# scripts

可复现实验和检查脚本目录。

| 脚本 | 用途 |
|---|---|
| `run_ebpf_runtime_ablation.mjs` | eBPF 运行时消融验证：无观察器、仅观察、观察并反哺、正常行为负样本。 |
| `run_benchmark_eval.py` | 综合攻击回归 benchmark 评测。 |
| `run_tool_attack_benchmark_eval.py` | 非提示注入工具攻击专项评测。 |
| `run_full_acceptance_tests.py` | 8765 插件完整功能验收。 |
| `run_competition_experiments.py` | 早期 8000 离线原型竞赛实验。 |
| `check_openclaw_ui.py` | 检查 8765 / 18789 页面可访问和基础 UI 状态。 |
| `check_ui_layout.py` | 早期 8000 页面布局检查。 |
| `demo_run.py` | 早期离线原型一键演示。 |
| `run_blind_evaluation.py` | 运行由独立 evaluator 提供、标签与检测输入隔离的盲测集，并输出可信指标与置信区间。 |
| `run_agentdojo_native.py` | 使用官方 AgentDojo 环境、工具与 evaluator 运行原生端到端适配；支持无密钥 doctor、plan 和 contract。 |
| `audit_agentdojo_side_effects.py` | 对 native private transcript 做三层攻击计分：官方 ASR、normalized exact sink、实际恶意 side-effect incidence；不回写官方 boolean。 |
| `replay_agentdojo_native.py` | 将已观察到的 no-defense 恶意 sink 以完全相同的 detector 输入离线回放到 competition bridge；不执行 AgentDojo 工具。 |
| `import_dataset_registry.py` | 将四列 Excel 数据源目录导入可追溯 Registry。 |
| `collect_benchmarks.py` | 浅克隆/安全审计六个 raw benchmark，并记录 commit、license 和哈希。 |
| `build_dataset.py` | 离线生成保留原文的统一 research JSONL。 |
| `validate_dataset.py` | 标记不完整样本并输出数据质量统计，不静默删除。 |
| `deduplicate_dataset.py` | 精确去重并为近似重复分组，保留完整审计集。 |
| `split_dataset.py` | 按模板/重复组切分，并生成 cross-dataset 留出集。 |
| `prepare_dataset.py` | 一键执行 build、validate、dedup、split 与 BenchmarkCase export。 |
| `run_dataset.py` | 严格关联 BenchmarkCase 与 ResearchCase，送入 `/api/lab/command`，按危险 sink 评分并输出 micro、来源/威胁 macro 和 proxy 保真声明；也可从已有结果离线重建报告，harness error 返回非零。 |

脚本输出不要直接放在本目录，统一写到 `reports/` 或 `runtime/`。

`run_blind_evaluation.py` 默认读取不会提交到 Git 的 `evaluation/blind/blind_holdout.jsonl`。真实盲测集应由未参与规则开发的人在发布提交冻结后放入；脚本记录数据集 SHA-256、提交版本、三次重复决策、ASR、保护率、FPR、Ask Rate、Utility、Overblocking、P50/P95/P99、Judge 调用、成本字段、稳定性和 Wilson 置信区间。

`run_agentdojo_native.py` 固定 `agentdojo==0.1.35`、`workspace v1.2.2`、20 个正常任务、20 个攻击 pair 和 3 个 seed。先运行 `--doctor`、`--plan`、`--contract`；其中 contract 使用 AgentDojo 官方 ground-truth pipeline 验证真实工具边界，但不发布 benchmark 分数。模型实跑的私有明细只写入已忽略的 `runtime/agentdojo/`。

`audit_agentdojo_side_effects.py` 和 `replay_agentdojo_native.py` 只消费已完成
run 的 private files，输出应放在 ignored `.tmp/`。Replay 默认关闭 Judge，表示
no-model-cost 的 deterministic competition-policy coverage；报告 native frozen
证据时应使用对应 release checkout 的 `--bridge`（例如
`.tmp/qwen-native-a6ee031/openclaw-plugin/scripts/agentdojo-policy-bridge.mjs`），
并核对输出中的 policy commit、bridge 和 dist commitments。它不是新的
end-to-end ASR。公开聚合结果只发布提交到 `reports/native_agentdojo/` 的 schema
校验 JSON，不发布原始工具参数或 transcript。

Audit 的 `--public-output` 会移除 private path、trial ID 和 sink atom 明细，只
保留三层计分、诊断计数与 source commitments；Replay 的同名选项执行相同的
脱敏投影。
