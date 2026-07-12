# scripts

可复现实验和检查脚本目录。

| 脚本 | 用途 |
|---|---|
| `run_benchmark_eval.py` | 综合攻击回归 benchmark 评测。 |
| `run_tool_attack_benchmark_eval.py` | 非提示注入工具攻击专项评测。 |
| `run_full_acceptance_tests.py` | 8765 插件完整功能验收。 |
| `run_competition_experiments.py` | 早期 8000 离线原型竞赛实验。 |
| `check_openclaw_ui.py` | 检查 8765 / 18789 页面可访问和基础 UI 状态。 |
| `check_ui_layout.py` | 早期 8000 页面布局检查。 |
| `demo_run.py` | 早期离线原型一键演示。 |
| `run_blind_evaluation.py` | 运行由独立 evaluator 提供、标签与检测输入隔离的盲测集，并输出可信指标与置信区间。 |
| `run_agentdojo_native.py` | 使用官方 AgentDojo 环境、工具与 evaluator 运行原生端到端适配；支持无密钥 doctor、plan 和 contract。 |

脚本输出不要直接放在本目录，统一写到 `reports/` 或 `runtime/`。

`run_blind_evaluation.py` 默认读取不会提交到 Git 的 `evaluation/blind/blind_holdout.jsonl`。真实盲测集应由未参与规则开发的人在发布提交冻结后放入；脚本记录数据集 SHA-256、提交版本、三次重复决策、ASR、保护率、FPR、Ask Rate、Utility、Overblocking、P50/P95/P99、Judge 调用、成本字段、稳定性和 Wilson 置信区间。

`run_agentdojo_native.py` 固定 `agentdojo==0.1.35`、`workspace v1.2.2`、20 个正常任务、20 个攻击 pair 和 3 个 seed。先运行 `--doctor`、`--plan`、`--contract`；其中 contract 使用 AgentDojo 官方 ground-truth pipeline 验证真实工具边界，但不发布 benchmark 分数。模型实跑的私有明细只写入已忽略的 `runtime/agentdojo/`。
