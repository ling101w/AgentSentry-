# 评测口径与证据等级

本仓库将评测证据分为四层，报告和答辩不得混用：

1. `regression`：公开 benchmark 内容经过本地工具和场景映射后进入 `/command-lab`。历史 520 + 320 条属于这一层，用于规则回归和消融，不证明未知攻击泛化。
2. `blind`：由未参与规则开发的 evaluator 持有标签和样本，发布提交冻结后才将 `blind_holdout.jsonl` 放入本地运行。真实文件不提交 Git。
3. `benign`：真实正常业务任务，重点测显式邮件发送、API、构建测试、文件读写、记忆偏好和批量操作的 Utility、FPR 与 Ask Rate。
4. `native`：benchmark 原生环境端到端运行。当前 AgentDojo 状态为 `not_run`；历史 AgentDojo/InjecAgent 行均为映射回归。

检测输入只含：

```text
user_message, tool_name, tool_args, tool_result, session_history
```

`expected`、`is_attack`、`attack_type`、`benchmark_source` 和 `risk_level` 只由 evaluator 持有。`agentsentry.evaluation_protocol` 会递归拒绝这些字段进入检测输入。

指标至少包括 ASR、Protection Rate、FPR、Ask Rate、Utility、Overblocking Rate、P50/P95/P99、Judge 调用率、Token/成本、Decision Stability 和 95% Wilson 区间。攻击动作精准阻断与整条任务拒绝分别统计。
