# benchmark_risk_tiered

当前推荐 benchmark 结果目录。

证据口径：本目录是公开 benchmark 内容映射到 `/command-lab` 的开发回归留档，不是独立盲测或原生 AgentDojo/InjecAgent 运行。

这里保存 risk-tiered LLM-Judge 调度下的 840 条评测：

- `benchmark_cases.risk_tiered.jsonl`：综合攻击回归 520 条可执行映射样例。
- `benchmark_eval_results.risk_tiered.json`：综合攻击回归真实输出。
- `tool_attack_cases.risk_tiered.jsonl`：工具攻击专项 320 条可执行映射样例。
- `tool_attack_benchmark_results.risk_tiered.json`：工具攻击专项真实输出。
- `xuanjian_benchmark_risk_tiered_record.txt`：长文本留档。

`/command-lab` 的公开样例库优先读取本目录。
