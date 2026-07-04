# 玄鉴文档从这里开始

更新时间：2026-07-03

参赛作品名称：

> 玄鉴：面向智能体工具调用链的实时行为监督与风险拦截系统

当前仓库和插件内部仍使用 `AgentSentry` 作为工程代码名，这是历史命名；展示、报告和答辩统一使用“玄鉴”。

## 先看哪几份

如果只想快速理解项目，按这个顺序看：

1. `reports/START_HERE.md`：当前入口页，解释文档和 benchmark 文件怎么找。
2. `reports/README.md`：完整文档索引和最新指标。
3. `reports/competition_report.md`：正式安全风险分析与行为监督报告。
4. `reports/system_functionality.md`：系统有哪些真实功能、数据从哪里来、哪些限制要如实说明。
5. `reports/technical_design_and_algorithms.md`：TaskSpec、污点传播、Memory Guard、LLM-Judge、ABAC 和系统预执行的算法流程。
6. `reports/project_name_and_benchmark_summary.md`：公开 benchmark 跑了哪些、结果是什么、能说明什么。
7. `reports/demo_and_reproduction.md`：答辩演示顺序和复现实验命令。

如果准备答辩，重点看 `competition_report.md`、`feature_algorithm_talk_track.md`、`project_name_and_benchmark_summary.md`。

## Benchmark 文件在哪

目录里有三类文件，作用不一样：

| 类型 | 位置 | 说明 |
|---|---|---|
| 公开 benchmark 原始仓库 | `third_party/benchmarks/` | 下载下来的公开项目源文件，格式各不相同，通常包含原始任务、攻击载荷、工具定义或评测脚本。 |
| 玄鉴可执行映射样例 | `reports/benchmark_risk_tiered/benchmark_cases.risk_tiered.jsonl` 和 `reports/benchmark_risk_tiered/tool_attack_cases.risk_tiered.jsonl` | 把公开 benchmark 转成 `/command-lab` 能运行的统一输入。每行都有 `case_id`、`source`、`category`、`command`、`tool`、`params`、`expectation`。 |
| 玄鉴历史评测输出 | `reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json` 和 `reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json` | 上次全量实验的真实结果，包含玄鉴裁决、风险分数、决策序列、是否误拦或漏放、耗时。 |

原始 benchmark 一般不会自带 OpenClaw 的回答。OpenClaw/玄鉴 的输出是我们运行实验后生成的，保存在结果 JSON 里。

## 已接入哪些 Benchmark

综合攻击回归 520 条：

- `InjecAgent`：工具返回注入、外部响应污染。
- `RedTeamCUA`：计算机使用智能体的网页到系统攻击、间接注入、泄露和破坏。
- `MemoryGraft`：记忆投毒与正常记忆写入。
- `MCPSecBench`：MCP 工具投毒、Shadowing、沙箱逃逸等。
- `MSB`：MCP 名称混淆、越权参数、模拟用户响应。
- `AgentDojo`：工具型智能体提示注入。

工具攻击专项 320 条：

- `AgentHarm`：直接恶意多工具任务、欺诈、网络犯罪、虚假信息等。
- `AgentDefense-Bench`：MCP 工具投毒、恶意参数、响应操纵和正常基线。
- `BashArena`：Linux 命令、敏感文件、恶意脚本、防火墙、sudo 等系统风险。
- `ToolEmu`：真实工具调用场景中的有害工具选择和参数风险。

## 在网页上怎么逐条测试

打开：

```text
http://43.153.201.180:8765/command-lab
```

左侧“公开样例库”可以：

- 按“样例集”选择综合攻击回归或工具攻击专项。
- 按“来源”选择 RedTeamCUA、MSB、AgentDefense-Bench 等。
- 按“类别”筛选具体攻击类型。
- 用关键词搜索 `case_id`、工具名、payload 或类别。
- 点“载入样例”把输入填入测试请求。
- 点“运行样例”走真实玄鉴链路，并在右侧四域一环数据流里看到裁决、告警和工具结果。

页面展示的“上次结果”来自 `reports/benchmark_risk_tiered/*results*.json`。再次点击运行时，会生成新的真实运行记录，不会复用旧结果。

## 当前最新指标

`risk-tiered` 模式下，两批 benchmark 共 840 条：

- 攻击/期望保护：711 条。
- 正常/期望放行：129 条。
- 高风险漏放：0 条。
- 误拦：0 条。
- Harness error：0 条。

这个结果说明玄鉴对高风险工具调用、数据外泄、MCP 工具攻击、记忆投毒、RCE/命令类风险拦截稳定；同时 risk-tiered 调度比 full LLM-Judge 更适合生产化展示，因为它只在风险路径调用 DeepSeek Judge。
