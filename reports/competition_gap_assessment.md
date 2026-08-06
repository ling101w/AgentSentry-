# 玄鉴 比赛要求完成度评估

更新时间：2026-07-03

## 总体判断

玄鉴 已满足题面要求的核心交付形态：有 OpenClaw 接入、有行为监督插件、有受控业务工具、有模型链路记录、有对抗样本和攻击脚本、有实时告警与阻断展示，也有公开 benchmark 和开启/关闭对比实验。

如果按冲高奖项标准，后续仍可增强 root 级 eBPF、更多真实业务样本和更完整的 MCP sidecar，但这些不是当前可提交性的阻断项。

## 要求对照

| 比赛要求 | 当前状态 | 证据 |
|---|---|---|
| 至少 3 类攻击场景 | 已超过 | `competition_report.md`、`agent_attack_scripts.md` |
| 模型对抗样本与越狱测试用例集 | 已有 | `adversarial_testset.jsonl` |
| 智能体攻击脚本 | 已有 | `agent_attack_scripts.md` |
| 可嵌入或旁路监督机制 | 已实现 | OpenClaw 插件 |
| 拦截工具调用、代码执行、文件访问 | 已实现 | `tool_decision`、System Preflight |
| 实时审计与异常判定 | 已实现 | `8765/records`、`8765/security-screen` |
| 允许/拒绝/询问策略 | 已实现 | observe/approval/block，allow/ask/deny |
| 开源智能化应用 | 已实现 | OpenClaw |
| 邮件、读写文件、API 业务工具 | 已实现 | `/command-lab` |
| 模型调用链路安全监控插件 | 已实现 | message、tool decision、tool result 记录 |
| 基座模型检测或过滤原型 | 已实现 | OpenAI-compatible LLM-Judge；历史 full/risk-tiered 映射回归已留档 |
| 实时展示告警或阻断记录 | 已实现 | 大屏 Live Alerts、records |

## 高分亮点

- 使用公开 benchmark：10 类来源、840 条 `/command-lab` 映射回归；不能当作独立盲测或原生 Benchmark。
- 不完全依赖 LLM：主要由确定性策略、信任标签、污点传播、ABAC、语义动作图和系统预执行控制。
- LLM-Judge 可按 full、risk-tiered、off 调度；最新推荐结果采用 risk-tiered，在保持 0 漏放的同时降低误拦和延迟。
- 反应试化：新增语义动作图、编码规范化、能力声明一致性和行为基线。
- 正常业务可通过：risk-tiered 复测中综合回归正常放行率 100.0%，工具专项正常放行率 100.0%；full Judge 下暴露出的误拦已在旧留档 TXT 中保留，作为生产优化对照。
- 数据展示真实：8765 页面直接读取 records 和聚合接口。

## 剩余限制

| 项目 | 状态 | 影响 |
|---|---|---|
| eBPF 内核观测 | 受权限限制 unavailable | 不影响应用层执行前阻断 |
| 真实 SMTP/外部系统 | 使用本机受控 outbox | 避免实验误发，适合比赛受控演示 |
| MCP sidecar | 当前为 OpenClaw 插件内联拦截 | 已能满足题目“嵌入或旁路”中的嵌入形态 |
| 生产误判率 | 历史映射回归未出现误拦；样本参与过规则开发，不能外推生产 FPR | 需要独立盲测和至少 200 条人工审查的正常业务样本 |

## 建议答辩说法

> 本作品已经完成从攻击样本构造、工具调用拦截、记忆防护、模型链路监控到实时展示的闭环。系统把攻击抽象成信任标签、数据流、任务授权和工具副作用；公开 benchmark 仅用于开发回归，独立盲测与原生 AgentDojo 单独报告。

最新推荐说法：

> 在 840 条公开映射回归中，risk-tiered 留档结果为攻击保护率 100%、高风险漏放 0、正常样例误拦 0；这些数字只说明已知映射集没有退化，不代表未知攻击泛化或生产 FPR。独立结果以 `evaluation/blind` 协议另行报告。
