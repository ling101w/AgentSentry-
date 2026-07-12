# 玄鉴 Benchmark 适配评测报告

生成时间：2026-07-02T20:23:42.757995+00:00
评测入口：`http://127.0.0.1:8765/api/lab/command`

> 证据口径：公开 benchmark 内容经本地映射后进入 `/command-lab`。本报告是开发回归，不是独立盲测或原生 AgentDojo/InjecAgent 结果。

## 结论摘要

- 总用例：520，攻击用例：441，正常用例：79。
- 攻击保护率：100.0%；未阻断高风险放行率：0.0%。
- 正常业务放行率：100.0%；正常请求误拦率：0.0%。
- 中位延迟：5864.55 ms；P95 延迟：12706.18 ms。
- LLM-Judge 抽样：{"default": 520}。`on` 表示该样例调用语义裁决，`off` 表示只走确定性规则、污点/信任传播和系统策略。

## 运行画像

xuanjian-risk-tiered-20260703

## Benchmark 取舍

- RedTeamCUA: downloaded，使用 191 条。 原因/备注：已映射到本地安全实验台。 链接：https://github.com/OSU-NLP-Group/RedTeamCUA
- MSB: downloaded，使用 80 条。 原因/备注：已映射到本地安全实验台。 链接：https://github.com/dongsenzhang/MSB
- MCPSecBench: downloaded，使用 9 条。 原因/备注：已映射到本地安全实验台。 链接：https://github.com/AIS2Lab/MCPSecBench
- MemoryGraft: downloaded，使用 69 条。 原因/备注：已映射到本地安全实验台。 链接：https://github.com/Jacobhhy/Agent-Memory-Poisoning
- AgentDojo: downloaded，使用 65 条。 原因/备注：AgentDojo directly targets prompt-injection attacks against tool-using agents, so its user/injection task pairs are mapped to 玄鉴 external-content and tool-use scenarios. 链接：https://github.com/ethz-spylab/agentdojo
- InjecAgent: downloaded，使用 106 条。 原因/备注：InjecAgent provides tool-response injection cases where malicious instructions are embedded in normal tool outputs, matching the external content injection threat model. 链接：https://github.com/uiuc-kang-lab/InjecAgent
- ToolShield / MT-AgentRisk: method_reference_only，使用 0 条。 原因/备注：ToolShield is useful for safety-tree and multi-turn methodology, but its MT-AgentRisk task data is hosted separately on Hugging Face and was not available as a direct local dataset in this run. 链接：https://github.com/CHATS-lab/ToolShield
- PINT / JailbreakBench: method_reference_only，使用 0 条。 原因/备注：PINT is primarily a prompt-injection detector benchmark and JailbreakBench is a model jailbreak behavior set; both are useful as detector/jailbreak references, but they do not directly exercise OpenClaw tool calls in this run. 链接：https://github.com/lakeraai/pint-benchmark

## 按来源统计

| 来源 | 用例 | 攻击 | 正常 | 保护率 | 漏放行率 | 正常放行率 | 误拦率 | 中位延迟 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AgentDojo | 65 | 55 | 10 | 100.0% | 0.0% | 100.0% | 0.0% | 5797.8 |
| InjecAgent | 106 | 106 | 0 | 100.0% | 0.0% | 0.0% | 0.0% | 5774.67 |
| MCPSecBench | 9 | 9 | 0 | 100.0% | 0.0% | 0.0% | 0.0% | 6382.64 |
| MSB | 80 | 80 | 0 | 100.0% | 0.0% | 0.0% | 0.0% | 5927.16 |
| MemoryGraft | 69 | 9 | 60 | 100.0% | 0.0% | 100.0% | 0.0% | 5035.9 |
| RedTeamCUA | 191 | 182 | 9 | 100.0% | 0.0% | 100.0% | 0.0% | 6338.2 |

## 按攻击类别统计

| 类别 | 用例 | 攻击 | 正常 | 保护率 | 漏放行率 | 正常放行率 | 误拦率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Availability/Resource/CPU | 11 | 11 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Availability/Resource/Disk | 6 | 6 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Availability/Resource/Service | 16 | 16 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Confidentiality/Send/Normal | 17 | 17 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Confidentiality/Send/Privacy | 15 | 15 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Confidentiality/Send/System | 8 | 8 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Delete/Normal | 16 | 16 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Delete/Privacy | 16 | 16 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Delete/System | 16 | 16 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Modify_content_or_name/Normal | 16 | 16 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Modify_content_or_name/Privacy | 14 | 14 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Modify_content_or_name/System | 6 | 6 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Modify_permission/Normal | 7 | 7 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Modify_permission/Privacy | 9 | 9 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| Integrity/Modify_permission/System | 9 | 9 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_banking_benign_task | 3 | 0 | 3 | 0.0% | 0.0% | 100.0% | 0.0% |
| agentdojo_banking_external-email-hidden | 4 | 4 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_banking_malicious-skill | 12 | 12 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_slack_benign_task | 2 | 0 | 2 | 0.0% | 0.0% | 100.0% | 0.0% |
| agentdojo_slack_external-email-hidden | 2 | 2 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_slack_external-web-hidden | 9 | 9 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_travel_benign_task | 4 | 0 | 4 | 0.0% | 0.0% | 100.0% | 0.0% |
| agentdojo_travel_external-email-hidden | 7 | 7 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_travel_external-web-hidden | 5 | 5 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_workspace_benign_task | 1 | 0 | 1 | 0.0% | 0.0% | 100.0% | 0.0% |
| agentdojo_workspace_external-email-hidden | 14 | 14 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_workspace_external-web-hidden | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| agentdojo_workspace_pdf-stego | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| benign_memory_experience | 60 | 0 | 60 | 0.0% | 0.0% | 100.0% | 0.0% |
| benign_web_os_task | 9 | 0 | 9 | 0.0% | 0.0% | 100.0% | 0.0% |
| injecagent_data-security-harm | 21 | 21 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| injecagent_financial-data | 12 | 12 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| injecagent_financial-harm | 13 | 13 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| injecagent_others | 21 | 21 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| injecagent_physical-data | 20 | 20 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| injecagent_physical-harm | 19 | 19 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_false_error | 8 | 8 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_name_overlap | 5 | 5 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_out_of_scope_parameter | 12 | 12 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_preference_manipulation | 5 | 5 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_preference_manipulation-out_of_scope_parameter | 9 | 9 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_preference_manipulation-simulated_user | 5 | 5 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_prompt_injection | 6 | 6 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_prompt_injection-false_error | 6 | 6 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_prompt_injection-simulated_user | 8 | 8 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_search_term_deception | 4 | 4 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_simulated_user | 5 | 5 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcp_tool_transfer | 7 | 7 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Data Exfiltration | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Indirect Prompt Injection | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Package Name Squatting(Server Name) | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Prompt Injection | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Rug Pull | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Sandbox Escape | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Tool Misuse via Confused AI | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Tool Poisoning Attack | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| mcpsecbench_Tool Shadowing Attack | 1 | 1 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |
| memory_graft_poisoned_experience | 9 | 9 | 0 | 100.0% | 0.0% | 0.0% | 0.0% |

## 评测说明

- 本报告使用公开 benchmark 的任务、攻击类型和 payload 模板作为输入来源，再映射到 玄鉴 的本地实验工具链。
- 外部邮件、网页、PDF、图片、MCP 劫持、Skill、记忆写入均通过 8765 实验台产生真实审计记录、裁决记录和工具结果。
- 浏览器来源的 shell 命令不会真正执行；系统仍会对命令进行真实策略裁决，避免 benchmark payload 破坏主机。
- LLM-Judge 可按样例强制 on/off，也可使用 default 保留服务端调度；`default` 表示由当前运行配置决定，例如 risk-tiered 只在风险路径调用语义裁决。
- ToolShield / MT-AgentRisk 在本轮主要作为方法参考；其完整 365 条任务数据需要单独从 Hugging Face 获取后再导入。
