# 漏洞复现佐证材料说明

本目录用于放置安全风险分析报告附录中的复现佐证截图和说明材料。证据应尽量使用已经产生的真实文件和真实运行结果，不只写“证据类型”。当前附录已生成三类脚本和三份原始日志，截图可围绕脚本内容、终端运行结果和 JSON 日志内容截取。

## 已生成的真实证据

| 证据类型 | 文件 | 说明 |
|---|---|---|
| 提示注入攻击脚本 | `../scripts/prompt_injection_attack.py` | 从 `benchmark_cases.risk_tiered.jsonl` 读取 RedTeamCUA、AgentDojo 和 InjecAgent 的完整提示注入映射样例。 |
| 工具调用劫持攻击脚本 | `../scripts/tool_hijack_attack.py` | 从 `benchmark_cases.risk_tiered.jsonl` 读取 MSB、MCPSecBench，并从 `tool_attack_cases.risk_tiered.jsonl` 读取 AgentDefense-Bench、BashArena、ToolEmu 和 AgentHarm 的完整工具攻击映射样例。 |
| 记忆中毒攻击脚本 | `../scripts/memory_poison_attack.py` | 从 `benchmark_cases.risk_tiered.jsonl` 读取 MemoryGraft 的完整污染经验和正常经验样例。 |
| 提示注入原始日志 | `../logs/prompt_injection_attack_log.json` | 已生成 5 条记录，首条为 `agentdojo:workspace:UserTask7:InjectionTask0`。 |
| 工具调用劫持原始日志 | `../logs/tool_hijack_attack_log.json` | 已生成 6 条记录，首条为 `agentdefense:toolpoisoning-backdoor-042-conditional`。 |
| 记忆中毒原始日志 | `../logs/memory_poison_log.json` | 已生成 8 条记录，首条为 `memorygraft-poison:exp_poison_010`。 |

## 建议截图清单

| 编号 | 建议文件名 | 说明 |
|---|---|---|
| E01 | `prompt_injection_script_cases.png` | 打开 `prompt_injection_attack.py`，截取 `PROMPT_INJECTION_SOURCES` 和 `load_cases` 逻辑。 |
| E02 | `prompt_injection_run_terminal.png` | 终端运行 `python3 reports/risk_report_appendix/scripts/prompt_injection_attack.py --limit 5` 后显示保存记录，或全量运行后显示 362 条记录。 |
| E03 | `prompt_injection_raw_log.png` | 打开 `prompt_injection_attack_log.json`，截取 `case_id`、`source`、`category`、`scenario`、`run_id` 字段。 |
| E04 | `tool_hijack_script_cases.png` | 打开 `tool_hijack_attack.py`，截取 `TOOL_HIJACK_SOURCES_IN_COMPREHENSIVE` 和 `load_cases` 逻辑。 |
| E05 | `tool_hijack_raw_log.png` | 打开 `tool_hijack_attack_log.json`，截取 AgentDefense-Bench、BashArena 或 ToolEmu 样例的 `source`、`category`、`params`、`run_id`。 |
| E06 | `memory_poison_script_cases.png` | 打开 `memory_poison_attack.py`，截取 `MEMORY_SOURCE` 和 `load_cases` 逻辑。 |
| E07 | `memory_poison_raw_log.png` | 打开 `memory_poison_log.json`，截取 MemoryGraft 污染经验和正常经验记录。 |
| E08 | `appendix_file_tree.png` | 截取 `reports/risk_report_appendix` 目录树，证明脚本、日志、用例集和说明文件均已整理。 |
| E09 | `optional_command_lab_or_audit_ui.png` | 可选：截取业务测试台或运行记录页面，用于展示样例进入系统后的审计记录。 |

## 日志对应关系

| 攻击场景 | 脚本 | 原始日志 |
|---|---|---|
| 提示注入攻击 | `../scripts/prompt_injection_attack.py` | `../logs/prompt_injection_attack_log.json` |
| 工具调用劫持攻击 | `../scripts/tool_hijack_attack.py` | `../logs/tool_hijack_attack_log.json` |
| 上下文记忆中毒与环境感知污染攻击 | `../scripts/memory_poison_attack.py` | `../logs/memory_poison_log.json` |

## 留存要求

截图应覆盖攻击样本、脚本执行、原始日志和复现编号四个层面。日志文件应保留脚本原始输出，避免手工修改。涉及邮箱、密钥、令牌或个人信息的内容只能使用模拟值，不应放入真实凭据。
