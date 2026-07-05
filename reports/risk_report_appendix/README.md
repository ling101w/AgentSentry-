# 安全风险分析报告附录材料

本目录用于存放安全风险分析报告末尾附录所需材料，内容按老师建议拆分为测试用例集、自动化攻击脚本、原始审计日志和复现佐证材料说明。

## 目录结构

| 路径 | 内容 |
|---|---|
| `test_cases/three_attack_scenarios_test_cases.md` | 三类攻击场景测试用例集，样例来自已映射的公开 benchmark。 |
| `scripts/prompt_injection_attack.py` | 提示注入场景自动化攻击脚本，调用 OpenClaw 本地实验台接口并生成日志。 |
| `scripts/tool_hijack_attack.py` | 工具调用劫持场景自动化攻击脚本，调用 OpenClaw 本地实验台接口并生成日志。 |
| `scripts/memory_poison_attack.py` | 记忆中毒场景自动化攻击脚本，调用 OpenClaw 本地实验台接口并生成日志。 |
| `logs/` | 攻击脚本运行后生成的原始 JSON 审计日志。 |
| `evidence/README.md` | 漏洞复现佐证材料说明，列出建议截图、日志和留存命名方式。 |

## 运行方式

默认实验台地址为 `http://127.0.0.1:8765`。可直接执行完整三类攻击样例：

```bash
python3 reports/risk_report_appendix/scripts/prompt_injection_attack.py
python3 reports/risk_report_appendix/scripts/tool_hijack_attack.py
python3 reports/risk_report_appendix/scripts/memory_poison_attack.py
```

脚本会从 `reports/benchmark_risk_tiered/benchmark_cases.risk_tiered.jsonl` 和 `reports/benchmark_risk_tiered/tool_attack_cases.risk_tiered.jsonl` 按攻击类型读取完整映射样例，再把结果写入 `reports/risk_report_appendix/logs/`。脚本只面向受控实验台提交样例，邮件、接口和命令类动作均由本地实验环境记录裁决和工具意图，不真实外发数据、不破坏主机。

完整运行数量分别为：提示注入攻击 362 条、工具调用劫持攻击 409 条、记忆中毒攻击 69 条。现场快速复现可使用 `--limit` 参数，例如：

```bash
python3 reports/risk_report_appendix/scripts/prompt_injection_attack.py --limit 5
python3 reports/risk_report_appendix/scripts/tool_hijack_attack.py --limit 5
python3 reports/risk_report_appendix/scripts/memory_poison_attack.py --limit 5
```

`logs/` 目录中保留的是已运行生成的复现日志；完整日志可由上述脚本重新全量生成。
