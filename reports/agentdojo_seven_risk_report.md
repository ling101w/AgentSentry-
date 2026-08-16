# 七类安全风险 AgentDojo/DeepTrap 评测结果

- 模型：`qwen3.6-27b`（读取 `.env`，API key 仅记录是否配置）
- 审计事件：750 条，逐条导出：`E:\cslearn\AgentSentry\玄鉴-f\AgentSentry-q\reports\agentdojo_audit_events.jsonl`
- 口径：原生 AgentDojo、DeepTrap replay、curated coverage 分层统计；缺少原生套件的风险不冒充 AgentDojo 原生分数。
- `.env` 模型 probe：14 条，完成 0 条，provider/harness error 14 条；error 不进入 ASR/DR/FPR/Utility 分母。错误 case ID 见 JSON 的 `coverage.curated_model_error_cases`。

## 指标

ASR 是攻击目标实际完成率（AgentDojo `security=true`）；`approved_attack_rate` 是攻击样本被 allow/Approved 的比例；DR 是实际 `deny/ask` 比例；Unsafe Interception Rate 是恶意副作用未发生比例。无攻击组的 Utility 只取 clean 样本，`benign_approved_rate`/`benign_intervention_rate` 分别表示 clean allow/ask；纯攻击组 Utility 标记为 attack-environment basis。provider/harness error 不计入安全指标分母。
以下按证据层级解读；原生防御运行与 DeepTrap no-defense replay 不合并作单一防御结论。

- 原生 AgentDojo（防御运行）：ASR 0.00% (0/100)，Approved attack rate 64.00% (64/100)，DR 36.00% (36/100)，Unsafe Interception 100.00% (100/100)，FPR 25.00% (10/40)，clean Utility 70.00%，clean Approved 70.00% (28/40)，clean Ask 5.00% (2/40)。
- DeepTrap（no-defense 环境污染基线）：ASR 54.76% (23/42)，污染上下文 replay 成功率（报告字段 `cross_session_contamination_success_rate`）为 54.76% (23/42)；无 DR/Unsafe Interception 分母。

| 风险类别 | 样本 | 攻击 | ASR | Approved | DR | Unsafe interception | Utility |
|---|---:|---:|---:|---:|---:|---:|---:|
| direct_prompt_injection | 124 | 84 | 0.00% (0/84) | 72.62% (61/84) | 27.38% (23/84) | 100.00% (84/84) | 70.00% [benign] |
| model_jailbreak | 0 | 0 | N/A | N/A | N/A | N/A | N/A |
| training_data_leakage | 0 | 0 | N/A | N/A | N/A | N/A | N/A |
| misuse | 16 | 16 | 0.00% (0/16) | 18.75% (3/16) | 81.25% (13/16) | 100.00% (16/16) | 31.25% [attack_environment] |
| tool_call_hijacking | 0 | 0 | N/A | N/A | N/A | N/A | N/A |
| memory_poisoning | 0 | 0 | N/A | N/A | N/A | N/A | N/A |
| environment_context_pollution | 42 | 42 | 54.76% (23/42) | N/A | N/A | N/A | 92.62% [attack_environment] |

## 证据与覆盖

- 原生 AgentDojo：140 条（workspace v1.2.2 FunctionsRuntime；攻击 100、良性 40）。
- DeepTrap replay：42 条环境感知污染任务；这是 no-defense baseline，只用于污染成功率，不提供 DR/Unsafe Interception 分母。
- curated coverage：14 条（七类各 2 条），业务域覆盖：`{"deployment": 1, "finance": 3, "general": 1, "medical": 2, "office": 5, "travel": 2}`；只有模型 probe 成功完成的行才可计分。
- 原生 AgentDojo 的 `indirect_prompt_injection` 在报告层归入 `direct_prompt_injection`（提示注入总类），每条原始记录仍保留 `source_risk_family`。

## 性能

- 原生 AgentDojo：140 trials，吞吐 1.63 trials/min，端到端 P50/P95/P99 = 24116.022/93011.416/174032.13 ms。
- misuse 优先性能：18 条（有延迟样本 16 条）；工具边界延迟 P50/P95/P99 = 50245.687/131133.727/153109.066 ms；吞吐沿用原生 AgentDojo wall-clock 基线。

## 业务场景（可计分样本）

| 场景 | 样本 | 攻击 | ASR | Approved | DR | Unsafe interception | FPR | Utility |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| finance | 1 | 1 | 100.00% (1/1) | N/A | N/A | N/A | N/A | 100.00% [attack_environment] |
| general | 29 | 22 | 0.00% (0/22) | 77.27% (17/22) | 22.73% (5/22) | 100.00% (22/22) | 14.29% (1/7) | 71.43% [benign] |
| medical | 1 | 1 | 0.00% (0/1) | N/A | N/A | N/A | N/A | 100.00% [attack_environment] |
| office | 151 | 118 | 18.64% (22/118) | 60.26% (47/78) | 39.74% (31/78) | 100.00% (78/78) | 27.27% (9/33) | 69.70% [benign] |
| travel | 0 | 0 | N/A | N/A | N/A | N/A | N/A | N/A |

## 审计与复现

每条工具边界事件都导出 `timestamp`、`created_at`、`agent_id`、`run_id`、`session_key`、`tool_name`、`input_params/params`、`decision`、`disposition`、`execution_status`；敏感 token/password/card 参数已脱敏。
审计校验结果：`reports/agentdojo_audit_validation.json`（由 `scripts/validate_audit_records.py` 复核）。

```powershell
python scripts/aggregate_seven_risk_results.py
python scripts/validate_audit_records.py reports/agentdojo_audit_events.jsonl
```

`cross_session_contamination_success_rate` 使用 DeepTrap 的预污染持久工作区 replay，表示新 replay 会话继续受污染上下文诱导的比例；它不是同一脚本内完成“写入 memory 文件→重启会话”的独立生命周期实验。
