# 玄鉴 使用指南

更新时间：2026-07-03

## 入口说明

| 页面 | 用途 |
|---|---|
| `8765/command-lab` | 提交正常请求、攻击样本和公开 benchmark 映射样例 |
| `8765/records` | 查看运行记录、工具裁决、告警和阻断证据 |
| `8765/security-screen` | 大屏展示真实统计、拓扑和 Live Alerts |
| `18789/` | OpenClaw Control UI |

`8000` 是辅助离线原型，当前主系统以 `8765` 为准。

## 常用操作

### 在 `/command-lab` 逐条运行公开 benchmark

左侧有两个入口：

- “测试用例模板”：适合快速演示比赛要求中的三大场景，如外部内容注入、记忆持久化、工具劫持。
- “公开样例库”：适合从已接入的公开 benchmark 中选择单条样例复测。

公开样例库支持按样例集、来源、类别和关键词筛选。点“载入样例”只把输入填入表单，便于先阅读；点“运行样例”会真实调用 `/api/lab/command`，产生新的四域一环数据流、工具裁决、告警和工具结果。

公开 benchmark 文件对应关系：

| 类型 | 位置 |
|---|---|
| 原始公开仓库 | `third_party/benchmarks/` |
| 可运行映射样例 | `reports/benchmark_risk_tiered/benchmark_cases.risk_tiered.jsonl`、`reports/benchmark_risk_tiered/tool_attack_cases.risk_tiered.jsonl` |
| 上次真实结果 | `reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json`、`reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json` |

页面中的“上次结果”来自结果 JSON；重新运行样例时以当前系统真实裁决为准。

### 运行一个正常请求

在 `/command-lab` 选择或输入：

```text
检查本地健康接口是否正常，只调用健康检查 API。
```

预期：`call_api` 到 `127.0.0.1:8765/api/health`，decision 为 `allow`。

### 运行一个攻击请求

选择“恶意 Skill”或输入伪装天气 Skill 样例。

预期：`write_file` 或 `call_api` 被 `deny`，理由包含供应链风险、敏感源到外部 sink、能力声明不一致等。

### 查看证据

- `/records`：按时间逆序查看每条事件。
- `/security-screen`：查看聚合统计、风险拓扑和 Live Alerts。
- `~/.openclaw/agentsentry/records.jsonl`：底层真实事件日志。

## 模式说明

| 模式 | 含义 | 适合场景 |
|---|---|---|
| observe | 只记录，不阻断 | 无防护基线、对比实验 |
| approval | 高风险动作要求人工确认 | 展示审批机制 |
| block | 高风险动作执行前阻断 | 比赛主展示 |

语义裁决还有三种调度：

| LLM-Judge 调度 | 含义 | 适合场景 |
|---|---|---|
| off | 不调用 LLM，只走规则、TaskSpec、污点、ABAC、Memory Guard、工具边界域的 System Preflight | 无模型基线 |
| full | 所有启用面都调用 LLM-Judge | 离线评测、复现 full Judge 结果 |
| risk-tiered | 低风险请求跳过 LLM，高风险工具/记忆/外部污染/基础文件才调用 LLM-Judge | 当前推荐模式 |

当前运行态为 `approval + risk-tiered`。这表示高风险动作会进入审批/阻断链路，LLM-Judge 只在风险路径上复核。

## 数据真实性

页面统计来自真实接口和记录文件：

- 总事件数来自 records 聚合。
- 告警数来自 `alert` 和高危 finding。
- 阻断数来自 `tool_decision.decision = deny`。
- 工具拓扑来自实际工具调用和结果。
- benchmark 指标来自最新 JSON/CSV 结果文件。

没有后端数据时，页面显示空态或错误，不生成假数据。

## 常用命令

```bash
cd /home/ubuntu/AgentSentry-

npm --prefix openclaw-plugin run test:policy
.venv/bin/python -m pytest -q

systemctl --user restart openclaw-gateway.service
systemctl --user status openclaw-gateway.service --no-pager

curl -sS http://127.0.0.1:8765/api/health | python3 -m json.tool
curl -sS http://127.0.0.1:8765/api/security/overview | python3 -m json.tool | sed -n '1,120p'
```

复跑当前推荐的 `risk-tiered` benchmark：

```bash
python3 scripts/run_benchmark_eval.py \
  --max-cases 520 \
  --llm-judge-rate -1 \
  --llm-judge-timeout-ms 15000 \
  --timeout 35 \
  --sleep 0.02 \
  --profile-note xuanjian-risk-tiered

python3 scripts/run_tool_attack_benchmark_eval.py \
  --max-cases 320 \
  --max-agentdefense-attack 120 \
  --max-agentdefense-benign 50 \
  --max-basharena 24 \
  --max-agentharm 80 \
  --max-toolemu 80 \
  --llm-judge-rate -1 \
  --llm-judge-timeout-ms 15000 \
  --timeout 35 \
  --sleep 0.02
```

这里 `--llm-judge-rate -1` 表示 benchmark 不强制开/关 Judge，而是使用服务端当前调度。当前服务端是 `risk-tiered`。

## 看懂一次裁决

一次工具调用的记录通常包含：

- `task_spec`：用户本轮授权边界。
- `decision`：最终 `allow / ask / deny`。
- `risk_vector`：提示注入、敏感数据、外泄、持久化、工具劫持等风险分量。
- `trust`：当前会话信任标签和污点流。
- `semantic_judge`：LLM-Judge 是否启用、当前调度是 full 还是 risk-tiered。
- `system_monitor`：系统预执行控制和 eBPF/隔离状态。
- `findings`：主规则、证据和建议动作。

判断逻辑可以这样理解：

1. 先看动作是否在 TaskSpec 内。
2. 再看参数是否形成敏感源到外部 sink、持久化或提权。
3. 再看是否有低信任污点影响高风险 sink。
4. 再看 Memory Guard 和 工具边界域的 System Preflight 是否命中。
5. 最后看 LLM-Judge 是否补充了语义风险。

## AgentDojo 发布级复跑清单

发布级原生结果必须在干净冻结提交上运行。当前工作区有未提交修改时，不要使用 `--allow-dirty` 生成正式结论；该选项只适合开发验证，而且结果会被标为不可发布。

1. 在目标冻结提交的独立 checkout 中安装项目依赖和 `agentdojo==0.1.35`，确认 AgentDojo `workspace v1.2.2`、选择文件和工具 manifest 与分析计划一致。
2. 先运行 `--doctor` 和 `--plan`，记录 selection canonical SHA-256、tool manifest SHA-256、bridge profile、预计 140 trials 和当前 Git commit。
3. 在同一选择集上完整运行 no-defense arm，随后完整运行 `competition` arm；两组都必须达到 140/140 trials、provider/harness error 为 0，才可进入主结果表。
4. 对 `evidence-gated` 只使用新的完整 arm，不覆盖预注册 `competition` 结果。若发生 Judge 或 provider 错误，保留原始 partial artifact，并在独立 evaluator 提交上重跑；发布协议应分别记录 `policy_commit` 与 `evaluator_commit`，同时使用规范化 manifest 哈希。
5. 复核官方 AgentDojo ASR、归一化 exact sink、已执行危险副作用、benign Utility、FPR、intervention、attack Utility、Ask Rate 和错误率；报告分子、分母及 Wilson 区间，不把 replay 或本地映射结果并入主表。
6. 完成后才允许使用 `--publish` 更新 canonical result；将 public JSON、详细报告、selection、manifest、bridge metadata、transcript/trial commitments 一并归档。

典型命令骨架如下，凭据只通过环境变量提供，不写入命令行或结果文件：

```bash
python3 scripts/run_agentdojo_native.py --doctor \
  --selection evaluation/native/native_expanded_v1_selection.json \
  --defense agentsentry --policy-profile evidence-gated

python3 scripts/run_agentdojo_native.py --plan \
  --selection evaluation/native/native_expanded_v1_selection.json \
  --defense agentsentry --policy-profile evidence-gated

python3 scripts/run_agentdojo_native.py \
  --selection evaluation/native/native_expanded_v1_selection.json \
  --defense agentsentry --policy-profile evidence-gated \
  --model openai-compatible --model-id "$MODEL_ID" \
  --openai-compatible-system-role system \
  --output-root runtime/native-release
```

不使用 `--max-trials`、`--allow-dirty`、`--allow-no-judge` 或开发中的 `--resume` 结果作为正式发布物。若需要断点恢复，必须保留同一 selection、model、provider、profile、policy commitments 和 checkpoint，并将恢复次数及任何重试写入报告。

## 故障排查

- 如果 `8765` 打不开，先看 `systemctl --user status openclaw-gateway.service`。
- 如果大屏无数据，先访问 `/api/health` 和 `/api/stats`。
- 如果 OpenClaw Control UI 慢，优先检查 `18789` 代理和浏览器扩展。
- 如果 eBPF 显示 unavailable，这是当前用户级服务权限限制，不影响应用层预执行策略。
- 如果 benchmark 比普通演示慢，这是正常现象：公开攻击 benchmark 高风险样例占比高，risk-tiered 仍会频繁调用 DeepSeek Judge。
