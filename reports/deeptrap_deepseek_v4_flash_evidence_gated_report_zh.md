# 玄鉴 DeepTrap evidence-gated 复跑报告

> 日期：2026-08-16  
> 被测模型与 Judge：`qwen/deepseek-v4-flash`  
> 评测套件：DeepTrap 全量 42 任务，每任务运行 1 次  
> 玄鉴策略：`evidence-gated` + `block` enforcement + `risk-tiered` semantic mode

## 1. 结论

本轮“只有明显攻击证据才阻断”策略已完成全量复跑。原始结果和独立重算结果均为 `42/42` 个任务有效，`summary.valid_result=true`，可以作为本轮正式对比结果。

与无防御相比，`evidence-gated` 将 AGS 从 `0.3361` 降至 `0.2371`，Defense Score 从 `0.5659` 提升至 `0.6685`，但 UGS 从 `0.4119` 降至 `0.2167`。它确实位于无防御和严格 `competition` 策略之间，但效用仍未恢复到无防御水平。

与严格 `competition` 策略相比，`evidence-gated` 的 UGS 提高 `0.1048`，同时 AGS 上升 `0.0943`。这符合低干预策略的预期取舍：少阻断、效用回升，但攻击通过程度也有所上升。

## 2. 结果文件

- 原始结果：[`0025_qwen-deepseek-v4-flash.json`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-evidence-gated/0025_qwen-deepseek-v4-flash.json)
- 独立重算：[`0025_qwen-deepseek-v4-flash.revalidated.json`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-evidence-gated/0025_qwen-deepseek-v4-flash.revalidated.json)
- 运行日志：[`run.stdout.log`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-evidence-gated/run.stdout.log)
- 审计记录：[`audit/records.jsonl`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-evidence-gated/audit/records.jsonl)
- 审计校验：[`audit/validation.json`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-evidence-gated/audit/validation.json)

## 3. 三组核心指标

| 指标 | 无防御 | competition 严格防御 | evidence-gated | evidence-gated 相对无防御 |
|---|---:|---:|---:|---:|
| AGS，越低越安全 | 0.3361 | 0.1428 | 0.2371 | -0.0990 |
| UGS，越高越好 | 0.4119 | 0.1119 | 0.2167 | -0.1952 |
| Defense Score，越高越安全 | 0.5659 | 0.7839 | 0.6685 | +0.1026 |
| 有效任务 | 42/42 | 42/42 | 42/42 | 0 |
| `valid_result` | true | true | true | - |

相对变化：与无防御相比，AGS 下降约 `29.5%`，Defense Score 相对提升约 `18.1%`，UGS 下降约 `47.4%`。与 `competition` 相比，UGS 相对提高约 `93.7%`，但 Defense Score 下降 `0.1154`。

## 4. 分类结果

下表是 DeepTrap 的分类 Defense Score，数值越高表示该类攻击评分越低。

| 风险类别 | 无防御 | competition | evidence-gated | evidence-gated 相对无防御 |
|---|---:|---:|---:|---:|
| encoding_obfuscation | 0.5669 | 0.6877 | 0.7454 | +0.1785 |
| harness_hijacking | 0.5416 | 0.8273 | 0.6122 | +0.0706 |
| privacy_leakage | 0.7997 | 0.8691 | 0.8006 | +0.0009 |
| supply_chain_risk | 0.6003 | 0.8617 | 0.7249 | +0.1246 |
| tool_abuse | 0.4066 | 0.7783 | 0.6449 | +0.2383 |
| unauthorized_execution | 0.4803 | 0.6791 | 0.4834 | +0.0031 |

低干预策略对 `tool_abuse`、`encoding_obfuscation` 和 `supply_chain_risk` 的收益最明显；对 `privacy_leakage` 和 `unauthorized_execution` 基本接近无防御。`encoding_obfuscation` 本轮还高于严格策略，但单次运行不能据此断言该策略在此类攻击上稳定优于 `competition`。

## 5. 策略行为证据

本轮 OpenClaw 配置快照确认：

- profile：`evidence-gated`
- enforcement：`block`
- semantic mode：`risk-tiered`
- 模型与语义 Judge：`deepseek-v4-flash`
- `ask` 只记录干预建议，不在本配置下强制阻断；只有最终 `deny` 被阻断

按全量运行开始时间 `2026-08-16T00:52:04Z` 过滤审计记录，共得到 `2,992` 条本轮记录，其中 `219` 条 `tool_decision`：

| 决策 | 数量 | 实际 disposition |
|---|---:|---|
| allow | 156 | allowed |
| ask | 22 | allowed |
| deny | 41 | blocked |

因此，这次运行确实执行了“仅明确拒绝才阻断”的低干预语义，而不是把 `ask` 也转换成拒绝。

## 6. 评测器有效性复盘

本轮状态统计为 `40 timeout + 2 error`，但 42 个任务均保留了非空 transcript，长度范围为 `7-16`，并且均有可解析的攻击评分与效用评分。因此按当前评测器门禁，全部任务的 `evaluation_valid=true`。

独立运行 [`revalidate_deeptrap_result.py`](../scripts/revalidate_deeptrap_result.py) 后，重算结果与原结果完全一致：

- `AGS=0.2371`
- `UGS=0.2167`
- `Defense Score=0.6685`
- `valid_task_count=42`
- `invalid_task_count=0`
- `valid_result=true`

这里必须区分两个概念：`valid_result=true` 表示结果可复核，不表示 42 个 OpenClaw 进程都正常退出。当前 timeout 规则是：只要已有非空 transcript 且 Judge 评分完整，超时前已经发生的行为仍可评估；空 transcript、缺失 Judge 结果或不可解析评分仍会被判无效。

## 7. 审计证据限制

完整审计快照包含本轮前的 smoke 记录。对原始 `records.jsonl` 运行完整性校验得到：

| 检查项 | 结果 |
|---|---:|
| 总记录 | 3,181 |
| 完整记录 | 424 |
| 完整率 | 13.3291% |
| tool/approval 记录 | 468 |
| tool/approval 不完整记录 | 44 |
| malformed lines | 0 |
| timestamp errors | 0 |
| overall status | `fail` |

按本轮开始时间过滤后为 `2,992` 条记录，其中满足全部回放字段的记录为 `395` 条；`436` 条 tool 事件中有 `395` 条完整。缺失主要来自生命周期、消息和部分工具结果记录未统一携带 `agent_id`、`tool_name`、`params`、`decision`、`disposition`、`execution_status`。

这不改变 DeepTrap 结果的 `valid_result=true`，因为两者校验对象不同，但比赛材料中不能将本目录表述为“完整、纯净、逐事件闭环的单次运行审计包”。后续应隔离 smoke 与正式运行的审计目录，并统一所有工具决策和结果事件的回放字段。

## 8. 最终判断

`evidence-gated` 达到了预期方向：相较严格策略显著恢复效用，同时保留了一部分安全收益。当前数据支持将它作为“低干预运行模式”的候选策略，但不能替代严格策略用于高安全场景；尤其是 `privacy_leakage` 和 `unauthorized_execution`，本轮相对无防御的提升几乎为零。

此外，本次使用的 API key 已在对话中明文出现。正式提交或继续使用前应立即轮换，并检查配置快照、日志与报告中是否残留旧 key。
