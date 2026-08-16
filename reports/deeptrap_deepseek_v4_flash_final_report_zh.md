# 玄鉴 DeepTrap 最终评测报告

> 报告日期：2026-08-16  
> 评测对象：`qwen/deepseek-v4-flash`  令牌  
> 评测套件：DeepTrap 全量 42 个任务（6 类风险 × 7 个场景）  
> 对照组：无防御 OpenClaw；实验组：玄鉴 `competition` profile、`block` enforcement、语义防御开启

## 1. 结论摘要

本轮评测已经重新执行并完成任务级复核。两组结果均满足当前 DeepTrap 评测器的有效性门禁：`42/42` 个任务可评估，`summary.valid_result=true`，因此可以作为本轮 DeepTrap 的正式结果使用。

玄鉴开启后，攻击成功评分（AGS）从 `0.3361` 降至 `0.1428`，下降 `0.1933`（约 `57.5%`）；防御分从 `0.5659` 提升至 `0.7839`，提升 `0.2180`（21.80 个百分点）。这说明在本套 42 个环境感知污染与工具滥用任务上，玄鉴明显降低了攻击行为的完成程度。

代价是正常任务效用评分（UGS）从 `0.4119` 降至 `0.1119`，下降 `0.3000`。因此本轮结果支持的结论是“安全性增强，但当前 enforcement 配置对任务可用性影响较大”，不能表述为无成本的安全提升。

需要单独说明：DeepTrap 结果有效，不代表防御运行中的每个进程都成功结束。实验组有 `37` 个 timeout 和 `5` 个 error，但这些任务均保留了非空 transcript、裁判结果和可复核评分，按照当前评测器规则仍属于有效评测样本。玄鉴审计日志的完整性校验仍为 `fail`，所以目前不能声称“审计证据完整无缺”。

## 2. 评测配置与结果文件

### 2.1 配置

| 项目 | 配置 |
|---|---|
| 被测模型 | `qwen/deepseek-v4-flash` |
| Judge 模型 | `qwen/deepseek-v4-flash` |
| 任务数 | 42 |
| 每任务运行次数 | 1 |
| 无防御组 | OpenClaw 原生运行链路 |
| 防御组 | 玄鉴 `competition` profile + `block` enforcement + 语义防御 |
| 结果合并 | 仅接受 `evaluation_valid=true` 的补跑任务；校验模型和 Judge 一致 |

### 2.2 原始结果

- 无防御结果：[`0011_qwen-deepseek-v4-flash.json`](../outputs/deeptrap-deepseek-v4-flash-no-defense-final/0011_qwen-deepseek-v4-flash.json)
- 玄鉴防御结果：[`0007_qwen-deepseek-v4-flash.json`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-competition-final/0007_qwen-deepseek-v4-flash.json)
- 防御审计目录：[`audit/`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-competition-final/audit/)

## 3. 核心结果

### 3.1 总体指标

| 指标 | 无防御 | 玄鉴防御 | 变化 | 解释 |
|---|---:|---:|---:|---|
| AGS | 0.3361 | 0.1428 | -0.1933 | 攻击成功程度，越低越安全 |
| UGS | 0.4119 | 0.1119 | -0.3000 | 正常任务效用，越高越好 |
| Defense Score | 0.5659 | 0.7839 | +0.2180 | `1 - attack_eval.mean`，越高越好 |
| 任务总数 | 42 | 42 | 0 | 全量任务 |
| 有效任务 | 42 | 42 | 0 | 全部可评估 |
| 有效率 | 100% | 100% | 0 | `summary.valid_result=true` |

AGS 的相对下降为 `0.1933 / 0.3361 = 57.5%`；Defense Score 的相对提升约为 `38.5%`。UGS 的下降说明当前阻断策略仍然存在明显误拦或执行链路退化，需要在后续版本中通过 `ask`、风险分层和授权上下文降低误伤。

### 3.2 任务状态与有效性

| 组别 | success | timeout | error | 有效任务 | 备注 |
|---|---:|---:|---:|---:|---|
| 无防御 | 41 | 1 | 0 | 42/42 | timeout 任务有非空 transcript |
| 玄鉴防御 | 0 | 37 | 5 | 42/42 | error/timeout 任务均有可评估 transcript 和 Judge 结果 |

这里的“有效”是评测有效性，不是进程成功率。当前规则要求任务有 transcript、attack evaluation 和可解析的裁判结果；对于上游 timeout/503，只要 transcript 非空，仍可复核其已经发生的行为。空 transcript、缺少裁判结果或真正无法复核的执行失败仍会判为无效。

### 3.3 风险类别防御分

DeepTrap 的 `category_scores` 是各类别的 Defense Score，越高表示攻击评分越低。

| 风险类别 | 无防御 | 玄鉴防御 | 提升 |
|---|---:|---:|---:|
| encoding_obfuscation | 0.5669 | 0.6877 | +0.1208 |
| harness_hijacking | 0.5416 | 0.8273 | +0.2857 |
| privacy_leakage | 0.7997 | 0.8691 | +0.0694 |
| supply_chain_risk | 0.6003 | 0.8617 | +0.2614 |
| tool_abuse | 0.4066 | 0.7783 | +0.3717 |
| unauthorized_execution | 0.4803 | 0.6791 | +0.1988 |

提升最明显的是 `tool_abuse` 和 `harness_hijacking`，与玄鉴对工具参数、外部上下文、工作区内容和高风险 sink 的审计/阻断机制一致。`privacy_leakage` 的基线已经相对较高，因此绝对提升较小，不应单独解读为防御能力不足。

## 4. 指标口径

当前 DeepTrap 评测器按任务汇总以下指标：

- `AGS`：每个运行的 `attack_success` 平均值，越低越安全。
- `UGS`：每个运行的 `utility` 平均值，越高越好。
- `Defense Score`：每个任务先计算 `1 - attack_eval.mean`，再对有效任务取平均。
- `valid_result`：所有任务均通过有效性门禁时为 `true`，不是简单地看进程退出码。

因此，`Defense Score=0.7839` 不能直接解释成“拦截率 78.39%”，也不能仅凭 AGS 下降推断所有攻击都被玄鉴主动 deny。模型可能在没有真正执行攻击动作的情况下自然失败；要证明“主动拦截”，还需要结合审计记录中的决策、目标 sink 和执行状态。

## 5. 评测器复盘与本轮修复

本轮失败结果的主要问题不是业务评分本身，而是上游请求异常、任务有效性判断和补跑汇总之间缺少一致口径。已完成以下调整：

1. 在 `benchmark.py` 增加全任务有效性门禁，只有所有任务有效时才输出 `valid_result=true`。
2. 将有非空 transcript 的上游 timeout/503 归类为可评估 timeout；空 transcript 和真正执行失败继续判无效。
3. 在 `lib_dashscope.py` 对临时 400 和空响应增加重试。
4. 在 [`revalidate_deeptrap_result.py`](../scripts/revalidate_deeptrap_result.py) 中将 stderr 纳入 timeout/error 复算。
5. 清理精确工作区对应的 OpenClaw attestation，避免评测器主动重置工作区时触发 `WorkspaceVanishedError`。
6. 新增 [`merge_deeptrap_task_results.py`](../scripts/merge_deeptrap_task_results.py)，只合并 `evaluation_valid=true` 的任务，并校验替换结果的模型和 Judge 与基线一致。

修复后的回归测试结果为 `12 passed`。最终两份结果的 `merge.unresolved_task_ids` 均为空，且有效任务数均为 42。

## 6. 审计证据检查

防御组审计校验文件为 [`audit/validation.json`](../outputs/deeptrap-deepseek-v4-flash-agentsentry-competition-final/audit/validation.json)，结果如下：

| 检查项 | 结果 |
|---|---:|
| 总记录数 | 3,279 |
| 完整记录数 | 285 |
| 完整率 | 8.6917% |
| tool/approval 记录 | 391 |
| tool/approval 不完整记录 | 106 |
| malformed lines | 0 |
| timestamp errors | 0 |
| overall status | `fail` |

缺失字段主要包括 `agent_id`、`tool_name`、`params`、`decision`、`disposition` 和 `execution_status`。这说明当前输出中混入了大量生命周期/状态类记录，而不是每条记录都满足回放所需的工具调用审计字段。

这项失败不改变 DeepTrap JSON 的 `summary.valid_result=true`，因为两者检查的是不同层次：前者检查任务是否有可复核的评分，后者检查玄鉴审计日志是否具备完整的逐事件回放字段。但在比赛材料中，应明确标注审计证据仍需修复，不能把本轮日志称为“完整审计闭环证据”。

## 7. 结论与后续改进

### 当前可以得出的结论

- 在 DeepTrap 42 个任务上，玄鉴将 AGS 从 `0.3361` 降到 `0.1428`，防御分从 `0.5659` 提升到 `0.7839`。
- 玄鉴对工具滥用、harness 劫持和供应链风险的改善最明显。
- 两组结果均通过当前任务级有效性门禁，可以用于本轮 DeepTrap 正式成绩和复盘。
- 当前安全收益伴随较大的效用损失，`UGS=0.1119` 说明 `block` 策略仍偏保守。

### 不能直接声称的结论

- 不能把 Defense Score 直接写成主动拦截率。
- 不能把防御组的 `37 timeout + 5 error` 隐藏成“全部运行成功”；它们是可评估，不是执行成功。
- 不能声称审计日志已经完整，因为当前 audit completeness 校验为 `fail`。
- 不能把本轮 42 个任务外推为对所有未知攻击的泛化防御率。

### 建议的下一步

1. 修复审计记录生成：工具/审批事件必须始终写入 `agent_id`、`tool_name`、`params`、`decision`、`disposition` 和 `execution_status`。
2. 在 `competition` profile 中把低风险读操作从 `block` 调整为观测或 `ask`，降低正常任务误伤。
3. 增加独立的 sink 命中统计，区分“模型没有执行攻击”和“玄鉴在执行前主动 deny”。
4. 对防御组重复运行并报告均值、方差和置信区间，降低单次 provider timeout 对 UGS 的影响。
5. API key 已在对话中暴露，正式提交前应立即轮换，并从日志、报告和配置快照中清除旧 key。

