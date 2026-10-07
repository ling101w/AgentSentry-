# Benchmark 运行盘点（2026-10-07）

这份盘点补充了项目之前只展示 840 条映射回归的问题。扫描范围是当前工作区的 `reports/`、`evaluation/`、`benchmarks/` 和 `runtime/`，按 JSON 内容 SHA-256 去重；`archives/` 只作为历史来源，不并入当前可复现实验总数。

## 已确认的独立结果

| 结果类型 | 数量 | 说明 |
|---|---:|---|
| 当前映射综合评测 | 520 | `reports/benchmark_risk_tiered/`；公开样例映射到 command lab。新版逐步判分因旧结果缺少执行证据，实际保护率显示证据不足。 |
| 当前映射工具专项 | 320 | `reports/benchmark_risk_tiered/`；同上。 |
| 原生 AgentDojo 完整结果 | 120 trials | `benchmarks/evaluation-q/native/agentdojo_results.json`；60 benign + 60 attack，0 harness error，官方 ASR 0/60，protection 60/60，benign utility 58/60，FPR 0/60。 |
| 原生 AgentDojo smoke（两次 API） | 18 + 18 trials | `runtime/native-kimera-20261007/` 与 `runtime/native-qiaodao-20261007/`；均为 3 tasks x 3 arms x benign/attack，开发 smoke，不是正式 benchmark。 |
| ATBench 静态轨迹 | 多个 40/80 条 smoke | 结果在历史归档，不能和原生 AgentDojo 相加。当前 `.test-audit/static-trajectory/summary.json` 是 20 条静态结果：TP 9、TN 3、FP 7、FN 1。 |
| 七风险 command-lab / 三臂结果 | 700 或 1400 case | 仅存在 `archives/` 历史归档；同一 `input_sha256` 的 arm 是配对实验，不能按 arm 相加成新样本。 |
| 720 authorization、72 blind、100 realistic comparison | 历史专项 | 只能按各自协议引用，不能并入 840 或原生 AgentDojo。 |

当前工作区扫描到 180 个 JSON 文件、33 个结果对象、30 个唯一内容、27 个唯一对象；3 组是内容重复备份。完整机器可读索引在 `benchmark-inventory.json`。

## 本次 API 运行

新 key 对应的 endpoint `https://api.qiudaoyu.ccwu.cc/v1` 已确认鉴权成功，返回 146 个模型通配项；`grok-4.20-non-reasoning`、`grok-4.20-reasoning`、`grok-4.3`、`gpt-4o`、`gpt-4.1`、`gpt-5` 均支持强制工具调用。

之前已验证可用的 endpoint `https://api-direct.kimera.cc/v1` 支持 `gpt-5.6-sol` 和工具调用；本轮用它跑了 18 条 development smoke，结果：

- no-defense：6/6 成功，3 个攻击样例均未成功触发攻击目标；
- observe：6/6 成功，3 个攻击样例均未成功触发攻击目标；
- block：6/6 harness 成功，正常任务 3/3 完成，攻击任务 3/3 未成功，1 条攻击任务 utility 为 false；
- smoke 不能代替完整 120 trial 原生结果，也不能证明泛化。

新 endpoint 的 18 条 smoke 重试后为 18/18 完成：正常任务 9/9，攻击任务 9/9 未成功；但这仍然只是 development smoke。正式 runner 的单条长上下文任务约 91 秒后触发 `ApiTimeoutError`，因此 120 trial 没有继续消耗。

新 key 的 `grok-4.20-non-reasoning` smoke：18/18 完成；no-defense 攻击成功 1/3，observe 攻击成功 1/3，block 攻击成功 0/3；三组各 3 个正常任务中 block 为 3/3，no-defense 和 observe 各 2/3。该结果保存于 `runtime/native-qiaodao-grok-20261007/`，仍是 development smoke。

随后尝试启动冻结的 120-trial native runner。前一轮失败的根因是自定义 provider 分支使用 JSON 工具结果格式，AgentDojo workspace 的 datetime 工具输出触发 `TypeError`；已修复为默认 formatter，并用有/无 Judge 的单条任务验证通过。之前的失败 run 不计入任何 ASR、保护率或 Utility。

修复后用新 key 的 `grok-4.20-non-reasoning` 重跑同一冻结 selection；首轮 120 条中 114 条完成、6 条遇到 Cloudflare 502，随后只重试这 6 条并合并，最终 120/120 成功。最终结果在 `runtime/native-qiaodao-agentdojo-retry-20261007/agentdojo-native-20261007T104451Z-b970ee87/result.public.json`：攻击 60/60 未成功（ASR 0/60，Protection 60/60），正常 Utility 30/60，攻击 Utility 27/60，FPR/正常干预率 24/60，P50 4388 ms、P95 27350 ms，harness error 0。该 run 使用 dirty worktree，`reportable=false`，不能替换干净工作树上的 canonical 结果；它是完整的可复现 development run，不能与已有 canonical AgentDojo 120 trials 合并计数。

这次重跑还新增了 `--retry-from`：只读取上一轮 private `trials/labels/detector-events`，重试 error trial，并按原 `trial_id` 合并，成功样例不会重复请求。标签仍只在 evaluator 文件中，detector envelope 没有新增 benchmark 标签字段。

## 下一步

1. 先决定论文/答辩主表：推荐使用已有原生 AgentDojo 120 trials，单独列 840 条映射回归和 ATBench/七风险专项，不把不同协议合并成一个总分。
2. 新 key 的 provider 已通过 smoke，可以从同一个冻结 selection 重跑 no-defense、observe、block 三臂；正式结果仍需等 120 trials 完整结束并检查 zero harness errors。
3. 运行原生 AgentDojo 完整 selection 前，先做 6 条小 smoke，确认 tool call、模型输出、桥接和 utility 都正常，再决定是否投入全量请求。
4. 映射 benchmark 重新跑时必须保留 `toolCallId`、`execution_status` 和逐步参数；旧报告的 100% 只能写作旧判分口径，不能当作实际保护率。

当前 native Grok 结果的下一步不是继续扩充攻击样本，而是先修复 8 个稳定失败的正常任务映射，具体见 [native-grok 正常任务诊断](native-grok-benign-diagnosis.md)。



## 新 API 原生 runner 适配结果

已为 `scripts/run_agentdojo_native.py` 增加 `--model openai-compatible --model-id <provider-model>` 分支和自定义 `ToolKnowledgeAttack` 适配，原有 31 项 native runner 测试通过。用 `deepseek-v4-flash` 尝试正式 120 trial 时，单条完整 AgentDojo trial 在 provider 侧约 91 秒超时，连续错误后已停止；没有产生可评分的成功 trial。该结果保存于 `runtime/native-qiaodao-agentdojo-one-20261007/`，错误类型为 `ApiTimeoutError`，不计入 benchmark 指标。

要跑完整 120 trial，应先确认 provider 对长上下文 AgentDojo 请求的稳定 timeout/额度，再从同一冻结 selection 开始；建议先用 smoke 的 18 条结果作为协议检查，不能把 timeout 结果填成 ASR 或保护率。
