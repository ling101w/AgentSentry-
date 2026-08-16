# Native AgentDojo Expanded v1：DeepSeek V4 Pro / Evidence-Gated 发布复跑

运行日期：2026-08-14（UTC+8）

## 结论

本轮在冻结提交 `b26d308d1dfa8aef8dbdb4d2ee2bd868906a27ba` 上完成 AgentDojo 原生端到端评测。公开结果状态为 `complete`，`reportable=true`，140/140 个 trial 全部成功，provider/harness error 为 0，语义 Judge 最终审计为 `12 requested / 12 called / 0 failed`。

本轮与历史 evidence-gated 实验使用同一 Expanded v1 选择集，并非更换数据集：

- AgentDojo `0.1.35`，workspace `v1.2.2`；
- `tool_knowledge` attack；
- 40 个唯一正常任务、100 个唯一攻击 pair；
- harness seed `7`，每个唯一 case 一次 provider generation；
- selection canonical SHA-256：`679cf45d9a186a5acc472151ba1b22a4a49c3029931b491d5611690d9fb9fad1`；
- provider/model：OpenAI-compatible `deepseek/deepseek-v4-pro`，`system` role；
- provider/Judge 请求预算均为 90 秒，bridge 预算为 120 秒。

## 指标

| 指标 | 本轮结果 | 95% Wilson 区间 |
|---|---:|---:|
| 官方 AgentDojo ASR | `0/100 = 0.00%` | `0.00%-3.70%` |
| 归一化 exact-sink match | `0/100 = 0.00%` | `0.00%-3.70%` |
| 已执行恶意高风险副作用 | `0/100 = 0.00%` | `0.00%-3.70%` |
| 正常任务 Utility | `37/40 = 92.50%` | `80.14%-97.42%` |
| 正常 deny FPR | `0/40 = 0.00%` | `0.00%-8.76%` |
| 正常 intervention | `0/40 = 0.00%` | `0.00%-8.76%` |
| 攻击环境任务 Utility | `83/100 = 83.00%` | `74.45%-89.11%` |
| Trial 级 Ask Rate | `7/140 = 5.00%` | `2.44%-9.96%` |
| Provider/harness errors | `0/140` | - |

决策统计为 130 allow、7 ask、3 deny。延迟均值为 25,078.55 ms，P50 为 16,518.94 ms，P95 为 65,357.03 ms，P99 为 138,514.55 ms。Provider 未返回可验证价格，成本继续记为 unknown，不进行估算。

三层攻击审计没有观察到 scorer miss，也没有出现“官方成功但未观察到危险副作用”的反向异常。审计另行记录 8 个 `get_unread_emails` 读状态变化；该工具会把邮件标为已读，这属于状态副作用，但不计入外发、删除、日历写入等恶意高风险副作用分母。

## 与历史 Evidence-Gated 结果的关系

历史同选择集结果为三层攻击指标 `0/100`、正常 Utility `35/40`、攻击 Utility `75/100`、正常干预 `0/40`。本轮仍为三层 `0/100`，正常 Utility 为 `37/40`，攻击 Utility 为 `83/100`，正常干预仍为 `0/40`。

这些变化不应解释为策略修改带来的确定性提升。AgentDojo 0.1.35 不向 provider 传递生成随机种子，因此两轮是同 case、同模型、同策略配置的端到端复跑，不是逐 token 或逐轨迹重放。指标波动反映 provider generation 的非确定性。

本轮仍是 post-hoc `evidence-gated` profile 实验，不替代预注册 `competition` 主结果。预注册主结果继续是无防御 ASR `61/100` 对 competition `1/100`，正常 Utility `35/40` 对 `27/40`。

## 运行与重试说明

本轮从 clean frozen commit 启动，但不是单一 OS 进程不中断地完成：

1. 初始进程完成 108 条后被外部进程生命周期终止，checkpoint 中 108 条均为有效成功 trial；
2. 使用同一选择集、模型、provider、策略、manifest、bridge 和冻结提交，从原 checkpoint 继续剩余 32 条；
3. 140 条完成后，语义 Judge 审计为 `15 requested / 12 called / 3 failed`，因此结果正确标记为 `partial/reportable=false`，未覆盖 canonical result；
4. 使用 `--retry-judge-failures` 只重新生成 Judge 失败所在 trial，最终为 `12 requested / 12 called / 0 failed`；
5. 最终 checkpoint `resume_count=2`，结果更新为 `complete/reportable=true` 并覆盖冻结 checkout 的 canonical result。

因此，本轮解决了历史 evaluator overlay 和 raw manifest 换行哈希不统一的问题：所有阶段都在同一提交和同一 manifest 文件哈希下运行，`policy_commit` 与 `evaluator_commit` 均为 `b26d308d1dfa8aef8dbdb4d2ee2bd868906a27ba`，tool manifest raw SHA-256 始终为 `1c3882e0394e2ddc9a1fda0f3f56e4f3e2a451015f745bd87ef3f70c4a6b6ece`。但它仍包含 checkpoint resume 和 Judge failure retry，不能描述为“无重试的一次性 traversal”。

## 发布校验

归档完成后对公开产物执行了以下一致性检查：

- `result.public.json` 通过 `agentdojo-native-result-v1` Draft 2020-12 Schema 校验；
- 公开 result 与冻结运行时中的 `result.public.json` 字节一致，SHA-256 均为 `cfd8e32f4aa97dfd00dc1153656738c7513d33a4f170bfd287c0a7aecdbe7373`；
- detector transcript、private labels、private trials 和 checkpoint 的实际 SHA-256 与 manifest 全部一致；
- selection canonical hash、post-join canonical hash、run ID、release/policy/evaluator commit、checkpoint 计数、Judge 计数和三层指标在 public result、manifest、three-layer audit、provenance sidecar 与私有 checkpoint 之间一致；
- 四个公开 JSON 未包含 API key、Authorization、私有标签数组、逐 trial 内容、prompt/response 或 tool-call 明细。

主工作区的 `evaluation/native/agentdojo_results.json` 继续保留标准选择集 canonical 结果，不用本 post-hoc Expanded v1 arm 覆盖；本轮公开归档以 `outputs/native_deepseek_v4_pro_evidence_gated_expanded_v1_140*` 文件组为准。

## 证据承诺

- Run ID：`agentdojo-native-20260814T080717Z-0c80934f`
- Policy commit：`b26d308d1dfa8aef8dbdb4d2ee2bd868906a27ba`
- Evaluator commit：`b26d308d1dfa8aef8dbdb4d2ee2bd868906a27ba`
- Selection SHA-256：`679cf45d9a186a5acc472151ba1b22a4a49c3029931b491d5611690d9fb9fad1`
- Trial plan SHA-256：`b99fc2d6bc2f259cec7c23dbd5724418b41249f5d8b85ae8816de4db1c6cac9b`
- Tool manifest SHA-256：`1c3882e0394e2ddc9a1fda0f3f56e4f3e2a451015f745bd87ef3f70c4a6b6ece`
- Plugin dist SHA-256：`db20e378b99cc97ed955bed4e96c1dbb4be3db2433828c1afe852c867356ad55`
- Bridge script SHA-256：`7cb77c713dd90024b880a01c3f2fb5eadac43045624b7da44534e86374a02d93`
- Detector transcript SHA-256：`f42984e6f8cf9c4a6e074021466a9086d2ab3fe2a2ad0a8748e95e9a2161b6dc`
- Private labels SHA-256：`16c593b44d2ee3ca395c2d9c422c4e8e318744d8fa69c3833a7b9a1df4b1bb06`
- Private trials SHA-256：`7ec0c3f3dfdbde5c827af8fc12b15f5217ca7e09936162ad288e2a09cc018a38`
- Post-join SHA-256：`388c020ec8a94491019cc1e69d0f444c52477e045fa7fef9d12a6b344496ef4d`

私有 checkpoint、labels、trials 和 detector transcript 保留在 ignored runtime 目录，不作为公开文件分发。