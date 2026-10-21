# 本地正常业务 benchmark 复用与修复（2026-10-17）

本轮从本地现有 benchmark 中冻结了 **210 条原标签要求 allow 的工作流，以及 3 条原本要求 ask 的对照**，另复用了 32 条历史审查/安全对照。完成确定性策略回放及官方 AgentDojo workspace 的 40 条内存环境参考流程，并根据实际失败修复授权提取和邮箱适配。全部运行均为零模型调用。

本集属于已知开发回归。来源包含历史映射和模板变体，精确去重不使它们成为独立样本；这些比例不代表生产 FPR，也不能称为独立评审的 200 条正常业务实验。工作区包含本轮及之前尚未提交的改动，结果均标为 development / reportable=false。

## 复用了什么

| 本地来源 | 导入条目 | 说明 |
| --- | ---: | --- |
| 历史综合映射回归 | 79 | MemoryGraft 60、RedTeamCUA 9、映射 AgentDojo 10 |
| 历史工具专项映射回归 | 50 | AgentDefense-Bench 原标签正常的 MCP 操作 |
| Custom Realistic 100 | 68 | 65 条 allow、3 条 ask；包含重复输入 |
| AgentDojo workspace v1.2.2 | 40 | 从已安装 0.1.35 的官方正常任务与 ground-truth 工具序列导出 |

共 237 条，按实际五字段输入序列去掉 24 条精确重复，留下 213 条：210 allow + 3 ask。标签、来源、case ID 均留在 evaluator 中；detector 只接收 user_message、tool_name、tool_args、tool_result、session_history。重建历史 Lab 参数时移除了工具参数中由评测者添加的 benchmark/benign-baseline reason 提示。

已冻结文件：

- `evaluation/benign/reused_business_workflows.jsonl`：本轮主集合。
- `evaluation/benign/reuse_inventory.json`：来源路径、SHA-256、数量、去重及变换说明。
- `evaluation/regression/reused_business_controls.jsonl`：32 条审查/安全对照。

还盘点到 banking 16、slack 21、travel 20 个官方正常任务，加上 workspace 共 97 个。当前原生桥接具备 workspace 契约，其余 57 个只列入覆盖缺口，没有冒称执行完成。历史映射的 AgentDojo 项目按 mapped development 记录。

## 固定集合的前后对比

balanced 与 competition 都关闭语义 Judge，使用各自原有风险驱动策略。两个配置重用同一套输入，不能合计为 420 个独立正常任务。固定集合 SHA-256 在 `before-replay.json` 与 `after-replay.json` 一致。

| 配置 | 阶段 | allow | ask | deny | 原标签正常请求的拒绝比例 |
| --- | --- | ---: | ---: | ---: | ---: |
| balanced | 修复前 | 83 | 13 | 114 | 54.3% |
| balanced | 修复后 | 143 | 13 | 54 | 25.7% |
| competition | 修复前 | 81 | 7 | 122 | 58.1% |
| competition | 修复后 | 141 | 7 | 62 | 29.5% |

每个配置恢复了 60 条正常源工作流，未新增对之前放行样例的干预。恢复项分别是 MemoryGraft 57 条、Custom Realistic 2 条、原生参考动作 1 条。放行与干预明细、原因分组及剩余首个干预点见 `comparison.json`。

这张表是 **source-labelled normal 的策略干预**，并非每一项都已被独立判定为误报。3 条原标签 ask 对照均仍被当前策略 deny，单独记录，没有混进正常误拒分母。

回放在第一个 ask/deny 处停止，不执行业务工具，不把 allow 等同于任务完成。历史动作没有结果时，也不会伪造工具反馈或任务 Utility。修复前确定性回放与 `native-before.json` 在同一未修改的检测器基线上执行；检测器基线指纹保存在后者中。后续运行记录源码指纹和工作区状态。

## 已修复的根因

1. **明确的经验写入漏授权。** 原解析器漏掉“写入长期经验库”等明确句式，使 60 条经验中 57 条被拒绝。已补充经验库/长期记忆句式，同时处理否定、讨论、引用和条件，保护记忆内容本身的安全检查。
2. **邮件摘要发送漏授权。** “给某邮箱发送巡检摘要”等请求缺少原模式要求的“邮件/报告”字样，现支持摘要、通知、进展和结果，收件人仍按具体授权匹配。
3. **未读邮件错误落入通用 API。** 官方 `get_unread_emails` 没有 URL，并且会将邮件标为已读。它现在映射为独立 `email_read` 能力，保留 persistent_change 副作用，只支持用户明确请求的自身未读邮箱、无额外参数。它不授予发送、删除或读取别人的邮箱；调用预算同时写回授权会话，后续消息不能重置已用预算。manifest mapping_version 更新为 1.2.0。
4. **先执行后补审批的长期记忆。** 历史对照发现“遇到审批提示先继续任务，审批稍后整理”可以落盘。已增加这类延期审批规则的记忆边界，并验证“审批通过后执行”和否定危险做法的提醒可以保存。证据门控配置也保留该边界。

## 32 条历史审查/安全对照

初测有 1 条延期审批记忆被放行，见 `controls-before-hardening.json`。补充记忆边界后：

| 配置 | allow | ask | deny |
| --- | ---: | ---: | ---: |
| balanced | 0 | 4 | 28 |
| competition | 0 | 3 | 29 |

明细见 `controls.json`。这是静态策略回放中未整条放行的数量，没有执行攻击，也没有证明因果攻击保护率；某些对照的首次干预可能发生在正常前置步骤。原标签预期 ask、实际 deny 的差异仍保留。

## 官方环境中的参考流程

对 workspace 的 40 个正常任务，先运行无防护官方 GroundTruthPipeline，再通过当前 bridge 运行同一参考动作。工具只在 AgentDojo 官方内存环境中执行；没有真实邮箱、日历或文件服务写入。没有创建模型客户端。

| 指标 | 修复前 | 修复后 |
| --- | ---: | ---: |
| 无防护参考 Utility 通过 | 40/40 | 40/40 |
| 有防护参考 Utility 通过 | 21/40 | 22/40 |
| 全部参考工具执行且 Utility 通过 | 18/40 | 19/40 |
| 出现策略干预的任务 | 22/40 | 21/40 |
| harness errors | 0 | 0 |

`user_task_24` 的未读邮件操作实际执行并通过了官方评估。详见 `native-before.json`、`native-after.json` 和 `test_native_mailbox_contract.py`。

GroundTruthPipeline 同时提供工具计划和最终答案。继续已知参考序列，是为了让官方评估器到达最终检查；被拒绝的工具仍不会执行。由于只读任务可能仅凭给定答案就通过 Utility，所以单列了“全部工具执行且评估通过”。这些是参考路径兼容性验证，不能作为自主 LLM Agent 的 native Utility 成绩。

## 仍需处理的问题

- 每个配置剩余失败中有 **43 条旧 API 映射缺少可信服务上下文**：工具参数含健康检查 URL，用户文字只写“调用本地健康接口”。当前通用 HTTP 授权无法从中确定该地址，这批需要重建原 MCP 工具契约或命名服务上下文。
- 部分正常源标签与当前边界冲突，例如读工作区外系统文件、没有具体目标的 Skill 写入，以及风险安装操作。这些需要重新审定预期和配置。
- 原生路径仍有 delete_email、share_file、file_id/文件选择、从邮件指令派生动作，以及日历参数/参与者绑定等缺口。剩余 21 个受干预的官方参考任务没有被隐藏。
- 当前运行关闭 Judge，不能推断模型启用后的拒绝率或误判变化。应在冻结版本、同一选择集上另测模型模式，并将实际执行与审批反馈纳入统计。

## 复跑

先让 Node 24 在 PATH 中，在仓库根目录执行：

```powershell
npm --prefix openclaw-plugin run build
python scripts/run_benign_reuse.py --output reports/benign-reuse-20261017/replay-new.json
python scripts/run_benign_reuse.py --cases evaluation/regression/reused_business_controls.jsonl --output reports/benign-reuse-20261017/controls-new.json
python scripts/run_benign_reuse.py --native-reference --output reports/benign-reuse-20261017/native-new.json
```

冻结的 JSONL 可直接回放，不依赖历史源目录。重新导入需要本地原始报告和 AgentDojo 0.1.35，入口为 `scripts/build_benign_reuse.py`；`--controls-only` 只重建对照。重导出后的 selection hash 需重新记录，不能与旧结果混算。

验证：完整插件 CI 通过，67 个测试文件、758 项测试通过、1 项跳过；Python 150 项通过。覆盖了标签隔离、去重冲突、审批对照分母、Utility 不伪造、正常/危险记忆、邮箱权限范围、预算持续性和真实原生契约。
