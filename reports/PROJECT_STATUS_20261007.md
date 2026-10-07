# 玄鉴项目当前状态

更新时间：2026-10-07  
当前分支：`feat/graph-learning-2.0`  
最近提交：`f20f1cd fix benchmark scoring and native provider evaluation`

## 先看结论

项目现在不是“还没做完”，而是分成三个成熟度不同的部分：

1. **玄鉴 1.0 监督系统**已经能运行、演示和做受控评测。
2. **Benchmark 评测体系**已经完成分层和判分修正，但正式结果和开发结果必须分开引用。
3. **图学习 2.0**已有模型、真实会话数据和消融实验，但目前没有证明图结构比简单基线更有用，暂不适合接入线上阻断。

## 当前能交付的部分

生产插件在 `openclaw-plugin/`，包括：

- OpenClaw 工具调用前后的监督钩子；
- TaskSpec V2 用户能力授权；
- 文件、邮件、API、Shell、记忆和日历动作控制；
- 外部内容信任标记、字段级 provenance、污点到 sink 的检查；
- `allow / ask / deny` 裁决和 observe / approval / block 模式；
- 8765 Dashboard、`/command-lab`、实时告警和审计记录；
- native AgentDojo bridge，以及标签隔离和执行状态记录。

最近一次 benchmark/native 修复已提交为 `f20f1cd`。前端、图学习和其他开发中的改动仍在工作区，没有混入该提交。

## 评测应该怎么读

| 结果 | 正确定位 | 当前结论 |
|---|---|---|
| 520 + 320 | 公开样例映射到 `/command-lab` 的回归 | 只能说明已知映射规则没有退化；旧“100%保护率”缺少执行证据，已改为逐步判分和证据不足。 |
| 原生 AgentDojo canonical 120 | 历史完整原生结果 | 可以作为已有原生主表，和映射回归分开。 |
| 新 API + Grok development 120 | 当前工作树的完整开发运行 | 120/120 完成，ASR 0/60、保护 60/60；正常 Utility 30/60、正常干预 24/60。因 dirty worktree 标为 `reportable=false`，不能替换 canonical。 |
| ATBench、DeepTrap、七风险、custom 100 | 独立协议或历史专项 | 只能按各自协议引用，不能相加成一个总样本量。 |

完整盘点见 `reports/benchmark-inventory-20261007/README.md`。

## 图学习真实状态

图学习代码在 `xuanjian-2.0/`，目前完成了：

- 因果图 schema、图构建、真实 OpenClaw session 转图；
- TemporalGAT、生产 GAT shadow router、解释路径和延迟基准；
- grouped CV、执行前截取、控制边/无边/随机边/工具基线消融；
- 真实会话审计和人工标注流程。

当前最重要的证据是：执行前数据约 105 张图，但有效攻击正样本只有 9 张；清理后的完整 GAT AUC 约 `0.789`，无控制边约 `0.809`，随机边约 `0.858`，工具/结构基线也不弱。真实会话上的 F1 和 recall 仍然偏低。

这说明当前问题主要是**数据和标签不足、样本分布不真实、特征可能存在采样偏差**，不是继续加深 GAT 就能解决。图模型现在应当作为 shadow / 研究模块，不能作为线上唯一阻断器。

详见 `reports/graph-learning/PRE_ACTION_RESEARCH.md` 和 `reports/graph-learning/pre-action-ablation-20261006.md`。

## 当前已知问题

- 新 API 能跑完整 benchmark，但短批量仍可能遇到 502、429 和连接错误；runner 已支持失败 trial 定向重试。
- Grok native run 的安全指标很好，但正常 Utility 只有 50%，主要失败集中在日历、外部邮件和文件映射任务。
- 日历授权、AgentDojo `file_id` 和 datetime formatter 已修复并通过针对性测试；针对性重跑仍受 provider 不稳定影响，尚未重新形成正式 120 结果。
- 真实生产误拦率不能由 840 条映射回归推断，需要独立正常业务集或盲测。
- 工作区仍有大量前端、图学习和运行产物未提交，当前 Git 状态不适合直接发布正式评测。

## 唯一推荐的下一步

1. 保留当前 `f20f1cd` 作为 benchmark/native 修复基线。
2. 在 provider 稳定后，只重跑日历、文件、邮件这批正常任务，确认 Utility 和误拦是否恢复。
3. 通过后创建干净工作树，再跑一次完整 120 native selection；只有 clean worktree、zero harness errors、selection hash 一致时，才更新 canonical 结果。
4. 图学习暂停新增模型，先收集并独立标注更多真实攻击/正常会话，再做同一分组下的图结构增益验证。

现在不应该做的事情是：继续堆更多 benchmark 数量、把 mapped/native/DeepTrap 结果相加、用图模型直接替换现有确定性阻断、或为了提高 Utility 全局放宽高风险规则。

## 常用入口

- 系统说明：`README.md`
- 比赛和评测入口：`reports/START_HERE.md`
- Benchmark 盘点：`reports/benchmark-inventory-20261007/README.md`
- 图学习研究：`reports/graph-learning/PRE_ACTION_RESEARCH.md`
- 生产插件：`openclaw-plugin/`
- 图学习目录：`xuanjian-2.0/`
