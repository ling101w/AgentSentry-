# 监督编排与状态边界

## 模块职责

| 模块 | 职责 |
| --- | --- |
| `core/supervision-service.ts` | 固定输入、配置和状态快照，组织确定性初判、语义 Judge 与最终裁决，提供同步提交入口 |
| `core/policy.ts` | 保持原有公开接口；组织 `evaluate(snapshot) → { decision, effects }` |
| `core/policy/contracts.ts` | action、decision、effects、state、checkpoint 的类型契约 |
| `core/policy/actions.ts` | 工具别名与参数标准化 |
| `core/policy/rules.ts` | 授权、确定性边界、风险与裁决规则 |
| `core/policy/exposure.ts` | 已暴露数据与后续动作之间的污染匹配 |
| `core/policy/results.ts` | 工具结果生命周期、标签、provenance 继承和 IFC 分支 |
| `core/policy/state.ts` | 初始状态、版本检查、effects 提交和 checkpoint |
| `core/policy/updates.ts` | 消息、任务、裁决、运行反馈和审批对当前状态的更新 |
| `core/policy/support.ts` | 上述模块共同使用的输入验证、provenance 与信任辅助函数 |
| `core/session-queue.ts` | 按会话串行执行异步请求 |
| `server/policy-sessions.ts` | 每个 RecordStore 独立的会话、草稿提交和 Lab 客户端续接 |
| `server/sidecar-service.ts` | Sidecar 输入转换、会话试算和决策审计 |
| `server/policy-test-service.ts` | 控制台的独立策略试算 |
| `server/lab/service.ts` | Lab 请求转换、会话选择和命令审计 |
| `server/lab/runner.ts` | 调用监督服务、执行允许的工具、接收结果反馈 |
| `server/lab/executor.ts` | 演示工具的实际文件、网络、记忆和消息操作 |
| `server/lab/scenarios.ts` | 场景、样例内容、动作生成和演示授权 |
| `server/lab/workspace.ts` | 工作区定位、路径边界与输出截断 |
| `server/dashboard.ts` | HTTP 认证、路由、静态资源和控制台功能；将 Lab、Sidecar、策略试算交给对应服务 |

依赖从适配器进入监督服务，再进入策略模块。策略内部通过 contracts 和辅助模块协作，避免反向依赖 `policy.ts`。公开接口继续由 `policy.ts` 导出。

## 评估与提交

1. `SupervisionService.evaluate` 在第一次异步等待前复制 state、config、params 与调用上下文。初判与最终裁决使用同一份输入。
2. `policy.evaluate` 在独立状态上计算 effects，携带读取时的 `baseRevision`，不修改传入状态。
3. `applyEffects` 先比较 `baseRevision` 与当前 `sessionRevision`。冲突时抛出 `PolicyStateConflictError`，不写回图或其他 effects。
4. 成功提交、任务更新、消息/结果反馈、运行反馈、审批状态更新和 checkpoint 恢复都会使旧评估失效。
5. 审批回调只修改当前图中对应的 action 节点。它不能把旧 decision 中的整张图重新写回。

同一份 effects 只能提交一次。需要评估下一次动作时，重新读取当前状态。冲突后的处理应重新评估，不能绕过版本检查重试原 effects。

Hook 通过会话队列组织工具预检，并在提交前检查配置是否在等待期间变化。配置变化时阻断本次预检并要求重试。Sidecar 与 Lab 使用请求的配置快照；后续请求读取新的配置。

监督服务保留适配器原有的 Judge 路由：Hook 使用 `full`，Sidecar、Lab 和控制台试算默认使用 `ambiguous`。它们共享编排与提交逻辑，具体路由范围仍是显式适配选项。

## 会话草稿

`PolicySessions.run` 按会话排队，在队列执行时复制最近的已提交状态，构造下一轮草稿。回调成功且 `commit !== false` 时才发布草稿。

- `commitState:false` 的 Sidecar 请求可以生成审计记录，但不能发布任务、轮次、污染、图或重置结果。
- 回调失败时保留原有已提交会话；新会话的失败请求不占用会话条目。
- `runClient` 还按 Lab 客户端排队，成功后才发布客户端到会话的映射。失败的重置不能断开旧会话，续接请求也不能越过正在执行的重置。
- 会话按 RecordStore 隔离；闲置超过一小时后过期，最多保留 200 个会话。清理和淘汰避开正在执行或排队的请求。

这是一层会话状态事务。Lab 工具已经发生的文件、网络或记忆操作，以及已经写出的审计记录，不会因后续步骤抛错而自动撤销。

## 验证口径

- `supervision-state.test.ts`：旧 effects 拒绝、各类状态变更失效、审批更新保留后续记录、Judge 等待期间输入隔离、会话失败与重置、并发和淘汰。
- `openclaw-hooks.test.ts`：Hook 并发、等待期间配置变化、Hook/Sidecar/Lab 确定性裁决一致性。
- `dashboard-sidecar.test.ts`：HTTP 试算隔离、运行实例隔离和既有 Lab 场景。
- `lab-service.test.ts`：实际读取嵌套文件、阻断动作不进入执行器、失败重置续接、绝对路径和越界路径。

`npm run ci` 执行类型检查、lint、覆盖率、策略 smoke、AgentDojo bridge 自检、安全 smoke 和 property/fuzz。覆盖率报告包含 `server/**`；原核心门槛保持在原范围，并为 server 总体与会话/试算服务分别设置门槛。
