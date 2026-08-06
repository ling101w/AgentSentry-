# openclaw-plugin/core

玄鉴 OpenClaw 插件的策略与算法核心。

唯一生产策略链：

`normalize -> Session TaskSpec -> Authorization Graph -> Provenance/Taint/IFC Branch -> Deterministic Enforcement -> Semantic Judge -> Runtime Feedback -> applyEffects`

`policy.ts` 的 `evaluate(snapshot, action, config)` 在克隆的 snapshot 上计算 `{ decision, effects }`，不修改调用方 state；`updateAfterDecision()` 统一提交 policy effects、history、behavior 和 aggregate risk。

主要模块：

- `policy.ts`：工具标准化、纯 evaluation/effects 契约和 deterministic enforcement 编排。
- `task-spec/`：会话级 TaskSpec V2 capability 提取、授权状态、过期和严格 authorization containment。
- `policy/safe-ops.ts`：系统健康检查等低风险只读动作的共享分类器。
- `policy/action-assessment.ts`：action 风险、sink/source 和敏感路径分类。
- `policy/behavior-baseline.ts`：按 tool x task class 的 warm-up、TTL、滑动窗口基线。
- `taint/provenance-graph.ts`：tool result 字段到 tool arg/sink 的 provenance 数据流。
- `semantic-action-graph.ts`：authorization、action、data、transformation 和 sink 的可验证图。
- `security/`：URL 与 canonical path 边界。
- `persistence/`：批量异步事件写入。
- `provenance.ts`：按文件 fingerprint 增量扫描和 watcher 失效。
- `session-registry.ts`：生产 session idle TTL、LRU 上限和 in-flight eviction guard。
- `init-defense.ts`：初始化组件盘点，覆盖 OpenClaw skill、plugin、配置和长期记忆入口；输出组件指纹、清单签名状态、声明能力和 Foundation Integrity 发现。
- `rollback.ts`：文件/配置/记忆 checkpoint 和操作级 checkpoint，记录可恢复边界、不可恢复边界、执行历史和会话安全状态。
- `agent-trust.ts`：多 Agent 身份等级与跨 Agent 消息信任约束，给主 Agent / 子 Agent / 外部 Agent 分层。
- `sandbox.ts`：有副作用 shell 命令的 workspace-shadow 执行，成功后提交，异常或运行时风险后丢弃。
- Memory Guard 读写保护、完整性校验、隔离和共识检测。
- LLM-Judge 调度和语义风险补充，覆盖用户消息、复杂工具调用、记忆写入和溯源扫描。
- 系统预执行检查和运行时记录脱敏。
- Dashboard 同时暴露 `/api/sidecar/evaluate` 作为外部 policy/sidecar 接口，第三方工具或网关可复用同一套 TaskSpec、IFC、ABAC、LLM-Judge 和运行态策略。
- Dashboard 还提供策略控制台、Bootstrap 统计、Checkpoint 回滚与图形化配置入口，便于演示和可解释性检查。

这里是核心安全逻辑，改动后必须运行 `npm --prefix openclaw-plugin run test:policy`。
