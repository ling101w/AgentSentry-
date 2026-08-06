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
- Memory Guard 读写保护、完整性校验、隔离和共识检测。
- LLM-Judge 调度和语义风险补充，覆盖用户消息、复杂工具调用、记忆写入和溯源扫描。
- 系统预执行检查和运行时记录脱敏。

这里是核心安全逻辑，改动后必须运行 `npm --prefix openclaw-plugin run test:policy`。
