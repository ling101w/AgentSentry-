# openclaw-plugin/core

玄鉴 OpenClaw 插件的策略与算法核心。

策略执行顺序：

`normalize -> Authorization Graph -> Provenance/Taint Graph -> Deterministic Enforcement -> Semantic Judge (ambiguous only) -> applyEffects`

`policy/decision.ts` 中的 `evaluate(snapshot, action, config)` 不修改会话状态；所有 history、rate、behavior、risk 和 provenance graph 更新都由 `policy.ts` 的 `applyEffects()` 提交。

主要模块：

- `adapters/`：OpenClaw 工具名和参数标准化。
- `authorization/`：TaskSpec 与 capability 集合包含检查。
- `policy/`：纯判定、deterministic gate 和 risk 计算。
- `taint/`：tool result 到 tool arg/sink 的 provenance graph。
- `behavior/`：会话行为基线。
- `security/`：URL 与 canonical path 边界。
- `persistence/`：批量异步事件写入。
- `provenance.ts`：按文件 fingerprint 增量扫描和 watcher 失效。
- `session-registry.ts`：session idle TTL 与 LRU 上限。
- Memory Guard 读写保护、完整性校验、隔离和共识检测。
- LLM-Judge 调度和语义风险补充。
- 系统预执行检查和运行时记录脱敏。

这里是核心安全逻辑，改动后必须运行 `npm --prefix openclaw-plugin run test:policy`。
