# openclaw-plugin/core

玄鉴 OpenClaw 插件的策略与算法核心。

主要职责：

- 工具调用标准化和策略裁决。
- TaskSpec 授权边界、ABAC 会话策略和动态意图跟踪。
- 污点传播、信任标签、敏感源到外部 sink 检查。
- Memory Guard 读写保护、完整性校验、隔离和共识检测。
- LLM-Judge 调度和语义风险补充。
- 系统预执行检查和运行时记录脱敏。

这里是核心安全逻辑，改动后必须运行 `npm --prefix openclaw-plugin run test:policy`。
