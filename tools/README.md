# tools

运维和集成工具目录。

- `openclaw-public-proxy.mjs`：OpenClaw Control UI 公网访问代理。
- `guard-comparison-console.mjs`：独立插件对比控制台，用于互斥切换 `agent-sentry` 与 `agent-ward`，按 benchmark 用例记录二者在同一输入下的工具调用裁决和输出摘要。
- `promptbeat-openclaw-adapter.mjs`：PromptBeat/OpenClaw 适配工具。
- `agentsentry-ebpf-observer.bt`：eBPF 观测脚本草案。
- `systemd/`：用户级服务模板。

这里的工具不属于核心检测策略，核心逻辑在 `openclaw-plugin/core/`。
