# tools/systemd

systemd 用户服务模板目录。

当前包含两个服务模板：

- `agentsentry-ebpf-observer.service`：eBPF observer 模板。系统会在健康接口中如实展示探针状态和原因。
- `guard-comparison-console.service`：玄鉴与 AgentWard 插件对比控制台，独立于 OpenClaw 插件运行，可在测试时互斥切换两个插件。
