# tools/systemd

systemd 用户服务模板目录。

当前包含两个服务模板：

- `agentsentry-ebpf-observer.service`：eBPF observer 模板。系统会在健康接口中如实展示探针状态和原因。
- `agentsentry-ebpf-enforcer.service`：可选的内核网络强制层。它要求 cgroup BPF、root 权限和 BCC；能力不满足时服务退出，不伪装成已启用。
- `openclaw-gateway-agentsentry-enforcer.conf`：OpenClaw 网关 drop-in。安装后，玄鉴的 shell 沙箱会在事务开始时登记进程，事务结束时注销进程。
- `guard-comparison-console.service`：玄鉴与 AgentWard 插件对比控制台，独立于 OpenClaw 插件运行，可在测试时互斥切换两个插件。

启用 enforcer 后，每个进入 shell 影子工作区的事务都会被移动到独立的 cgroup，内核 cgroup BPF egress 程序允许回环通信，丢弃该事务的非回环 IPv4/IPv6 出站包。事务完成后会移回原 cgroup 并解除挂载。该层只负责网络边界；文件提交、工作区回滚和策略降级仍由玄鉴插件控制，不能撤销已经发生的外部邮件、API 写入等不可逆副作用。
