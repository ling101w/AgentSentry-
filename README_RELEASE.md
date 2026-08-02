# 玄鉴 OpenClaw 插件交付包

发布重建日期：2026-08-02

归档文件名保留 `xuanjian-openclaw-plugin-20260703.tar.gz`，用于兼容既有交付链接；包内代码和构建产物来自当前 release commit，不是 2026-07-03 的旧快照。

## 部署

在已安装 OpenClaw CLI 的环境中：

```bash
cd openclaw-plugin
npm run build
./setup.sh --force
```

启动或重启 Gateway 后，在 OpenClaw 中运行：

```text
/agentsentry profile competition
/agentsentry
```

打开 `/agentsentry` 返回的认证 bootstrap URL。裸 `http://127.0.0.1:8765/` 在全新浏览器中按设计返回 `401`；bootstrap URL 设置 HttpOnly、SameSite=Strict session cookie 后立即跳转到不含 token 的地址。

## 安全架构

唯一生产执行链为：

```text
normalize -> TaskSpec V2 capability authorization -> field provenance/taint graph
          -> deterministic enforcement -> semantic judge (ambiguous only)
          -> final decision -> apply effects and async telemetry
```

`read_file` 和 `write_file` 使用基于真实 workspace 的 canonical path boundary，存在的 symlink/junction 必须解析到授权 root 内。

eBPF observer 对 `execve/openat` 提供可判定的运行证据。`connect` 当前只记录 syscall 的 pid/comm/fd，不提取或分类 destination sockaddr，因此不宣称提供目标地址异常外联检测；网络目的地控制来自应用层 URL/command preflight 和部署侧 egress allowlist。

## 验证

```bash
npm --prefix openclaw-plugin run ci
npm --prefix openclaw-plugin run sbom
python -m pytest -q
```

Dashboard fresh-browser 验收脚本：

```bash
AGENTSENTRY_DASHBOARD_ACCESS_URL='<temporary bootstrap URL>' \
node openclaw-plugin/scripts/dashboard-demo-acceptance.mjs
```

脚本验证裸 URL 401、bootstrap 去 token、session cookie 属性和默认 attack demo 的 deny 裁决。
