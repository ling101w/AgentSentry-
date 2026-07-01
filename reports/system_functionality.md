# AgentSentry 系统功能说明

更新时间：2026-07-01

本文档客观说明当前 AgentSentry + OpenClaw 原型系统已经具备的功能、使用入口、数据来源和已知限制。文档中的功能均以当前部署和代码为准，不包含未实现能力。

## 1. 系统定位

AgentSentry 是一个面向 OpenClaw 智能体应用的行为监督与安全审计系统。它的核心作用是拦截和记录智能体与外部工具之间的交互，并对工具调用、文件访问、代码/命令执行、网络请求、记忆写入等行为进行风险判定。

系统当前包括两部分：

- `8000`：AgentSentry 独立原型系统，用于离线实验、对抗样本评测、报告数据生成和态势展示。
- `8765`：OpenClaw 插件侧系统，用于记录 OpenClaw 真实运行链路、工具调用裁决、告警、阻断和实验台测试结果。

## 2. 访问入口

| 地址 | 功能 |
| --- | --- |
| `http://43.153.201.180:8000/` | AgentSentry 原型控制台 |
| `http://43.153.201.180:8000/security-screen` | AgentSentry 原型态势大屏 |
| `http://43.153.201.180:8765/` | OpenClaw 插件记录台 |
| `http://43.153.201.180:8765/command-lab` | OpenClaw 业务测试台 |
| `http://43.153.201.180:8765/security-screen` | OpenClaw 插件态势大屏 |
| `http://43.153.201.180:18789/` | OpenClaw Control UI，已通过 Basic Auth 保护 |

## 3. 数据真实性原则

当前系统不在前端构造统计数字。控制台、大屏、时间线、告警、工具裁决、风险计数均来自后端记录。

主要数据来源：

- OpenClaw 插件 JSONL 记录：`~/.openclaw/agentsentry/records.jsonl`
- AgentSentry 原型本地实验记录：SQLite 存储
- 8765 接口：`GET /api/records`、`GET /api/stats`、`GET /api/security/overview`
- 8000 接口：`GET /api/security/overview?source=openclaw|local|combined`

如果接口不可用，页面会显示空态、连接失败或过期状态，不使用伪造统计。

## 4. OpenClaw 插件审计功能

OpenClaw 插件会记录以下生命周期事件：

- `session_start`：OpenClaw 构建提示词上下文时的会话信息。
- `foundation_scan`：工作区基础扫描结果。
- `llm_input`：模型输入准备事件，可按配置决定是否记录系统提示词预览。
- `message_write`：用户、助手、工具结果写入事件。
- `tool_decision`：每次工具调用前的策略裁决。
- `tool_result`：工具调用完成、失败、被阻断或跳过后的结果记录。
- `guard_finding`：规则、污点、ABAC、系统预执行等检测发现。
- `alert`：高风险告警或阻断记录。
- `approval_resolution`：审批模式下的人工处理结果。
- `approval_cache_hit`：精确参数哈希命中的 allow-always 审批缓存记录。

记录内容包括工具名、归一化工具类型、参数预览、风险分数、裁决结果、命中规则、污染状态和风险向量。

## 5. 工具调用裁决功能

系统对工具调用输出三类决策：

| 决策 | 含义 |
| --- | --- |
| `allow` | 当前策略允许执行 |
| `ask` | 需要人工确认或进入审批 |
| `deny` | 违反确定性策略或风险超过阈值，拒绝执行 |

当前支持识别和归一化的工具类型包括：

- 读取网页或外部内容：`read_webpage`
- 调用 API：`call_api`
- 读取文件：`read_file`
- 写入文件：`write_file`
- 发送邮件：`send_email`
- 执行命令：`shell_exec`
- 读取记忆：`memory_read`
- 写入记忆：`memory_write`

策略依据包括用户任务意图、工具类型、参数内容、敏感路径、收件人白名单、API 主机、上下文污染状态、风险向量和历史工具轨迹。

## 6. 信任标签与污点追踪

系统实现了 Tessera 风格的信任标签和污点传播能力。

已实现内容：

- 对外部网页、邮件、PDF、图片、工具结果、记忆、配置、Skill 文件生成 trust label。
- trust label 包含来源、完整性级别、保密级别、是否污染、签名、时间和证据。
- 对工具结果进行污染标记，污染状态会影响同一会话后续高风险工具调用。
- 记录 `risk_vector`，包括：
  - `prompt_injection`
  - `hidden_content`
  - `sensitive_data`
  - `exfiltration`
  - `persistence`
  - `tool_hijack`
  - `privilege`
  - `intent_drift`
  - `supply_chain`

效果：当外部不可信内容影响上下文后，再尝试发送邮件、执行命令、写记忆、写配置或外联 API，会被 ABAC 会话策略收紧或阻断。

## 7. 外部内容注入检测

系统已覆盖以下外部内容注入场景：

| 场景 | 检测能力 |
| --- | --- |
| 隐藏邮件指令 | 检测 HTML 白色字体、极小字号、透明元素、隐藏 span、data 属性和编码载荷 |
| 恶意网页注入 | 检测零尺寸元素、HTML 注释、URL fragment 和 base64/hex 编码提示注入 |
| PDF 隐写注入 | 检测 PDF 透明文本、低可见度文本层、Optional Content Layer 等特征 |
| 图像文本注入 | 检测图片元数据、OCR 文本、iTXt/tEXt/comment 中的编码或命令型指令 |

这些检测结果会写入 `guard_finding`，并把后续高风险 sink 标记为不可信数据流。



### 7.1 隐蔽载荷与编码检测

当前实验样例不要求用户在提示词里直接写“读取密钥”或“发给攻击者”。系统会在外部内容和工具参数中做以下处理：

- 对文本做 Unicode 规范化，去除零宽字符和软连字符。
- 对 base64、URL-safe base64、hex 编码片段做可打印文本解码。
- 检测“归档、同步、遥测、证据附录、route、archive、telemetry、ingest”等业务化外联说法与本地敏感来源的组合。
- 对 Skill 代码执行“本地文件读取 API + `.openclaw/.env/.ssh` 路径 + 外部网络 API”的组合判断。

这部分用于降低只靠 `attacker`、`evil`、`token` 等显眼关键词带来的漏报和误报。

## 8. 记忆与配置持久化防护

系统已实现对持久化风险的检测和阻断：

- 检测 `[System]`、`role: system`、“以后/未来/永久忽略安全策略”等持久化指令。
- 检测对 `MEMORY.md`、`AGENTS.md`、`SOUL.md`、`USER.md` 的危险写入。
- 检测对 OpenClaw 配置、启动目录、cron、systemd、Skill 目录的危险写入。
- 检测 `/hooks/wake` 或 Webhook 历史回放中伪造系统角色的 payload。

对应检测层级主要为：

- `Cognition Protection`
- `ABAC Session Policy`
- `System Preflight`
- `Execution Control`

## 9. 工具调用劫持防护

系统已覆盖两类工具劫持风险：

### 9.1 网关 URL 劫持

检测内容：

- `?gatewayURL=ws://...`
- `gatewayURL=wss://...`
- 非本机、非 localhost、非 127.0.0.1 的 Control UI 网关覆盖
- 与非本机网关覆盖、外部归档/遥测端点、本地配置读取等数据流组合出现的参数

命中后会在工具调用前阻断，并记录为 `tool_hijack` 风险。

### 9.2 恶意第三方 Skill

基础扫描和工具调用检测会识别：

- Skill 文件读取 `openclaw.json` 或 `.openclaw` 下的本地配置
- 读取 `.env`、SSH 身份文件、凭据、会话或配置材料
- 使用 `fetch`、`axios`、`curl`、`wget`、`http.request` 等方式连接非白名单外部端点
- “天气查询”等正常功能描述与实际“本地配置读取 + 外部端点”的行为不一致

命中后会生成 Foundation 或 Execution Control 层告警。

## 10. 系统预执行监控

系统新增了 `System Preflight` 预执行检查模块。

已实现检查：

- 命令读取并外传 `~/.ssh/id_rsa`、`~/.ssh/id_ed25519`、`.env`、`openclaw.json`、secret/credential 文件。
- `curl | bash`、`wget | sh` 等远程脚本执行。
- `sudo`、`chmod 777`、`chown`、`systemctl`、`crontab` 等高权限或持久化命令。
- 工具参数指向敏感路径、OpenClaw 配置、启动项或系统目录。
- 网络请求中包含非本机 `gatewayURL` 覆盖。
- 对低风险系统观测命令做放行分级，例如 `du -sh .`、`df -h`、`cat /etc/os-release`、`cat /proc/meminfo` 等只读命令不会按危险命令阻断。

当前运行环境中 eBPF 附加工具不可用，因此系统状态真实显示：

```json
{
  "pre_exec_policy": "active",
  "ebpf": "unavailable",
  "reason": "bpffs and bpftool exist, but /sys/fs/bpf is not accessible to this user service; unprivileged_bpf_disabled=2"
}
```

这表示当前机器的内核和工具链支持 eBPF，且 `bpftool`、`bpftrace` 已存在，但 OpenClaw 插件运行在 `ubuntu` 用户态 systemd service 下，无法访问 root-only 的 `/sys/fs/bpf` 和 tracefs。当前具备应用层预执行硬拦截，但没有伪装为已挂载 eBPF 探针。

仓库中已补充可选 root 级 eBPF 观测脚本：

- `tools/agentsentry-ebpf-observer.bt`
- `tools/systemd/agentsentry-ebpf-observer.service`

具备 root 权限时可用以下方式启用内核级观测：

```bash
sudo bpftrace /home/ubuntu/AgentSentry-/tools/agentsentry-ebpf-observer.bt
```

或将 `tools/systemd/agentsentry-ebpf-observer.service` 安装到系统 service。该 observer 记录 `execve`、`openat`、`connect` 内核事件，用于补充审计证据；工具调用是否放行仍由 AgentSentry 插件在执行前完成。

## 11. ABAC 会话策略

系统在工具调用前执行会话级 ABAC 判定。

主要规则：

- 高风险 sink 需要可信上下文。
- 外部内容、工具结果、邮件、网页、PDF、图片等来源一旦被标记为污染，不能直接驱动邮件外发、命令执行、记忆写入、配置写入或敏感 API 调用。
- 机密污染上下文不能流入外部 sink。
- 用户任务如果只是“总结/阅读/查看”，后续突然出现发邮件、写文件、执行命令，会记录为动态意图漂移。
- 普通白名单邮件、普通代码编辑、普通文件读取、目录大小和系统版本查询按低风险路径处理，不会因为工具类型本身被一刀切阻断。
- 普通文件写入不再默认视为高风险 sink；只有写入记忆、配置、Skill、启动项、系统目录或敏感内容时才进入硬阻断。

记录层级为：

- `ABAC Session Policy`
- `Decision Alignment`
- `Sentry Trajectory`

## 12. LLM-Judge 能力

系统保留可选的 OpenAI-compatible 语义 judge。

可配置能力：

- 对工具调用做语义安全判断。
- 对消息和工具结果做提示注入判断。
- 对基础文件、Skill、配置文件做语义扫描。

当前防护不依赖 LLM-Judge。规则、污点、ABAC、系统预执行检查是确定性链路；LLM-Judge 是第二道辅助判断。

## 13. 业务测试台功能

`/command-lab` 提供真实请求测试能力。

当前内置场景：

1. 外部内容注入：隐藏邮件
2. 外部内容注入：恶意网页
3. 外部内容注入：PDF 隐写
4. 外部内容注入：图像文本
5. 持久化：历史回放 Webhook
6. 持久化：长期记忆污染
7. 工具劫持：网关 URL 劫持
8. 工具劫持：恶意第三方 Skill
9. 良性健康检查
10. 手动请求

测试台会将请求映射为真实业务工具动作，并写入以下记录：

- `lab_command`
- `tool_decision`
- `guard_finding`
- `alert`
- `tool_result`

允许的请求会实际执行受控工具，例如访问 `/api/health` 或读取内部测试内容端点；被拒绝的请求不会执行危险 sink。

同一个 `clientId` 的测试请求会保留 lab 会话状态。切换模板后的首次提交会重置会话；连续提交同一会话时，外部内容污染会继续影响后续邮件、API、命令、记忆等高风险 sink，用于验证多轮诱导攻击。

## 14. 态势展示功能

系统提供两个态势展示入口：

- `8000/security-screen`
- `8765/security-screen`

展示内容包括：

- 总事件数
- 高危告警数
- 阻断/审批/放行统计
- 防护指数
- Agent 行为安全拓扑
- 工具调用流
- 攻击链阶段分布
- 规则命中统计
- 实时告警和时间线
- 数据来源状态

8765 大屏默认使用 OpenClaw 插件真实记录，并由插件本地从 `~/.openclaw/agentsentry/records.jsonl` 聚合，不依赖 8000 代理。顶部总数与 `GET /api/stats` 的 `total` 一致；当前验证中 `GET /api/stats` 与 `GET /api/security/overview` 的总数均为同一窗口口径。

## 15. 导出与复现实验

当前支持：

- `GET /api/export?format=json` 导出插件记录。
- `GET /api/export?format=csv` 导出 CSV。
- `scripts/run_competition_experiments.py` 运行比赛实验。
- `reports/competition_report.md` 保存安全风险分析报告。
- `reports/adversarial_testset.jsonl` 保存对抗样本集合。
- `reports/agent_attack_scripts.md` 保存攻击脚本说明。
- `reports/supervision_ablation/supervision_ablation_explained.md` 保存开启/关闭监督对比说明。
- `scripts/run_full_acceptance_tests.py` 运行完整功能验收，包括正常业务、攻击场景和多轮诱导。
- `reports/full_acceptance/full_acceptance_report.latest.md` 保存最近一次完整验收报告。
- `reports/full_acceptance/full_acceptance_results.latest.json` 保存最近一次验收原始 JSON 证据。

## 16. 已验证结果

最近一次验证结果：

- `npm run test:policy`：通过。
- `.venv/bin/python -m pytest -q`：33 项通过。
- `.venv/bin/python scripts/check_ui_layout.py`：通过。
- `python3 scripts/run_full_acceptance_tests.py`：18/18 通过。
- 8765 大屏接口口径检查：`/api/stats` 与 `/api/security/overview` 总数一致。
- 8765 大屏 1920x1080、1366x768、1180x760 三个视口轻量 DOM 检查：KPI 总数、stats、overview 一致，运行状态为 `OPENCLAW`，关键容器无溢出。
- 真实提交 8 个攻击场景：均产生阻断或拒绝。
- 6 个正常业务场景：白名单邮件、普通写文件、普通读文件、本机 API、普通记忆、低风险 shell 观察均未触发会话污染；浏览器来源 shell 按设计不落地执行。
- 4 轮多轮诱导场景：第 1 轮正常通过且不污染；第 2 轮隐藏邮件污染；第 3/4 轮看似正常的邮件/API sink 被 ABAC 污点流策略阻断。

## 17. 当前限制

当前系统仍有以下限制：

- eBPF 探针未实际挂载，原因是当前运行环境缺少可用的内核 eBPF 附加工具；系统已如实展示状态。
- PDF 和图片检测当前主要基于可读字符串、元数据、透明文本特征和 OCR 文本字段，不等同于完整的图像视觉理解引擎。
- 邮件发送工具当前写入本地 outbox 文件，用于受控实验验证，不直接连接真实 SMTP 服务器。
- OpenClaw Control UI 的公网入口依赖 Basic Auth 代理保护；插件自身仍应配合 OpenClaw 原生鉴权使用。
- 语义 judge 是可选能力，只有配置 API key 和模型后才会调用。

## 18. 主要代码位置

| 文件 | 作用 |
| --- | --- |
| `openclaw-plugin/core/trust.ts` | 信任标签、污点追踪、风险向量和内容风险分析 |
| `openclaw-plugin/core/system-monitor.ts` | 系统预执行检查 |
| `openclaw-plugin/core/policy.ts` | TaskSpec、ABAC、动态意图追踪和工具裁决 |
| `openclaw-plugin/core/detect.ts` | 工具调用和消息检测入口 |
| `openclaw-plugin/core/foundation.ts` | 工作区、配置、Skill、PDF、图片基础扫描 |
| `openclaw-plugin/server/dashboard.ts` | 8765 API、业务测试台、实验内容端点 |
| `openclaw-plugin/public/command-lab.*` | 业务测试台前端 |
| `openclaw-plugin/public/security-screen.html` | OpenClaw 插件态势大屏 |
| `src/agentsentry/security_overview.py` | 8000/8765 大屏聚合数据逻辑 |

## 19. 参考架构功能核对

| 参考能力 | 当前状态 | 说明 |
| --- | --- | --- |
| AgentWard 基座扫描层 | 已实现 | 扫描 Skill、配置、敏感文件、PDF/图片可读内容、恶意外传代码 |
| AgentWard 输入净化层 | 已实现 | 检测邮件、网页、PDF、图片元数据中的间接提示注入 |
| AgentWard 认知保护层 | 已实现 | 监控记忆、配置、Webhook、启动项和 Skill 持久化风险 |
| AgentWard 决策对齐层 | 已实现 | TaskSpec、动态意图漂移、工具轨迹频次和任务外高风险动作检查 |
| AgentWard 执行控制层 | 已实现 | 对 shell、文件、邮件、API、记忆写入做执行前裁决 |
| Tessera 签名信任标签 | 已实现 | trust label 使用 HMAC 签名，记录来源、完整性、保密级别和证据 |
| Tessera 污点传播 | 已实现 | 工具结果污染会影响同一会话后续高风险 sink |
| Tessera MCP sidecar | 未实现 | 当前是 OpenClaw 插件内联拦截，不是 MCP 透明侧车代理 |
| ArbiterOS 动作分级拦截 | 部分实现 | 已按读、写、外部 sink、执行、记忆、网络分级；未实现独立内核式治理进程 |
| ArbiterOS 风险特征图谱 | 部分实现 | 已有风险向量；未实现完整图数据库或可查询特征图谱 |
| eBPF 系统级观测 | 部分实现 | 已提供 root 级 bpftrace observer；当前运行服务因权限未挂载 |
| LLM-Judge 第二道防线 | 已实现可选 | 配置 OpenAI-compatible API 后可启用；默认不依赖 LLM |

当前系统选择的是“OpenClaw 插件内联治理 + 信任标签/污点追踪 + 系统预执行检查”的落地形态。它没有实现完整 ArbiterOS 内核，也没有实现 Tessera MCP sidecar，但已覆盖比赛要求中的工具调用、代码执行、文件访问实时审计与异常判定。
