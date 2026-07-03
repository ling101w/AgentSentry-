# 玄鉴 系统功能说明

更新时间：2026-07-03

## 系统定位

玄鉴是一个嵌入 OpenClaw 的智能体运行时安全治理系统。它拦截智能体与外部工具之间的交互，对工具调用、代码执行、文件访问、API 调用、邮件发送和记忆写入进行实时审计、风险判定和阻断。

当前代码和插件目录仍使用 `AgentSentry` 命名，这是工程内部名；参赛作品名称使用“玄鉴”。

详细算法说明见 `reports/technical_design_and_algorithms.md`。

## 访问入口

| 地址 | 用途 |
|---|---|
| `http://<服务器IP>:8765/` | OpenClaw 插件控制台与记录入口 |
| `http://<服务器IP>:8765/command-lab` | 业务测试台，提交正常请求和对抗样本 |
| `http://<服务器IP>:8765/records` | 运行记录与风险观测 |
| `http://<服务器IP>:8765/security-screen` | 安全态势感知大屏 |
| `http://<服务器IP>:18789/` | OpenClaw Control UI |
| `http://<服务器IP>:8000/` | 历史离线原型与辅助展示，不作为主链路 |

## 数据来源

所有 8765 页面和大屏读取真实后端数据：

- `~/.openclaw/agentsentry/records.jsonl`
- `GET /api/stats`
- `GET /api/records`
- `GET /api/security/overview`
- `GET /api/lab/runs`

页面没有兜底假数据。接口不可用时显示空态、错误或 stale 状态。

## 五层防护

| 层级 | 功能 | 主要证据 |
|---|---|---|
| 基础扫描层 | 扫描 Skill、配置、敏感文件和供应链风险 | `foundation_scan`、Foundation finding |
| 输入净化层 | 检测外部邮件、网页、PDF、图片、工具返回污染 | Input Sanitization finding |
| 认知保护层 | 管控长期记忆写入、护照、哈希、保护键和隔离 | Memory Guard、memory passport |
| 决策对齐层 | 对比用户任务授权和当前工具计划，识别意图漂移 | Decision Alignment finding |
| 执行控制层 | 执行前检查文件、命令、API、邮件、网关和系统路径 | Execution Control、System Preflight |

## 核心能力

### 工具调用裁决

每个工具调用会输出：

- `allow`：允许执行。
- `ask`：需要审批或人工确认。
- `deny`：执行前阻断。

裁决基于工具名、参数、目标路径、收件人、API host、当前任务、历史上下文、污点状态、系统预执行策略和 LLM-Judge 语义复核结果。

### 任务授权 TaskSpec

系统从用户请求派生当前任务边界。例如：

- “总结网页”授权 `read_webpage`，不授权读取 `.env` 或发邮件。
- “保存报告到 notes/report.md”授权写入普通工作区文件，不授权写 `startup/` 或 `openclaw.json`。
- “发送项目进度给 user@example.com”授权白名单邮件，不授权外部归档邮箱。

### 信任标签与污点传播

系统为外部内容、工具结果、记忆和 Skill 打标签：

- 来源：用户、网页、邮件、PDF、图片、工具结果、记忆、配置、Skill、Webhook。
- 完整性：trusted、user、workspace、external、tainted。
- 机密性：public、internal、secret。
- 风险向量：提示注入、隐藏内容、敏感数据、外泄、持久化、工具劫持、权限、意图漂移、供应链。
- 污点画像：记录置信度、来源、标签、允许用途和禁止流向的 sink。

污染内容可以被读取和总结，但不能驱动其污点画像禁止的 sink，例如敏感文件读取、外部发送、命令执行、记忆写入、配置修改或 Skill 安装。

当前污点处理不是简单的“污染会话后一刀切”。系统会：

1. 判断污染数据来源和证据。
2. 生成污点画像，记录置信度、机密性、风险向量、允许用途和禁止 sink。
3. 判断当前工具动作是否属于被禁止的 sink。
4. 只在“不可信数据实际流向高风险 sink”时阻断或审批。
5. 在记录中保留 `taint_flows`，解释是哪条污点、为何禁止、流向哪个 sink。

因此，“总结有毒网页”可以通过；“网页隐藏指令诱导读取 `.env` 并外发”会被阻断。

### 语义动作图

新增的语义动作图不依赖公开 benchmark 的固定字段名。它遍历任意工具参数树，抽取：

- 敏感源：`.env`、OpenClaw 配置、SSH 私钥、token、credential 等。
- 本地读取：`fs.readFileSync`、`cat`、`open()` 等。
- 外部 sink：外部 URL、webhook、非白名单邮箱。
- 网络外发：`fetch`、`curl`、`requests.post`、upload、telemetry 等。
- 持久化：MEMORY、AGENTS、startup、cron、systemd、Skill 文件。
- 提权/系统副作用：sudo、chmod、systemctl、iptables、rm -rf 等。
- 伪装正常能力：天气、日历、翻译、摘要等声明与实际本地读取加外联行为冲突。
- 编码内容：base64、hex、URL percent、Unicode 转义、零宽字符和分隔符混淆。

### Memory Guard

长期记忆写入会生成 passport：

- key、来源、信任等级、创建/更新时间。
- 内容 SHA-256。
- 上下文哈希。
- HMAC 签名。
- 风险向量。
- 是否保护键。

普通偏好和数据分析经验可写入；系统角色、审批绕过、默认外发、保护键篡改、低信任来源权威记忆会被阻断或隔离。读取记忆时会重新校验内容哈希和护照签名，并对低信任、权威化或离群记忆触发审批。

### 行为基线

系统只从已放行操作学习会话内正常行为：

- 常见 API host。
- 常见邮件收件人。
- 常见文件路径根。
- 参数大小和参数结构。

后续同一会话出现目标突变或参数形态异常时会触发审批 finding。攻击样本不会被写入正常基线。

### LLM-Judge

LLM-Judge 使用 DeepSeek-compatible 接口进行语义复核，覆盖工具调用、消息、记忆写入和基础扫描。它是二道防线，即使关闭，确定性策略、污点传播、ABAC、Memory Guard 和系统预执行仍然工作。

LLM-Judge 在四个环节发挥作用：

- 消息/工具结果：判断是否包含提示注入、越狱、凭据外泄或恶意指令。
- 工具调用：判断动作是否与用户任务一致，是否可能外泄、破坏、越权或漂移。
- 记忆写入：判断候选长期记忆是否会污染未来行为或绕过审批。
- 基础扫描：判断 Skill、配置和工作区基础文件是否存在恶意能力或供应链风险。

Judge 返回低/中/高风险和理由。玄鉴不会把模型输出当成唯一裁决，而是转换为 finding，再与确定性规则、TaskSpec、污点流和系统预执行策略合并。

当前支持三种调度模式：

- `full`：所有启用的语义裁决面都调用 LLM-Judge，适合比赛全量复现实验。
- `risk-tiered`：低风险请求只走确定性策略；敏感路径、外部 sink、非平凡 shell、记忆写入、持久化和工具劫持信号才调用 LLM-Judge，适合生产降延迟。
- `off`：不调用 LLM-Judge，只保留确定性策略、污点传播、ABAC、Memory Guard 和系统预执行。

`/command-lab` 中 `semanticJudge=on` 会映射为 `full`，因此之前的全量 LLM-Judge benchmark 仍可复现。`semanticJudge=default` 保留服务端当前调度，例如本轮 `risk-tiered` 复测。

## 实验与指标

最新公开 benchmark：

- 综合攻击回归，risk-tiered：520 条，攻击保护率 100.0%，高风险漏放率 0.0%，正常放行率 100.0%，误拦 0。
- 非提示注入工具攻击专项，risk-tiered：320 条，工具攻击保护率 100.0%，高风险漏放率 0.0%，正常放行率 100.0%，误拦 0。
- 对比 full LLM-Judge：保护能力保持 0 漏放，误拦从 7 条降到 0 条，总耗时从约 135.2 分钟降到约 76.8 分钟。

最新报告：

- `reports/benchmark_risk_tiered/benchmark_eval_report.risk_tiered.md`
- `reports/benchmark_risk_tiered/tool_attack_benchmark_report.risk_tiered.md`
- `reports/project_name_and_benchmark_summary.md`
- `reports/benchmark_risk_tiered/xuanjian_benchmark_risk_tiered_record.txt`

## 已知限制

- eBPF 当前受运行权限限制不可用，系统已如实展示原因；应用层预执行策略处于 active，并在健康接口展示 `isolation.mode=pre-exec`、已启用的预执行控制、限制和推荐运行时隔离措施。
- 邮件工具使用本地 outbox 受控实现。
- destructive shell payload 不实际破坏主机，只评估执行前真实裁决。
- 当前指标来自公开 benchmark 映射和受控业务工具，生产环境仍需持续积累正常业务样本评估误判。
