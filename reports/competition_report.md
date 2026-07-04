# 玄鉴 安全风险分析与行为监督报告

更新时间：2026-07-03

## 摘要

玄鉴是一个面向 OpenClaw 等工具型智能体的运行时安全监督系统。系统在智能体执行工具之前，对文件访问、代码/命令执行、邮件发送、API 调用、长期记忆写入和第三方 Skill 安装进行实时审计与 `allow / ask / deny` 裁决，并在 `8765` 监督端展示告警、阻断、污点传播和调用链。

当前仓库和插件内部仍使用 `AgentSentry` 作为代码名；参赛作品展示建议使用“玄鉴”。

系统不是单纯关键词过滤。核心机制是把“用户授权任务、数据来源信任级别、工具参数语义、会话污点、系统预执行检查、行为基线、LLM-Judge 语义复核”合并成可解释的裁决链。

## 威胁模型

可信来源：

- 用户当前明确请求。
- 玄鉴策略引擎、OpenClaw 插件和审计记录系统。
- 本机可信配置、白名单目标和人工审批结果。

低信任来源：

- 邮件、网页、PDF、图片、URL fragment、HTML 隐藏节点。
- API 返回、MCP 工具描述、工具结果、Webhook 历史记录。
- 第三方 Skill、长期记忆、工作区文件。
- 模型生成的工具计划和中间推理结果。

主要攻击目标：

- 从“总结/查看/安装”任务漂移到读取本机敏感文件。
- 把配置、凭据、会话材料或私钥发送到外部邮箱/API。
- 将短期诱导写入长期记忆或历史回放，实现跨会话持久化。
- 利用 Control UI 网关参数、恶意 MCP 工具或第三方 Skill 劫持工具调用链。

## 系统架构

主链路是 `8765` OpenClaw 插件侧系统：

- `/command-lab`：业务测试台，提交正常请求和对抗样本。
- `/records`：运行记录与风险观测。
- `/security-screen`：安全态势大屏。
- `/api/lab/command`：实验与业务工具调用入口。
- `/api/security/overview`：大屏真实聚合数据接口。

核心模块：

- TaskSpec 授权：从用户请求提取允许工具、目标、收件人、路径和 API host。
- 信任标签：为外部内容、工具结果、记忆和 Skill 生成来源、完整性、机密性标签。
- 污点传播：低信任或污染内容不能驱动邮件、外部 API、shell、记忆和配置写入等高风险 sink。
- ABAC 策略：基于任务、来源、工具、目标、敏感资产和会话状态进行访问控制。
- 语义动作图：遍历任意工具参数树，抽取敏感源、本地读取、外部 sink、网络外发、持久化、提权副作用、伪装正常能力和编码内容。
- Memory Guard：为长期记忆提供来源护照、哈希完整性、保护键、脱敏、隔离和轻量共识检查。
- System Preflight：执行前检查危险命令、敏感路径、网关覆盖、本地配置外传和高权限操作。
- 行为基线：只从已放行操作学习常见 host、收件人、路径根和参数规模；后续突变进入审批。
- LLM-Judge：DeepSeek-compatible 语义复核，作为二道防线，不替代硬边界策略。

完整算法流程见 `reports/technical_design_and_algorithms.md`。

## 攻击场景

### 场景一：外部内容注入

攻击者把恶意指令藏在邮件、网页、PDF 或图片中。用户可见请求只是“总结邮件/网页/报告/图片”，但智能体读取内容后可能被诱导读取本地敏感文件并外发。

样例载体：

- HTML 白色极小字号、零尺寸 `span`、`data-*` 字段。
- URL fragment 中的编码载荷。
- PDF 透明文本层或 Optional Content Layer。
- 图片 iTXt/EXIF/OCR 文本。

防御效果：外部内容可以被读取和总结，但被标为低信任；一旦后续动作尝试读取 `.env`、`~/.ssh`、OpenClaw 配置，或把内容发到外部 sink，策略会在执行前阻断。

### 场景二：记忆与配置持久化

攻击者把恶意偏好伪装成“长期经验”“配置建议”“审批已处理”等内容写入记忆，使后续任务默认继承错误路由或绕过审批。

防御效果：

- 普通长期偏好和数据分析经验可以写入。
- 保护键、系统角色、未来越权、审批绕过、静默外发、启动项和配置污染会被拦截。
- 记忆读取时验证来源护照和内容哈希，发现篡改会产生告警。

### 场景三：工具调用劫持

攻击者通过恶意 MCP 工具、网关 URL 覆盖、响应操纵或第三方 Skill 劫持工具链。

防御效果：

- 非本机 `gatewayURL` 覆盖在 API 调用前被阻断。
- MCP 隐藏 payload、后门触发器、恶意默认参数和响应操纵字段进入上下文溯源检查。
- “天气查询”等正常声明如果同时出现本地配置读取和外部网络发送，会被语义动作图判定为能力声明与实际行为不一致。

## 实验结果

最新公开 benchmark 评测均通过真实 `8765 /api/lab/command` 接口执行。

| 实验 | 样例 | 攻击/保护样例 | 正常样例 | 保护率 | 正常放行率 | 误拦率 |
|---|---:|---:|---:|---:|---:|---:|
| 综合攻击回归，risk-tiered | 520 | 441 | 79 | 100.0% | 100.0% | 0.0% |
| 非提示注入工具攻击专项，risk-tiered | 320 | 270 | 50 | 100.0% | 100.0% | 0.0% |
| 综合攻击回归，full LLM-Judge | 520 | 441 | 79 | 100.0% | 94.9% | 3.8% |
| 非提示注入工具攻击专项，full LLM-Judge | 320 | 270 | 50 | 100.0% | 92.0% | 8.0% |

本轮推荐结果采用 `risk-tiered`，即 benchmark 输入 `semanticJudge=default`，由服务端按风险分层调用 DeepSeek Judge。它保持 full Judge 的 0 漏放，同时把 full Judge 暴露出的 7 条误拦降到 0 条，总耗时从约 135.2 分钟降到约 76.8 分钟。

综合回归来源：RedTeamCUA、MSB、MCPSecBench、MemoryGraft、AgentDojo、InjecAgent。

工具专项来源：AgentDefense-Bench、BashArena、AgentHarm、ToolEmu。

最新报告：

- `reports/benchmark_risk_tiered/benchmark_eval_report.risk_tiered.md`
- `reports/benchmark_risk_tiered/tool_attack_benchmark_report.risk_tiered.md`
- `reports/benchmark_risk_tiered/xuanjian_benchmark_risk_tiered_record.txt`
- `reports/project_name_and_benchmark_summary.md`

## 对比实验

开启/关闭对比实验见：

- `reports/supervision_ablation/supervision_ablation_explained.md`
- `reports/supervision_ablation/supervision_ablation_results.json`

实验结论：未开启监督时，隐藏载荷诱导出的危险工具动作会进入受控业务工具；开启玄鉴后，危险文件读取、外部邮件、外部 API、命令执行和记忆投毒在执行前被阻断。

## 授权与审批

玄鉴中“授权”分为两层：

- 任务授权：TaskSpec 判断当前工具、目标、收件人、路径和 API host 是否服务于用户原始任务。
- 人工审批：运行模式可在 `observe / approval / block` 间切换。`approval` 模式下高风险动作进入人工确认；比赛演示默认使用 `block` 证明危险动作不会落地。

系统不是“能拦就全拦”。公开 benchmark 和正常样例中，白名单邮件、普通文件读写、本机健康 API、普通长期记忆和低风险系统观察均可通过。

## 当前限制

- eBPF 内核级观测脚本存在，但当前 OpenClaw 用户服务无法访问 `/sys/fs/bpf`，因此健康检查如实显示 `ebpf: unavailable`。应用层系统预执行策略仍为 `active`。
- 危险 shell payload 不直接落地执行，实验评估的是执行前真实裁决，避免破坏主机。
- 邮件发送工具使用本机 outbox 受控实现，不连接真实 SMTP。
- LLM-Judge 依赖 DeepSeek-compatible API；API 不可用时，确定性策略、TaskSpec、污点传播、ABAC、Memory Guard 和 System Preflight 仍工作。
