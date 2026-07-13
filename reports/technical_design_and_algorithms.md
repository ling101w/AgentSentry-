# 玄鉴 技术架构与算法设计说明

更新时间：2026-07-12

实现更新（2026-07-12）：主插件已加入 TaskSpec V2 显式能力授权、记忆非授权原则、字段级 Provenance ID、Tool Security Manifest、Judge 单调合并、比赛配置档、TypeScript CI，以及跨工具调用的会话级 Semantic Action Graph V2。文末历史 benchmark 数字均为公开样例的 `/command-lab` 映射回归，不代表盲测或原生 AgentDojo；原生结果仍以仓库中的 `not_run` 状态为准。

本文用于解释玄鉴的核心技术路线。它不按代码变量讲实现，而按“智能体一次请求如何被治理”的流程说明算法设计、数据流、污点传播、LLM-Judge 和系统级控制如何协同工作。

## 1. 总体设计思想

玄鉴把智能体安全问题建模为三个问题：

1. 这个动作是否在用户当前授权任务内。
2. 影响这个动作的数据来源是否可信。
3. 这个动作落地后会产生什么工具副作用。

因此系统不是只判断一句话是否像攻击，也不是单纯做关键词过滤。它在智能体执行工具前，把用户任务、上下文来源、工具参数、历史行为、记忆状态、系统边界和 LLM-Judge 语义复核合并成一个可解释裁决，输出 `allow / ask / deny`。

玄鉴当前采用“四域一环”架构，而不是按通用智能体生命周期模板机械拆分：

| 结构 | 作用 |
|---|---|
| 上下文溯源域 | 判断上下文从哪里来、是否可信、是否包含隐藏注入、供应链风险或敏感内容。 |
| 状态完整性域 | 判断长期记忆、历史回放、配置状态是否被污染或篡改。 |
| 意图授权域 | 判断工具调用是否仍在用户当前授权任务范围内，并结合 ABAC 和污点流做越权判断。 |
| 工具边界域 | 在工具真正落地前检查文件、邮件、API、shell、网关和系统级边界，并接入 eBPF 运行证据。 |
| 证据回流环 | 把工具结果、审批、运行时审计和风险向量回写到会话状态，用于收紧后续决策。 |

## 2. 端到端裁决流程

一次请求进入系统后，按以下顺序处理：

1. 请求进入 OpenClaw 插件链路，玄鉴记录用户消息、场景、会话和运行编号。
2. TaskSpec 模块从用户请求中抽取任务授权边界，例如允许访问的路径、API host、收件人、工具类型和可接受副作用。
3. 上下文溯源域检查用户消息和外部内容，识别隐藏 HTML、URL fragment、PDF 透明文本、图像元数据、工具返回注入等污染源。
4. 信任标签模块为外部内容、工具返回、记忆、配置和 Skill 生成来源、完整性、机密性、风险向量和签名标签。
5. 单次调用语义事实抽取器递归遍历当前工具参数，识别敏感源、本地读取、外部 sink、网络外发、持久化、提权副作用、伪装能力和编码混淆。
6. 会话级 Semantic Action Graph V2 把 TaskSpec 意图、能力授权、工具动作、字段级数据、变换过程和最终 sink 连接成跨调用有向因果链。
7. 污点传播模块判断不可信数据是否正在流向高风险 sink，例如外部邮件、外部 API、shell、敏感文件读取、记忆写入或 Skill 安装。
8. ABAC 策略模块把“主体、资源、动作、环境”合并判断：当前任务是否授权、目标是否越界、来源是否可信、历史上下文是否污染。
9. Memory Guard 在记忆读写路径做来源护照、哈希完整性、保护键、低信任权威记忆和离群记忆检查。
10. 工具边界域的 System Preflight 在工具执行前检查危险 shell、系统路径、网关覆盖、容器逃逸、持久化启动项和高权限命令。
11. LLM-Judge 按当前调度模式对消息、工具调用、记忆写入和基础文件进行语义复核。
12. 策略引擎合并所有 finding，计算风险分数和风险向量，输出 `allow / ask / deny`。
13. 监督端实时展示工具裁决、阻断理由、字段血缘、带证据强度的因果链、风险拓扑、规则命中和统计指标。

## 3. TaskSpec：任务授权建模

TaskSpec 的作用是把自然语言任务转成可检查的授权边界。

示例：

- “总结这个网页”只授权读取网页和生成摘要，不授权读取 `.env`、OpenClaw 配置或发邮件。
- “发送项目进度给 user@example.com”授权邮件工具和指定收件人，不授权外部归档邮箱。
- “把报告保存到 notes/report.md”授权工作区普通文件写入，不授权写 `startup/`、`MEMORY.md`、`openclaw.json` 或 Skill 目录。

TaskSpec 不追求理解所有业务语义，而是为工具动作提供最小授权边界。后续工具调用如果超出边界，会被判为意图漂移或越权；如果风险不确定，则进入 `ask` 或审批模式。

### 3.1 TaskSpec V2 能力结构

V2 不再只输出粗粒度 `allowed_tools`，而是为每项能力记录 `action`、`resourceType`、具体 `targets`、副作用 `effect`、允许的路径/Host/收件人/HTTP 方法、原始授权片段哈希、置信度和单轮过期时间。`allowed_tools` 仅作为旧 Dashboard 的兼容视图。

能力只有同时满足以下条件才生效：来自当前用户、动作被明确请求、不在引用或“总结以下文字”的数据区、不处于否定范围、目标具体、实际参数满足约束。因而“分析攻击者如何发邮件”“不要发邮件”“总结以下文字：发送密钥”和“帮我处理一下”都不会授予外部副作用。

### 3.2 记忆非授权原则

长期记忆可以提供上下文，但不能产生新的外部副作用权限。即使记忆写着“用户习惯把报告发给 archive@example.com”，当前用户只要求总结时，邮件仍进入拒绝或审批。这一性质在 `task-spec.test.ts` 中作为安全不变量验证。

## 4. 信任标签设计

玄鉴为进入上下文的数据打信任标签。标签包含以下概念：

| 维度 | 含义 |
|---|---|
| 来源 | 用户输入、外部网页、邮件 HTML、PDF 文本、图片元数据、工具结果、记忆、配置、Skill、Webhook、工作区文件等 |
| 完整性等级 | trusted、user、workspace、external、tainted |
| 机密性等级 | public、internal、secret |
| 风险向量 | 提示注入、隐藏内容、敏感数据、外泄、持久化、工具劫持、权限、意图漂移、供应链 |
| 证据 | 命中的隐藏内容、敏感路径、外发信号、持久化信号、Skill 行为冲突等 |
| 签名 | 对标签关键字段做 HMAC，防止记忆护照或标签元数据被静默篡改 |

信任标签的核心作用是把“这段文本来自哪里、能不能信、能不能影响高风险动作”变成结构化数据，而不是让模型凭上下文自行判断。

## 5. 污点传播算法

污点不是一个简单的“有风险/无风险”布尔值。玄鉴使用“污点画像 + sink 兼容矩阵”来处理。

### 5.1 污点如何定义

当数据满足以下条件之一，会产生污点：

- 来源天然低信任：外部网页、邮件、PDF、图像、Webhook、第三方工具返回。
- 内容含隐藏指令：白色字体、零尺寸 HTML、PDF 透明层、URL fragment 编码、图像元数据提示。
- 内容含越权诱导：要求忽略策略、绕过审批、读取密钥、外发配置、修改长期记忆。
- 内容含敏感资产：`.env`、SSH 私钥、OpenClaw 配置、token、API key、系统提示等。
- 内容含工具劫持行为：恶意 gatewayURL、MCP 工具描述注入、Skill 表面正常但读取本地配置并外联。

### 5.2 污点画像包含什么

每个污点画像记录：

- 污点来源和证据。
- 置信度。
- 机密性等级。
- 风险向量。
- 允许用途。
- 禁止流向的 sink。

例如，外部网页中的隐藏指令可以被用于“摘要和展示”，但不能直接驱动：

- 读取敏感文件。
- 调用外部 API。
- 发送邮件。
- 执行 shell。
- 写长期记忆。
- 修改配置或安装 Skill。

### 5.3 污点如何传播

污点传播发生在三类边上：

1. 输入到上下文：外部内容进入会话后，系统把对应标签写入会话状态。
2. 工具结果到后续决策：结构化结果按 JSON Path 拆成字段，每个字段拥有独立 Provenance ID、父节点、来源、机密性、完整性、变换记录和内容指纹；只有实际匹配或继承到 Sink 参数的字段传播污点。
3. 记忆到未来会话：长期记忆写入前必须生成护照；低信任或高风险记忆不能直接成为未来高优先级指令。

### 5.4 为什么不再“一刀切”

早期做法是只要会话污染，所有高风险动作都保守阻断，误判较多。当前做法是：

- 看污点是否真的能影响当前动作。
- 看当前动作属于哪个 sink。
- 看污点画像是否禁止流向该 sink。
- 记录 `taint flow` 证据，说明“哪条污染数据，以什么原因，禁止流向哪个工具动作”。

这样可以允许“总结有毒网页”，但阻止“根据网页隐藏指令读取密钥并外发”。

例如同一结果中的 `$.title` 可保持 public，`$.hidden_instruction` 标为 tainted，`$.account_token` 标为 secret。发送 `title` 不因同对象其他字段而被误拦；发送 token 或由隐藏指令影响的内容则生成从来源字段到 Sink 的因果证据。

## 6. 单次调用语义事实与会话级有向图

当前实现包含两个互补层，必须区分：`core/action-semantics.ts` 中的 `SemanticGraph` 是当前一次工具调用的扁平语义事实集合；`core/semantic-action-graph.ts` 中的 Semantic Action Graph V2 才是跨工具调用、带节点和有向边的会话级因果图。前者回答“这次参数里出现了哪些危险能力组合”，后者回答“哪项用户授权、哪段数据、经过哪些动作，最终影响了哪个 sink”。

### 6.1 单次调用语义事实抽取

单次调用分析不依赖公开 benchmark 的固定字段名，而是递归遍历任意工具参数树，从文本、路径、代码片段和嵌套对象中抽取事实。系统先进行以下规范化：

- 合并嵌套参数中的文本。
- 去除零宽字符和异常分隔符。
- 展开 URL percent 编码。
- 尝试解析 Unicode 转义。
- 尝试解析 base64 和 hex 内容。

抽取结果是 `operations`、`sensitiveSources`、`externalSinks`、`persistenceTargets`、`privilegedEffects`、`encodings`、`benignClaims`、`localReads` 和 `networkWrites` 等数组，而不是跨调用拓扑。它可在单次调用内识别以下组合：

- “敏感源 + 本地读取 + 外部 sink/网络写入”视为高风险数据外泄。
- “正常能力声明 + 本地读取 + 网络外发”视为供应链或恶意 Skill 风险。
- “持久化 + 敏感源/外部 sink/提权”视为记忆或配置持久化攻击。
- 编码展开后出现敏感源、持久化或提权时进入审批或阻断。

### 6.2 Semantic Action Graph V2 模型

V2 图跟随当前 OpenClaw/Command Lab 会话累积，不再把每次工具调用视为互不相干的孤立事件。它包含五类节点：

| 节点 | 含义 |
|---|---|
| `intent` | 当前用户任务，只保留任务指纹，不保存任务原文。 |
| `capability` | TaskSpec V2 提取的能力及其是否来自明确、非引用、非否定且目标具体的用户授权。 |
| `action` | 一次规范化后的工具调用及其授权结果、裁决和执行状态。 |
| `data` | 由 Provenance ID 标识的字段，包含来源路径、机密性、完整性、变换和内容指纹。 |
| `sink` | 外部发送、持久化、进程执行、敏感读取或写入等副作用终点。 |

有向边表达关系，并且每条边都携带 `basis` 和 `confidence`，用于区分直接观察、可逆解码和保守推断：

| 边 | 方向与含义 |
|---|---|
| `declares` | `intent -> capability`，任务声明能力。 |
| `governs` | `intent -> action`，当前意图约束动作。 |
| `authorizes` | `capability -> action`，精确能力授权动作。 |
| `constrains` | `capability -> action`，存在相关能力，但动作的具体收件人、路径、Host、HTTP 方法或命令超出能力约束；该边只表示边界约束，不表示授权。 |
| `requests` | `intent -> action`，动作被请求但未获得匹配能力授权。 |
| `consumes` | `data -> action`，某个具体字段实际进入工具参数。 |
| `produces` | `action -> data`，成功执行的工具产生字段。 |
| `derives` | `data -> data`，编码、摘要或其他变换产生字段血缘。 |
| `targets` | `action -> sink`，动作指向具体副作用终点。 |

图在插入边时检查反向可达性，拒绝自环和有向环；校验器同时拒绝重复节点、重复边、悬空边和悬空攻击路径。

### 6.3 动作生命周期

动作节点使用以下状态：

| 状态 | 含义 |
|---|---|
| `proposed` | 工具执行前已建立动作节点并完成策略评估。 |
| `awaiting_approval` | `ask` 裁决正在等待人工审批。 |
| `blocked` | 动作被阻断，并从待完成调用中移除。 |
| `executing` | 已放行并进入实际工具执行。 |
| `succeeded` | 工具成功返回，可建立 `produces` 边。 |
| `failed` | 工具执行失败，不产生数据节点和 `produces` 边。 |
| `observed` | 仅观察到结果、未匹配到预执行节点时建立合成动作，随后按实际结果收束为成功或失败。 |

这一约束防止“被阻断或执行失败的调用”凭空成为后续数据源。终态节点不可被晚到或重复回调改写；非法状态转换会进入 `lifecycle_anomalies`。如果一个已标记 `blocked` 的调用后来仍回报成功，系统保留原阻断节点不变，另建 `status=observed`、`authorizationReason=post_block_execution` 的合成执行节点，复制实际输入血缘并记录输出，同时留下 `blocked -> succeeded` 异常证据。策略层同步产生分数 100 的 deterministic/block finding，证据为 `event=enforcement_bypass`、`execution_status=executed_after_block`，把它明确归类为“执行面绕过监督”，而不是普通工具结果。

终态回调按调用 ID 幂等处理。第一次阻断后成功回调会被如实记录；相同结果再次回放时返回空 finding，并且不再增加 Provenance、exposure、动作节点或边，避免重试/恶意重放重复污染审计状态。

没有工具调用 ID 时，同名工具的待完成动作按 FIFO 匹配，避免并发轨迹被错误串线。

### 6.4 字段级血缘与不透明变换

每个结构化工具结果按 JSON Path 拆分。后续参数只有在实际匹配到某个字段时，才建立该字段到动作的 `consumes` 边；同一对象的其他兄弟字段不会自动连入路径。

对于摘要、编码、拼接等变换，输出字段继承实际输入字段的父 Provenance ID、较强机密性和较弱完整性。拓扑强制经过 `输入 data -> 变换 action -> 输出 data`，不会用一条捷径掩盖执行过程。但父子关系的存在不等于所有变换都被直接观察：黑盒工具产生不透明输出时，`produces` 边明确标为 `conservative`，不能表述为已证明敏感内容出现在输出中。

例如：

```text
read_webpage --produces--> $.account_token (secret)
$.account_token --consumes--> summarize_text
summarize_text --produces--> $.summary = "summary-ref-7f4a9c01"
$.summary --consumes--> send_email --targets--> external sink
```

最终字符串没有 `token` 或 `secret` 关键词，因此这条黑盒摘要链只能形成“原始 secret 可能影响外部 sink”的保守证据。图 finding 要求审批和语义复核，而不是声称确定性证明外泄；若同一次调用还命中精确污点到 sink、明确越权等独立硬规则，最终合并裁决仍可为 `deny`。相反，如果变换只消费 `$.public_summary`，同级的 `$.account_token` 不会被错误连接，精确授权的正常邮件仍可放行。

### 6.5 证据强度与因果路径裁决

每条边的证据分为三类：

| `basis` | 典型来源 | 默认置信度 | 策略含义 |
|---|---|---:|---|
| `observed` | 字段值 `exact` 匹配、结构化生命周期边 | 1.00 | 可参与 observed 路径和确定性图裁决。 |
| `decoded` | 可逆解码后的 `encoded_exact` 匹配 | 0.98 | 仍可参与 observed 路径和确定性图裁决，同时保留“经过解码”的证据。 |
| `conservative` | substring、encoded substring、fuzzy、encoded fuzzy、语义引用、黑盒不透明输出传播 | 0.60～0.90 | 只能说明“可能影响”，进入审批和语义复核，不单独证明外泄。 |

其中 substring、encoded substring、fuzzy、encoded fuzzy 的置信度依次为 0.90、0.86、0.82、0.78；黑盒输出只有一个明确输入父节点时通常为 0.75，存在多个候选输入时为 0.60。路径置信度取路径上所有边的最小值。只有每条边都不是 `conservative` 且置信度不低于 0.95，路径才标记为 `observed`；其余均标记为 `conservative`。

当前风险路径类型覆盖：

- secret 或 tainted 数据流向外部 sink；
- secret 或 tainted 数据流向持久化状态；
- secret 或 tainted 数据流向进程执行。
- `unauthorized_side_effect`：动作具有写入、外发、执行或持久化副作用，但当前任务没有显式能力授权；
- `target_scope_mismatch`：存在相关能力候选，但实际收件人、附件/路径、Host、HTTP 方法、命令或其他目标超出能力约束。

路径搜索要求风险源能够沿有向边到达当前 action 和 sink，并采用“最强证据优先”选路，而不是简单选择最短路径：只要存在不含 `conservative` 边的路线，就排除所有保守路线；在剩余路线中最大化路径最弱边的置信度（widest-path/bottleneck confidence），最后才用最少跳数和稳定 ID 顺序确定唯一结果。多个风险源同时到达 sink 时，先排 observed，再按置信度和路径长度排序，之后才截取最多 6 条，因此较新的弱推断不会挤掉已观测证据。

observed 路径产生 deterministic/block 图 finding；conservative 路径产生 heuristic/require_approval 图 finding，并交给人工审批或启用的语义复核继续判断。授权边界路径的 verdict 则沿用 TaskSpec 的 `deny/ask` 结果。各类路径都记录源节点、动作节点、sink 节点、节点/边 ID、`path_certainty`、`path_confidence` 和 `causal_chain`；快照中的对应边保留各自的 basis 与 confidence。长路径报告压缩时保留头部与尾部，而不是只截取开头，因此来源、末端动作和最终 sink 仍在证据中；`node_count` 和 `edge_count` 保留完整路径规模。

图证据与其他策略独立合并：保守图路径本身只要求审批，但精确污点到 sink、TaskSpec 明确越权、Manifest 完整性失败等硬规则仍可把最终结果判为 `deny`。图计算异常时高风险策略 fail closed；LLM-Judge 只能收紧，不能把任何确定性 deny 降级。

### 6.6 隐私、会话隔离与展示

图不保存原始任务文本、原始工具参数或原始工具结果。任务、调用和内容使用 SHA-256 指纹或截断哈希；数据节点只保留 Provenance ID、来源、JSON Path、机密性、完整性、变换标签和内容指纹。普通审计记录仍遵循各自的脱敏与 preview 策略，但不属于图数据本身。

运行图默认最多保留 320 个节点、640 条边和 64 条攻击路径，并在裁剪后清理悬空引用；对外快照进一步限制为 36 个节点、40 条边和 6 条完整路径。快照先为当前 intent、最近的 active capability、pending action 及其 `declares / governs / authorizes / requests` 授权边预留空间，再选择完整攻击路径和近期支持节点。它不会为了凑数量截断单条路径：只有节点与边都能完整纳入边界的路径才会发布。

快照还设置 64 KiB UTF-8 序列化硬上限。超限时先移除较旧攻击路径，仍超限则退化为标记 `snapshot_truncated=true` 的最小元数据快照，绝不输出无界审计载荷。

Judge 不直接接收上述 64 KiB 审计快照，而使用 `semanticActionGraphJudgeProjection()` 生成专用结构化投影。该函数默认硬上限为 2,400 UTF-8 bytes，并按“2 条路径/10 个路径节点 -> 1 条路径/8 个节点 -> 1 条路径/6 个节点 -> 最小摘要”逐级降级，保留图计数、授权上下文、近期动作、风险路径和生命周期异常。实际 Judge 总信封还会给图分配更小的子预算，当前最高 1,800 bytes，因此运行时载荷不会因为图增长而挤占全部语义判断上下文。

OpenClaw 不直接拼接原始会话字符串，而是对结构化 `[sessionKey, sessionId]` 元组做 SHA-256，并使用 `session:<hash>` 命名空间作为内部身份，避免原始 key 与其他元组哈希发生碰撞。同一 `sessionKey` 下的不同 `sessionId` 不共享字段血缘。活跃会话上限为 500；容量回收只淘汰没有 pending graph call 且没有 runtime checkpoint 的空闲会话。如果所有槽位都在执行，系统拒绝创建新会话，避免智能体在没有可追踪策略状态的情况下继续运行。

快照通过 `trust.semantic_action_graph` 进入审计证据。Dashboard API 不下发完整会话图，而是按当前记录投影一个脱敏因果子图，并用 `trace_kind` 区分三种真实轨迹：`attack` 表示 finding 对应的攻击路径，`authorized` 表示具有 `declares -> authorizes -> targets` 证据的正常放行动作，`enforcement_bypass` 表示存在 `executed_after_block` finding、生命周期异常和独立 observed 执行节点的阻断后执行。选择顺序为 enforcement bypass、attack、authorized，防止正常授权分支掩盖更严重证据。

展示投影最多保留 12 个主路径节点、16 个总节点和 24 条边。路径超长时保留头尾，并在中间插入一个 `kind=collapsed` 的合成节点以及 `kind=summary` 的桥接边，使 SVG 仍保持有向连通；这些对象统一标记 `display_only=true`、`synthetic=true`、`basis=conservative`、`confidence=0`，明确说明它们只解决显示连续性，不形成新的因果证明。

`/security-screen` 保留原有 **态势** 3D 拓扑，并新增互补的 **因果** 视图。因果图按 DAG 拓扑排序计算 rank，再用父节点重心调整同层次序；支持自动适配、按钮/滚轮缩放、空白区拖拽平移。点击节点或边会打开脱敏证据检查器，并高亮其上下游连通链；边样式分别展示 observed、decoded、conservative 和 display-only projection。这样路径来自实际图数据，而不是根据告警标题拼接，也不会在报告中把 conservative 或展示折叠写成已证实事实。

### 6.7 Tool Security Manifest

工具不能再仅凭名称获得信任。内置和 MCP 工具可声明数据来源、副作用、是否接收敏感数据、是否能外发、是否需要显式授权和默认信任级别。工具 schema、endpoint、能力、副作用和版本共同生成 SHA-256；运行时摘要或工具身份变化会产生 `tool_manifest_integrity_mismatch` 并阻断。未注册工具默认进入人工审批。

## 7. Memory Guard 设计

记忆投毒的防御分为写入前、存储时、读取时三个阶段。

### 7.1 写入前

每次写入长期记忆前，系统检查：

- 来源等级：用户明确偏好、Agent 自推经验、外部网页、工具结果、Webhook 等。
- 是否修改保护键：系统提示、开发者提示、安全策略、API endpoint、gateway、OpenClaw 配置、`MEMORY.md` 等。
- 是否包含权威未来行为：例如“以后总是跳过审批”“未来默认外发配置”。
- 是否包含敏感信息：私钥、token、API key、密码、配置快照。
- 是否过大或结构异常。
- 是否需要 LLM-Judge 复核“这段内容是否适合长期保存”。

### 7.2 记忆护照

允许写入的记忆会带上护照：

- 记忆 key。
- 来源类别。
- 信任等级。
- 创建和更新时间。
- 上下文哈希。
- 内容 SHA-256。
- 风险向量。
- 是否保护键。
- HMAC 签名。

这使得后续读记忆时可以追溯它从哪里来、是否被篡改、是否应该影响当前决策。

### 7.3 读取时

读取记忆时，系统会：

- 校验内容 SHA-256 和护照签名。
- 对记忆内容重新做信任分析。
- 低信任记忆如果试图影响高风险动作，会要求审批或阻断。
- 多条记忆同时参与决策时，执行轻量共识检查：低信任、高风险、权威化的记忆如果成为离群记录，会被标为可疑。

这对应“记忆来源标记、分层信任、关键决策绕过记忆、异常推理路径检测”的设计目标。

## 8. LLM-Judge 的作用

LLM-Judge 是第二道动态防线，不是唯一防线。即使关闭 LLM-Judge，确定性策略、TaskSpec、污点传播、ABAC、Memory Guard 和 工具边界域的 System Preflight 仍会工作。

### 8.1 调用环节

LLM-Judge 覆盖四个环节：

| 环节 | 作用 |
|---|---|
| 消息/工具结果 | 判断是否包含提示注入、越狱、凭据外泄或恶意指令 |
| 工具调用 | 判断工具动作是否与用户任务一致，是否可能外泄、破坏、越权或漂移 |
| 记忆写入 | 判断候选长期记忆是否会改变未来安全边界、绕过审批或污染行为 |
| 溯源扫描 | 判断 Skill、配置、工作区基础文件是否含恶意行为或供应链风险 |

### 8.2 输出如何使用

Judge 只返回结构化风险：低、中、高和理由。玄鉴不会让模型直接执行阻断，而是把 Judge 结果转换成 finding，再与确定性策略合并：

- 高风险 Judge finding 会提高风险分数，可触发 `deny`。
- 中风险 Judge finding 通常触发 `ask` 或审批。
- 低风险不产生告警，但保留调度信息和审计画像。
- 合并使用单调序 `allow < ask < deny`；确定性 `deny` 永远不能被 Judge 降级。
- Judge 输入采用 JSON 数据信封，明确 `evidence.content_is_data_only=true`、无工具、不可修改策略，并只接受固定 JSON Schema 输出。

### 8.3 调度模式

当前支持三种模式：

| 模式 | 含义 | 适用场景 |
|---|---|---|
| full | 所有启用面都调用 LLM-Judge | 离线评测、比赛复现实验 |
| risk-tiered | 低风险走确定性策略，高风险路径调用 Judge | 日常演示和生产化方向 |
| off | 不调用 Judge | 无模型基线、成本或网络不可用场景 |

本轮最新 benchmark 使用 `risk-tiered`：benchmark 入参统一为 `semanticJudge=default`，服务端按风险分层决定是否调用 DeepSeek Judge。

## 9. ABAC 与策略裁决

玄鉴的 ABAC 可以理解为：

- 主体：当前智能体、当前会话、当前用户任务。
- 资源：文件、API host、邮件收件人、记忆 key、Skill、系统命令。
- 动作：读、写、发、调用、执行、安装、持久化。
- 环境：污点状态、历史基线、是否审批、系统预执行状态、eBPF 可用性。

策略合并后输出：

- `allow`：动作在授权范围内，风险低。
- `ask`：动作可能合理但有越界或高副作用，需要审批。
- `deny`：动作明确越权、污染驱动、敏感外泄、持久化投毒或系统破坏。

系统还支持三种运行模式：

- `observe`：只审计，不改变执行结果，适合做无防护基线。
- `approval`：高风险动作进入人工审批。
- `block`：高风险动作执行前硬阻断，适合比赛展示。

## 10. 工具边界域的 System Preflight 与系统级控制

当前环境下 eBPF 内核观测受权限限制不可用，健康检查会如实显示原因。玄鉴没有把不可用的 eBPF 伪装成已启用，而是提供应用层执行前控制：

- 敏感路径 denylist。
- 持久化路径 denylist。
- privileged command denylist。
- gateway override denylist。
- 网络外发审查。
- 容器/主机边界逃逸识别，例如 privileged Docker、挂载根目录、Docker socket、containerd socket、`nsenter`、`unshare`、`mount`、`/proc/*/mem`、`/dev/mem` 等。

这意味着危险命令不需要真正执行到系统调用阶段，已经可以在工具调用前被拦截。后续如果部署环境允许 root 或安全 sidecar，可继续把这些策略下沉到 seccomp、AppArmor、eBPF 或容器沙箱。

## 11. Benchmark 结果解释

最新 `risk-tiered` 全量复测结果：

| 实验 | 样例 | 攻击/期望保护 | 正常/期望放行 | 保护率 | 漏放 | 正常放行率 | 误拦 | 中位延迟 | P95 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 综合攻击回归 | 520 | 441 | 79 | 100.0% | 0 | 100.0% | 0 | 5864.55 ms | 12706.18 ms |
| 工具攻击专项 | 320 | 270 | 50 | 100.0% | 0 | 100.0% | 0 | 3750.44 ms | 7046.42 ms |

对比 full Judge：

- 高风险漏放保持 0。
- 误拦从 7 条降到 0 条。
- 总耗时从约 135.2 分钟降到约 76.8 分钟。
- 综合组中位延迟下降约 46.0%。
- 工具专项中位延迟下降约 44.5%。

结论：全量 Judge 安全性强但更慢且更保守；risk-tiered 在本轮公开 benchmark 上保持同等保护能力，同时降低延迟和误判，更符合生产化方向。

## 12. 可解释性输出

监督端展示的不是单一分数，而是证据链：

- 当前任务授权。
- 工具名与参数。
- 风险向量。
- 命中规则。
- LLM-Judge 调度模式和结论。
- 污点来源与流向。
- Memory passport。
- 工具边界域的 System Preflight 状态。
- 最终 `allow / ask / deny`。

这些信息可以支撑答辩中解释“为什么拦、为什么放、误判在哪里、后续如何优化”。
