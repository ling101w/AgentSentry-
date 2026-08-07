# 玄鉴 / AgentSentry

> 面向智能体工具调用链的实时行为监督与风险拦截系统

[![CI](https://github.com/ling101w/AgentSentry-/actions/workflows/ci.yml/badge.svg)](https://github.com/ling101w/AgentSentry-/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**玄鉴**是参赛作品名称，`AgentSentry` 是仓库与 OpenClaw 插件沿用的工程名。它嵌入智能体的工具调用生命周期，在文件、网络、邮件、命令、记忆等动作真正执行前回答三个问题：

1. 用户是否明确授权了这个能力和具体目标？
2. 当前参数是否实际使用了低可信或敏感数据？
3. 这个动作是否越过确定性的安全边界？

系统输出 `allow`、`ask` 或 `deny`。其中 `ask` 表示动作尚未放行，必须经过操作员审批；LLM Semantic Judge 只处理确定性规则无法判断的语义歧义，而且只能收紧、不能放宽确定性裁决。

## 核心架构

```text
OpenClaw lifecycle hook
        |
        v
normalize action
        |
        v
TaskSpec V2 capability authorization
        |
        v
field-level provenance / taint graph
        |
        v
deterministic enforcement
        |
        +------ ambiguous only ------> semantic judge (1-2s budget + cache)
        |                                  |
        +----------------------------------+
        v
allow / ask / deny
        |
        v
apply effects + async audit telemetry
```

玄鉴的生产链由三个概念构成：

- **Authorization Graph**：把最新用户请求解析为显式 capability set，约束文件路径、网络 origin、HTTP method、邮件收件人、命令和有效期。模型可以建议 capability，但不能授予 capability。
- **Provenance/Taint Graph**：记录具体 tool-result 字段如何进入后续 tool arguments。只有污染数据真实到达 sink 才会触发数据流阻断，避免“会话里出现过一次污染，后续所有动作都背锅”。
- **Deterministic Enforcement**：URL origin、SSRF、canonical path、敏感文件、持久化、Memory Guard、工具完整性和高风险 sink 由确定性策略执行，不依赖模型可用性。

策略评估采用 effects 契约：

```ts
const { decision, effects } = evaluate(snapshot, action, config);
applyEffects(state, effects);
```

`evaluate()` 在克隆的 snapshot 上计算，不修改调用方会话状态；最终裁决后再统一提交状态和异步审计事件。

## 能防什么

| 攻击面 | 关键防线 |
|---|---|
| 间接提示注入 | 外部内容 trust label、字段级 provenance、taint-to-sink 检查、响应覆盖 |
| Agent 擅自扩大任务 | TaskSpec V2 capability containment、目标与方法约束、ASK 审批 |
| 敏感文件与目录穿越 | workspace canonical boundary、realpath/symlink 检查、Windows drive/UNC 处理 |
| URL allowlist 绕过与 SSRF | exact/prefix 规则分离、origin 含端口、DNS 后私网/metadata IP 检查、逐跳重定向验证、流式大小限制 |
| 记忆投毒 | 独立 256-bit Memory Guard key、HMAC timing-safe 校验、namespace 与来源约束 |
| 恶意 Skill / 工具劫持 | 增量 provenance scan、Tool Security Manifest、digest pinning、未知工具审批 |
| 行为漂移 | 按 tool x task-class 的 warm-up、TTL 与滑动窗口基线 |
| Dashboard 暴露 | loopback 默认绑定、bootstrap token、HttpOnly + SameSite=Strict session、Host/Origin 校验 |

## 90 秒演示

1. 在 OpenClaw 中启用比赛配置：

   ```text
   /agentsentry profile competition
   /agentsentry
   ```

2. 打开 `/agentsentry` 返回的认证 URL。裸 `http://127.0.0.1:8765/` 在全新浏览器中按设计返回 `401`；bootstrap token 写入安全 session cookie 后立即从地址栏移除。
3. 进入 `/command-lab`，先运行一个普通文件写入或健康检查，证明系统不是一刀切。
4. 再运行隐藏指令、敏感数据外发或记忆投毒样例，观察动作在执行前进入 `deny` 或 `ask`。
5. 打开 `/security-screen` 的“因果”视图，查看 `intent -> capability -> data -> action -> sink` 路径和命中的边界。
6. 回到首页查看 `tool_decision`、`guard_finding`、`alert`、`tool_result`，并导出 JSON/CSV 审计记录。

更完整的演示话术和复现顺序见 [演示与复现实验指南](reports/demo_and_reproduction.md)。

## 快速安装

要求：

- Node.js 24（与 CI 一致）
- npm
- OpenClaw `>=2026.3.28`
- Python 3.13 仅用于离线原型、评测和 Python 测试

### Windows PowerShell

```powershell
git clone https://github.com/ling101w/AgentSentry-.git
cd .\AgentSentry-\openclaw-plugin
npm ci --legacy-peer-deps
npm run ci
.\setup.ps1 -Force
```

### Linux / macOS

```bash
git clone https://github.com/ling101w/AgentSentry-.git
cd AgentSentry-/openclaw-plugin
npm ci --legacy-peer-deps
npm run ci
bash setup.sh --force
```

安装完成并重启 OpenClaw Gateway 后：

```text
/agentsentry profile competition
/agentsentry status
```

`/agentsentry status` 会返回认证 Dashboard URL、记录路径、当前 profile、enforcement mode、session 数量与核心防线状态。审计记录默认写入：

```text
~/.openclaw/agentsentry/records.jsonl
```

## 安全配置

| Profile | Enforcement | 用途 |
|---|---|---|
| `observe` | `observe` | 只记录和告警，用作无阻断基线 |
| `balanced` | `approval` | 日常使用，高风险动作进入审批 |
| `competition` | `approval` | 比赛演示，启用 provenance judge、写入 root 和响应覆盖 |
| `high-security` | `block` | 强约束部署，要求高风险运行面具备内核 observer |

常用命令：

```text
/agentsentry status
/agentsentry profile <observe|balanced|competition|high-security>
/agentsentry config get [key]
/agentsentry config set <key> <value>
/agentsentry config reset
/agentsentry approvals [status|reset]
/agentsentry reset
```

Semantic Judge 默认使用独立的环境变量，不复用业务 API Key：

```powershell
$env:AGENTSENTRY_API_KEY="YOUR_JUDGE_KEY"
```

```text
/agentsentry config set semantic.enabled true
/agentsentry config set semantic.baseUrl https://api.openai.com/v1
/agentsentry config set semantic.model gpt-4o-mini
/agentsentry config set semantic.apiKeyEnv AGENTSENTRY_API_KEY
```

未配置 key、网络不可用或 Judge 超时，不会关闭确定性策略。

## Dashboard

认证后可使用三个主视图：

- `/`：实时记录、裁决详情、JSON/CSV 导出和运行配置。
- `/command-lab`：受控业务工具与公开攻击样例的逐条复测入口。
- `/security-screen`：安全态势、四域一环指标、告警时间线和 Live Causal Graph。

Dashboard 默认只允许 loopback。若要绑定 `0.0.0.0`，必须显式启用远程访问并配置认证 token；不要为了容器部署直接暴露未认证端口。

## 验证

OpenClaw 插件：

```powershell
cd openclaw-plugin
npm run ci
npm run sbom
```

当前 CI 覆盖 typecheck、ESLint、Vitest coverage、policy/security smoke、property/fuzz 和 AgentDojo bridge self-test。当前分支最近一次本地与 GitHub CI 结果为 31 个测试文件、341 项测试通过。

Python 离线原型与评测工具：

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
```

当前 Python 测试为 123 项。

## 评测口径

仓库保存了两组公开内容映射后的开发回归：综合攻击回归 520 条、工具攻击专项 320 条。这些结果用于规则回归、误报检查和消融，但必须明确：

- 它们不是独立盲测。
- 它们不是 AgentDojo/InjecAgent 原生端到端成绩。
- 历史标签不会进入 detector 输入；新的评测协议将 labels 保留在 evaluator-owned envelope。
- Native AgentDojo adapter、doctor/plan/contract 已实现，但模型驱动发布结果在完成干净 release run 前保持 `not_run`。

指标、标签隔离和证据等级见 [EVALUATION_METHODOLOGY.md](reports/EVALUATION_METHODOLOGY.md)。

## 能力边界

- eBPF observer 可记录 `execve`、`openat` 等事件；`connect` 当前只记录 syscall 的 pid/comm/fd，不提取或分类目标地址。网络目的地控制来自应用层 URL/命令 preflight 和部署侧 egress allowlist。
- canonical path 检查发生在 OpenClaw 文件工具打开路径之前，仍存在经典 check/use 时间窗。需要更强隔离时，应让文件工具使用 `openat`、`O_NOFOLLOW` 或检查过的 fd。
- 行为检测是轻量在线统计基线，不宣称使用 IsolationForest、GNN 或已训练异常检测模型。
- `src/agentsentry/` 的 FastAPI 服务是早期离线原型和辅助研究接口；比赛主链是 `openclaw-plugin/` 与认证后的 `8765` Dashboard。
- 公开 benchmark 映射可以证明已知规则回归稳定，不能单独证明未知攻击泛化能力。

## 目录结构

| 路径 | 作用 |
|---|---|
| `openclaw-plugin/` | 当前生产主系统：OpenClaw hooks、策略、Dashboard、测试和 profiles |
| `openclaw-plugin/core/task-spec/` | TaskSpec V2 capability 提取与 containment |
| `openclaw-plugin/core/taint/` | 字段级 provenance/taint graph |
| `openclaw-plugin/core/policy/` | action assessment、行为基线和 policy helpers |
| `openclaw-plugin/core/persistence/` | 异步批量事件写入 |
| `reports/` | 比赛报告、评测说明、验收证据和文档索引 |
| `evaluation/` | 标签隔离评测协议与 native adapter |
| `dataset/` | 数据源 Registry、六源 raw manifest、统一清洗与分组切分说明 |
| `cases/`、`policies/` | 中文案例集与离线策略材料 |
| `scripts/` | 评测、验收、发布和 UI 检查脚本 |
| `src/`、`tests/` | 早期 Python 离线原型及其测试 |
| `output/` | 可交付发布包 |

完整结构说明见 [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)。

## 文档入口

| 文档 | 适合谁看 |
|---|---|
| [START_HERE.md](reports/START_HERE.md) | 第一次打开仓库，希望快速找到材料 |
| [competition_report.md](reports/competition_report.md) | 评委、答辩者、安全评审 |
| [system_functionality.md](reports/system_functionality.md) | 想核对功能与真实数据来源的人 |
| [technical_design_and_algorithms.md](reports/technical_design_and_algorithms.md) | 想深入 TaskSpec、taint、Memory Guard、Judge 的开发者 |
| [demo_and_reproduction.md](reports/demo_and_reproduction.md) | 需要复现演示和 benchmark 的操作者 |
| [dataset/README.md](dataset/README.md) | 需要收集、清洗、切分并运行安全数据集的人 |
| [openclaw-plugin/README.md](openclaw-plugin/README.md) | 只安装或开发 OpenClaw 插件的人 |
| [README_RELEASE.md](README_RELEASE.md) | 使用交付 tarball 的部署人员 |

## 发布包

当前兼容包位于：

```text
output/xuanjian-openclaw-plugin-20260703.tar.gz
```

文件名为兼容已有交付链接而保留，包内代码来自当前 release commit。重新构建与审计：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release_archive.ps1
Get-FileHash -Algorithm SHA256 .\output\xuanjian-openclaw-plugin-20260703.tar.gz
```

## License

[Apache License 2.0](LICENSE)
