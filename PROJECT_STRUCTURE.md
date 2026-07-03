# 玄鉴项目结构说明

更新时间：2026-07-03

本仓库按“运行系统、实验材料、第三方样例、交付输出”分层组织。当前功能实现不依赖移动后的临时产物，核心运行路径保持不变。

## 顶层目录

| 目录 | 作用 |
|---|---|
| `openclaw-plugin/` | 当前比赛主系统，嵌入 OpenClaw 的玄鉴运行时插件，提供 8765 控制台、行为监督、工具拦截和 benchmark 单条复测。 |
| `src/` | 早期 FastAPI 离线原型和辅助研究接口，主要服务 8000 离线实验。 |
| `reports/` | 答辩报告、技术说明、benchmark 结果、验收证据和可读文档。入口是 `reports/START_HERE.md`。 |
| `scripts/` | 可复现实验、benchmark 评测、UI 检查和验收脚本。 |
| `tests/` | Python 离线原型的单元测试和策略测试。 |
| `cases/` | 中文安全案例集，用于离线原型和报告引用。 |
| `policies/` | YAML 策略配置，定义工具、路径、外部 sink 和污点约束。 |
| `third_party/benchmarks/` | 下载的公开 benchmark 原始仓库。只作为样例来源，不直接作为玄鉴运行时依赖。 |
| `tools/` | OpenClaw 公网代理、PromptBeat 适配、eBPF observer 等运维/集成工具。 |
| `runtime/` | 本地运行态目录。数据库、日志、outbox 和 sandbox 都是可再生成内容，不作为交付材料。 |
| `openclaw-workspace/` | OpenClaw 本地实验工作区，包含用于测试的 Skills、攻击样本和工作区状态。 |
| `output/` | 打包后的可交付产物和可执行插件包。 |

## 功能分层

1. OpenClaw 插件层：`openclaw-plugin/index.ts` 接入 OpenClaw 生命周期、工具调用和运行时配置。
2. 策略与算法层：`openclaw-plugin/core/` 负责 TaskSpec、污点传播、Memory Guard、ABAC、LLM-Judge 和系统预执行。
3. 展示与审计层：`openclaw-plugin/server/` 和 `openclaw-plugin/public/` 提供 8765 API、控制台、业务测试台和态势大屏。
4. 离线原型层：`src/agentsentry/` 提供 FastAPI、SQLite、沙箱工具和早期对比实验。
5. 实验与报告层：`scripts/` 复跑实验，`reports/` 保存最新报告和结果。

## 保留原则

- 核心代码不为目录美化而移动，避免破坏 import、OpenClaw 插件发现和测试脚本路径。
- 当前推荐 benchmark 结果统一放在 `reports/benchmark_risk_tiered/`。
- full LLM-Judge 结果只作为对照保留在 `reports/benchmark_judge_full/`。
- 旧 timestamp、latest 重复报告、Word 中间产物、日志、pid、SQLite 和 Python cache 不作为源码交付。
