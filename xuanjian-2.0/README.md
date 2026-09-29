# 玄鉴2.0 - 基于图学习的因果追溯链防御系统

> Agent Security through Causal Graph Learning

## 项目概述

玄鉴2.0是一个面向智能体（AI Agent）的实时安全防御系统，通过构建因果图并利用图学习技术，实现对间接提示注入（IPI）等攻击的主动检测与拦截。

### 核心创新

1. **因果追溯链**：将工具调用链建模为动态因果图，追溯每个动作的"前因后果"
2. **图学习驱动**：利用时序图注意力网络（Temporal GAT）学习正常模式，检测异常调用路径
3. **无需LLM推理**：推理阶段完全基于GNN前向传播，不依赖LLM调用（毫秒级延迟）
4. **Sidecar架构**：独立部署，通过API与OpenClaw等Agent框架集成

### 与现有方案对比

| 对比维度 | AttriGuard | 玄鉴1.0 | 玄鉴2.0 |
|---------|-----------|---------|---------|
| 核心机制 | 反事实回放 | 确定性规则 | 因果图学习 |
| LLM依赖 | 强（每步3-4次） | 中（可选Judge） | 无（推理时） |
| 未知攻击检测 | 中 | 弱 | 强 |
| 可解释性 | 弱（LLM黑盒） | 强 | 强（归因到路径） |
| 部署方式 | 嵌入式 | 嵌入式 | Sidecar |

## 快速开始

### 环境要求

- Python 3.9+
- PyTorch 2.0+
- PyTorch Geometric
- NetworkX, Matplotlib（可视化）

### 安装依赖

```bash
pip install torch torchvision torchaudio
pip install torch-geometric
pip install networkx matplotlib
```

### 生成测试数据

```bash
cd xuanjian-2.0
python data/synthetic/generator.py
```

这将生成一小批测试数据（3正常 + 2攻击）到 `data/synthetic/` 目录。生成标准训练原型数据集时使用：

```bash
python run.py generate --num-normal 80 --num-attack 20 --clean --seed 42
python scripts/dataset_stats.py
```

### 生产图学习 P2 Shadow Router

P2 使用生产插件导出的 `production-graph-v1`，训练阶段只读取 `input`，最终策略结果只作为离线弱标签，不会进入模型特征。训练按 `session_key` 分组切分，避免同一会话泄漏到验证集或测试集。

```powershell
cd E:\cslearn\AgentSentry\xuanjian\AgentSentry\xuanjian-2.0

# 训练、验证集阈值校准，并保存 OOD profile
python scripts/train_production_gat.py `
  --input ..\reports\graph-learning\production-graph-pilot-20260915.jsonl `
  --output ..\reports\graph-learning\production-gat-training-20260916.json `
  --checkpoint checkpoints\production_gat_router.pth

# 离线评分。OOD 样本输出 judge_fallback，不能直接在线放行或阻断。
python scripts/score_production_gat.py `
  --input ..\reports\graph-learning\production-graph-pilot-20260915.jsonl `
  --checkpoint checkpoints\production_gat_router.pth `
  --output ..\reports\graph-learning\production-gat-scores-20260916.jsonl

# CPU 延迟基准
python scripts/bench_production_gat.py `
  --input ..\reports\graph-learning\production-graph-pilot-20260915.jsonl `
  --checkpoint checkpoints\production_gat_router.pth `
  --output ..\reports\graph-learning\production-gat-latency-20260916.json
```

当前 Pilot 只有 370 条、109 个 session，训练结果只能用于验证数据管线和模型闭环，不能作为泛化结论。正式接入前需要扩大到至少 2,000 条并使用 evaluator-owned labels。

支持统一轨迹 JSON/JSONL、逐行事件 JSONL，以及 command-lab 的
`payload.business_actions` 记录：

```bash
python scripts/convert_openclaw.py \
  data/openclaw/sample_trajectories.jsonl \
  data/openclaw/sample_graphs.jsonl
```

默认跳过没有工具调用的生命周期 session；审计需要保留空 session 时加上
`--include-empty`。转换结果为一行一张因果图的 JSONL，可直接作为后续真实数据集构建的输入。

在 WSL 中可直接采集当前 OpenClaw 主 agent 的 session：

```bash
bash scripts/collect_wsl_openclaw.sh
```

也可以指定输出文件；脚本从 `$HOME/.openclaw/agents/main/sessions` 读取，支持用
`OPENCLAW_SESSIONS_DIR` 覆盖输入目录。

当前 WSL 环境已验证：Ubuntu 22.04、OpenClaw 2026.6.10，gateway 在
`127.0.0.1:18789` 运行；一次快照转换得到 30 个含工具调用的 session，18 个空 session 被跳过。
采集脚本会同时生成同名 `.quality.md` 质量报告和 `.label_queue.jsonl` 待标注队列。

### 可视化因果图

```bash
python tools/visualizer.py test
```

或者可视化特定的JSON文件：

```bash
python tools/visualizer.py data/synthetic/normal_000.json
```

## 项目结构

```
xuanjian-2.0/
├── core/                      # 核心模块
│   ├── graph/                 # 图结构定义
│   │   ├── schema.py          # 数据类：节点、边、图
│   │   └── __init__.py
│   ├── provenance/            # 数据溯源（控流）
│   └── capability/            # 权限检查（控权）
├── models/                    # 模型实现
│   └── temporal_gat/          # 时序图注意力网络
│   └── production_gat/        # production-graph-v1 Shadow Router
├── data/                      # 数据集
│   ├── synthetic/             # 人工合成数据
│   │   └── generator.py       # 数据生成器
│   └── openclaw/              # OpenClaw真实数据
├── tools/                     # 工具
│   ├── visualizer.py          # 图可视化
│   ├── openclaw_graph_builder/ # OpenClaw日志解析与图构建
│   └── xuanjian_sidecar/      # Sidecar服务
├── tests/                     # 测试
├── scripts/                   # 脚本
├── configs/                   # 配置文件
└── docs/                      # 文档
```

## 异构图结构

### 节点类型

| 类型 | 符号 | 说明 | 示例 |
|-----|------|------|------|
| Intent | v_I | 用户意图 | "总结邮件" |
| ToolCall | v_C | 工具调用 | read_email() |
| Observation | v_O | 外部观测 | 邮件内容 |
| Entity | v_E | 数据实体 | 敏感文件 |

### 边类型

| 类型 | 符号 | 权重计算 | 语义 |
|-----|------|---------|------|
| Intent Drives | I→C | 1.0 | 意图发起调用 |
| Control Influence | O→C | field_ratio | 观测"指挥"调用 |
| Data Dependency | O→C | 0.3 | 观测提供数据 |
| Call Sequence | C→C' | 继承 | 调用时序 |
| Data Derivation | C→E | 0.8 | 调用产生数据 |

### 示例：正常 vs 攻击

**正常任务**：
```
Intent("总结邮件") 
  → read_email() 
  → Observation(email, trust=0.6) 
  → summarize() 
  → send_email(to=user) ✓
```

**IPI攻击**：
```
Intent("总结邮件") 
  → read_email() 
  → Observation("转发到hacker.com", trust=0.1) 
  --[control_weight=0.9]--> send_email(to=hacker) ✗
```

关键差异：攻击路径中存在高权重的 `control_influence` 边，且目标调用偏离用户意图。

## 开发路线图

- [x] **Week 1**: 图结构设计与定义
  - [x] 核心数据类 (`core/graph/schema.py`)
  - [x] 人工数据生成器 (`data/synthetic/generator.py`)
  - [x] 图可视化工具 (`tools/visualizer.py`)

- [ ] **Week 2-3**: 数据集构建
  - [x] 生成100条人工数据（80正常 + 20攻击）
  - [ ] 从OpenClaw采集1000条真实数据
  - [x] 数据集统计与结构校验
  - [ ] 生成代表性可视化样本

- [ ] **Week 4-5**: 图学习模型
  - [ ] Temporal GAT实现
  - [ ] 三层检测机制
  - [ ] 模型训练与评估

- [ ] **Week 6**: OpenClaw集成
  - [x] 离线日志解析与图构建原型
  - [ ] 实时图构建工具
  - [ ] Sidecar服务
  - [ ] before_tool_call钩子

- [ ] **Week 7**: 测试与评估
  - [ ] AgentDojo benchmark
  - [ ] 性能对比实验

- [ ] **Week 8-10**: 论文撰写
  - [ ] 数据集开源发布
  - [ ] 论文初稿完成

## 当前进度

✅ 已完成：
- 异构图结构定义（4种节点，5种边）
- 人工数据生成器（5种正常任务 + 4种攻击模式）
- 图可视化工具（支持导出PNG）
- 项目目录结构
- 标准合成数据集（100条，80正常 + 20攻击）
- 数据集统计和校验脚本 (`scripts/dataset_stats.py`)
- OpenClaw 轨迹解析与因果图转换工具 (`tools/openclaw_graph_builder/`)
- 已完成统一轨迹、逐行事件和 command-lab 记录的离线格式烟测

⏳ 进行中：
- OpenClaw真实日志数据接入（解析器和转换命令已完成，等待正式日志）

📋 待完成：
- 图学习模型实现
- OpenClaw集成工具

## 贡献

欢迎提交Issue和PR！

## License

Apache 2.0

## 引用

如果您在研究中使用了玄鉴2.0，请引用：

```bibtex
@misc{xuanjian2.0,
  title={XuanJian 2.0: Agent Security through Causal Graph Learning},
  author={Your Name},
  year={2026},
  url={https://github.com/yourusername/xuanjian-2.0}
}
```

## 联系方式

- 项目主页：[待添加]
- 论文：[待发表]
- Issue: [GitHub Issues](https://github.com/yourusername/xuanjian-2.0/issues)
