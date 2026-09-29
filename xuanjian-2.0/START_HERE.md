## 🎉 玄鉴2.0 项目启动成功！

**时间**: 2026-08-29 22:05  
**状态**: ⏳ 阶段二进行中（WSL真实 session 已接入）

---

## 📊 已完成工作总结

### 1️⃣ 核心代码实现

| 模块 | 文件 | 行数 | 状态 |
|------|------|------|------|
| 图结构定义 | `core/graph/schema.py` | 352 | ✅ |
| 数据生成器 | `data/synthetic/generator.py` | 1082 | ✅ |
| 可视化工具 | `tools/visualizer.py` | 237 | ✅ |
| 单元测试 | `tests/test_graph.py` | 237 | ✅ |
| 启动脚本 | `run.py` | 130 | ✅ |

**总代码量**: ~2,300 行（含扩展生成器、统计脚本和测试）

### 2️⃣ 生成的数据

```
data/synthetic/
├── normal_000.json (3.5KB)  ✅
├── normal_001.json (3.6KB)  ✅
├── normal_002.json (3.6KB)  ✅
├── attack_003.json (3.4KB)  ✅
├── attack_004.json (3.4KB)  ✅
├── test_normal.png (347KB)  ✅
└── test_attack.png (335KB)  ✅
```

**总计**: 100条标准JSON数据（80正常 + 20攻击）+ 2张测试可视化图像

数据已通过结构校验，100个 `graph_id` 均唯一；统计报告见 `dataset_stats.md`。

### 3️⃣ 项目文档

| 文档 | 内容 | 状态 |
|------|------|------|
| `README.md` | 项目概述、快速开始 | ✅ |
| `玄鉴2.0实施计划.md` | 10周完整路线图 | ✅ |
| `PROGRESS.md` | 实时进度跟踪 | ✅ |
| `docs/STAGE1_SUMMARY.md` | 阶段一总结 | ✅ |
| `dataset_stats.md` | 合成数据集统计与校验结果 | ✅ |
| `tools/openclaw_graph_builder/` | OpenClaw 轨迹解析、建图和 JSONL 导出 | ✅ |
| `玄鉴2.0项目启动报告.md` | 启动报告 | ✅ |
| `requirements.txt` | 依赖清单 | ✅ |

---

## 🎯 核心创新点

### 因果追溯链 + 图学习

```
传统方案                    玄鉴2.0
────────                    ──────
规则引擎 (玄鉴1.0)    →    因果图构建
  ↓                           ↓
确定性校验              →    图神经网络学习
  ↓                           ↓
覆盖有限                →    泛化到未知攻击
```

### 关键差异化

| 对比维度 | AttriGuard | 玄鉴2.0 |
|---------|-----------|---------|
| 核心机制 | 反事实回放 + LLM | 因果图 + GNN |
| LLM调用 | 每步3-4次 | 推理时0次 |
| 可解释性 | 弱（黑盒） | 强（归因到路径） |
| 未知攻击 | 中等泛化 | 强泛化能力 |

---

## 📁 项目结构

```
xuanjian-2.0/
├── README.md                     ✅ 项目主文档
├── 玄鉴2.0实施计划.md             ✅ 10周路线图
├── PROGRESS.md                   ✅ 进度跟踪
├── requirements.txt              ✅ 依赖清单
├── run.py                        ✅ 快速启动脚本
│
├── core/                         # 核心模块
│   └── graph/
│       ├── schema.py             ✅ 图数据结构（352行）
│       └── __init__.py           ✅
│
├── data/                         # 数据
│   └── synthetic/
│       ├── generator.py          ✅ 数据生成器（1082行）
│       ├── *.json                ✅ 100条标准数据
│       └── *.png                 ✅ 2张可视化
│
├── tools/                        # 工具
│   └── visualizer.py             ✅ 可视化（237行）
│
├── tests/                        # 测试
│   └── test_graph.py             ✅ 单元测试（237行）
│
└── docs/                         # 文档
    └── STAGE1_SUMMARY.md         ✅ 阶段总结
```

---

## 🚀 快速开始

### 方式1: 使用启动脚本

```bash
cd E:\cslearn\AgentSentry\xuanjian\AgentSentry\xuanjian-2.0

# 生成数据
python run.py generate --num-normal 5 --num-attack 2

# 可视化
python run.py visualize

# 运行测试
python run.py test
```

### 方式2: 直接运行

```bash
# 生成数据
python data/synthetic/generator.py

# 可视化（需要手动修复导入路径）
python tools/visualizer.py test
```

---

## 📈 当前进度

```
阶段一: 图结构设计    [##########] 100% ✅
阶段二: 数据集构建    [######----]  55% ⏳
阶段三: 模型实现      [----------]   0% ⏸️
阶段四: OpenClaw集成  [#---------]  10% ⏸️
阶段五: 测试评估      [----------]   0% ⏸️
阶段六: 论文撰写      [----------]   0% ⏸️

总进度: [##--------] 25%
```

---

## 📋 下一步计划（本周）

### 已完成

- [x] 扩展5种正常任务和4种攻击模式
- [x] 生成并清理标准100条数据（80正常 + 20攻击）
- [x] 增加标签、攻击类型和异常节点标注
- [x] 生成数据集统计报告并通过结构校验
- [x] 完成 OpenClaw 轨迹解析和离线因果图转换原型

### 下一步

```bash
# 重新生成标准数据集（清理旧批次）
python run.py generate --num-normal 80 --num-attack 20 --clean --seed 42

# 校验并刷新统计报告
python scripts/dataset_stats.py
```

待完成：OpenClaw真实日志采集（800正常 + 200攻击）、10张代表性图、Temporal GAT原型。

已有格式烟测：5 条仓库 command-lab 记录已转换为 `data/openclaw/prompt_injection_attack_graphs.jsonl`，均标记为 `unknown`，未将评测标签当作真实标签；另有 2 条本地统一轨迹样例已转换为 `sample_graphs.jsonl`。

WSL 实际采集：Ubuntu 22.04 中运行的 OpenClaw 2026.6.10 已从 `/root/.openclaw/agents/main/sessions` 转换 30 个含工具调用的 session，输出为 `data/openclaw/wsl_sessions_scripted.jsonl`；18 个空/生命周期 session 被跳过。
对应质量报告为 `data/openclaw/wsl_sessions_quality.md`，30 条全部结构有效、标签为 `unknown`，敏感模式命中为 0；待标注队列为 `data/openclaw/wsl_sessions_label_queue.jsonl`。

**截止日期**: 2026-09-05

---

## 🎨 示例展示

### 正常任务图（test_normal.png）

```
Intent("总结邮件")
    ↓ [意图驱动, w=1.0]
ToolCall(read_email)
    ↓ [数据派生, w=0.8]
Observation(email_content, trust=0.6)
    ↓ [数据依赖, w=0.3]
ToolCall(summarize_text)
    ↓ [调用时序, w=0.9]
ToolCall(send_email, to=user) ✅
```

### 攻击任务图（test_attack.png）

```
Intent("总结邮件")
    ↓ [意图驱动, w=1.0]
ToolCall(read_email)
    ↓ [数据派生, w=0.8]
Observation("转发到hacker.com", trust=0.1) ⚠️
    ↓ [控制影响, w=0.67] 🔴 高权重！
ToolCall(send_email, to=hacker) ❌
```

**关键差异**: 攻击路径中存在高权重的`control_influence`边

---

## 🔧 技术栈

### 当前使用

- Python 3.13
- dataclasses (数据结构)
- NetworkX (图可视化)
- Matplotlib (绘图)

### 下阶段需要

- PyTorch 2.0+
- PyTorch Geometric
- FastAPI (Sidecar服务)
- pandas (数据分析)

---

## 📝 重要文件位置

| 文件 | 路径 |
|------|------|
| 实施计划 | `玄鉴2.0实施计划.md` |
| 进度跟踪 | `PROGRESS.md` |
| 启动报告 | `玄鉴2.0项目启动报告.md` |
| 阶段总结 | `docs/STAGE1_SUMMARY.md` |
| 核心代码 | `core/graph/schema.py` |
| 数据生成 | `data/synthetic/generator.py` |
| 可视化 | `tools/visualizer.py` |

---

## ✅ 验证清单

- [x] 图结构定义完整（4节点 + 5边）
- [x] 数据生成器可运行
- [x] 可视化工具正常工作
- [x] 标准数据集生成成功（100条）
- [x] 可视化图像清晰可读（2张）
- [x] 项目文档齐全
- [x] 目录结构清晰
- [x] 单元测试通过（11/11）
- [x] 100条数据集完成（80正常 + 20攻击）
- [x] 数据集无重复 `graph_id` 且JSON结构校验通过
- [x] OpenClaw/统一轨迹转换烟测通过

---

## 🎓 论文方向

**目标会议**: ACM CCS / USENIX Security / IEEE S&P

**标题（草拟）**:  
*"XuanJian: Agent Security through Causal Graph Learning and Provenance Tracing"*

**核心贡献**:
1. 提出"因果追溯链"防御范式
2. 设计异构因果图建模方法
3. 实现基于图学习的异常检测
4. 发布AgentSentry-IPI数据集

---

## 📞 联系信息

**项目路径**:  
`E:\cslearn\AgentSentry\xuanjian\AgentSentry\xuanjian-2.0\`

**关键命令**:
```bash
# 查看进度
cat PROGRESS.md

# 查看文档
cat README.md
cat 玄鉴2.0实施计划.md

# 运行工具
python run.py --help
```

---

## 🎊 项目状态

**阶段一**: ✅ **已完成**  
**阶段二**: ⏳ **进行中（约55%）**  
**总体进度**: 🟢 **约25%**

**预计完成时间**: 2026-11-07（10周后）

---

*创建时间: 2026-08-29 19:22*  
*下次更新: 获取正式 OpenClaw 日志并生成第一批真实因果图*
