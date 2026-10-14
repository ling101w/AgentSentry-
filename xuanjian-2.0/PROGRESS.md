# 玄鉴2.0 开发进度跟踪

**最后更新**: 2026-09-29

---

## 总体进度：约45% 完成

```
[########--] 45%
```

---

## 阶段一：图结构设计与定义 ✅ (100%)

### 已完成
- [x] 核心数据类定义 (`core/graph/schema.py`)
  - [x] 4种节点类型：Intent, ToolCall, Observation, Entity
  - [x] 5种边类型：IntentDrives, ControlInfluence, DataDependency, CallSequence, DataDerivation
  - [x] 图序列化/反序列化（JSON格式）
  - [x] 图统计信息API

- [x] 人工数据生成器 (`data/synthetic/generator.py`)
  - [x] 正常样本生成：邮件摘要任务
  - [x] 攻击样本生成：IPI邮件外泄
  - [x] 批量生成接口

- [x] 图可视化工具 (`tools/visualizer.py`)
  - [x] NetworkX + Matplotlib可视化
  - [x] 节点颜色区分（按类型）
  - [x] 边颜色区分（按类型）
  - [x] 导出PNG图像

- [x] 项目基础设施
  - [x] 目录结构
  - [x] README文档
  - [x] requirements.txt
  - [x] 启动脚本 (run.py)
  - [x] 基础测试 (tests/test_graph.py)

### 生成的数据
- 100条JSON格式因果图（80正常 + 20攻击）
- 100个唯一 `graph_id`
  - 5种正常任务各16条，4种攻击模式各5条
  - 2张测试可视化图像（test_normal.png, test_attack.png）

### 交付物
```
xuanjian-2.0/
├── core/graph/schema.py          ✅ 352行
├── data/synthetic/generator.py   ✅ 1082行  
├── tools/visualizer.py           ✅ 237行
├── run.py                        ✅ 130行
├── tests/test_graph.py           ✅ 237行
├── README.md                     ✅ 203行
└── requirements.txt              ✅ 40行
```

---

## 阶段二：训练数据集构建 ⏳ (约55%)

### 目标
- [x] 100条人工合成数据（80正常 + 20攻击）
- [ ] 1000条OpenClaw真实数据（800正常 + 200攻击）
- [x] 数据集统计报告 (`dataset_stats.md`)
- [ ] 数据集可视化样本

### 当前状态
- [x] 基础数据生成器完成
- [x] 已生成100条标准数据（80正常 + 20攻击）
- [x] 已扩展5种任务类型：邮件、文件、日程、信息查询、代码审查
- [x] 已扩展4种攻击模式：IPI、数据外泄、权限提升、记忆投毒
- [x] 已加入JSON标签、攻击类型和异常节点标注
- [x] 已加入数据集校验与统计脚本 (`scripts/dataset_stats.py`)
- [x] 已实现 OpenClaw/统一轨迹解析和离线图转换原型
- [x] 已完成 5 条 command-lab 记录的格式烟测
- [x] 已从 WSL OpenClaw 原生 session 目录转换 30 条真实轨迹图
- [x] 已生成 WSL 快照质量报告和 metadata-only 待标注队列
- [ ] 需要继续采集并清洗至1000条真实数据（当前30条，标签为unknown）
- [ ] 需要生成10张代表性数据集可视化图

### 下一步行动
1. 持续从 WSL OpenClaw session 目录采集并去重
2. 构建1000条真实因果图数据（800正常 + 200攻击）
3. 生成10张代表性图并补充数据集README
4. 完成阶段二后开始Temporal GAT原型

---

## 阶段三：图学习模型实现 ⏳ (原型75% — Layer 2/3 + 延迟基准已就绪)

### 已完成（2026-08-30）
- [x] TemporalGAT 模型实现 (`models/temporal_gat/model.py`)
  - [x] 边类型专属注意力（5种边类型独立投影，可学习门控混合）
  - [x] 时序编码（时间偏移 + 正弦基扩展）
  - [x] 节点级异常头 + 图级门控注意力池化
  - [x] 多任务损失（节点级 + 图级 BCE，节点级含 pos_weight 平衡）
  - [x] 纯 PyTorch 实现（无 PyG 依赖，CPU 可跑）
- [x] 数据加载器 (`models/temporal_gat/dataset.py`)
  - [x] CausalGraph JSON → 张量（24 维结构特征 + tool/task 词表 one-hot）
  - [x] 多图批处理（断开大图 + 偏移拼接）
  - [x] 无标签图过滤（跳过启动期残留的 test_normal/test_attack）
  - [x] **新增** `<<OOV>>` 桶（2026-08-30）：未知工具/任务类型不再全零特征
- [x] 训练与评估脚本 (`models/temporal_gat/train.py`)
  - [x] 按图标签分层切分（70/15/15）
  - [x] 指标：Acc/Precision/Recall/F1/AUC（图级 + 节点级，无 sklearn 依赖）
  - [x] checkpoint 保存 + 训练结果 JSON 导出
- [x] 单元测试 8 项（`tests/test_temporal_gat.py`）

### 新增：Layer 2 路径排名 + Layer 3 控制影响回溯（2026-08-30）

`models/temporal_gat/explain.py` 在模型输出基础上叠加图结构遍历，纯 Python 无新增参数：

- `layer2_paths(graph, node_probs)`：从每个 intent 节点 BFS 限深 6 步，按"路径节点平均概率 × 边权累加"打分，输出 top_k=3 的可疑路径
- `layer3_trace(graph, node_probs)`：对每个高风险工具调用，沿 `control_influence` 边反向回溯到首个 low-trust 观测/实体，给出"低信任观测→控制边→危险工具"的归因链
- `explain_graph(...)`：统一入口，输出 `{verdict, top_nodes, paths, traces}` JSON

### 新增：端到端 detect + 延迟基准 + 词汇修复（2026-08-30）

- `models/temporal_gat/detect.py`：单条命令 `python -m models.temporal_gat.detect --checkpoint ... --vocab ... --input ... --output ...`，输出含路径/回溯的完整检测报告
- `models/temporal_gat/bench.py`：跨 batch_size=1/4/8/16/32 测延迟，写 CSV + JSON 摘要
- `scripts/rebuild_vocab.py`：当 checkpoint 的 vocab.json 丢失时，从训练数据重建
- `scripts/realism_gap.py`：合成 vs 真实 WSL 分布差距量化报告

### 延迟基准结果（1000 条合成图，CPU，hidden=64，layers=3，198k 参数）

| batch | batch_ms_med | graph_ms_med | graphs/s |
|------:|-------------:|-------------:|---------:|
| 1     |       11.39  |       11.39  |    87.8  |
| 4     |       14.38  |        3.60  |   278.1  |
| 8     |       16.14  |        2.02  |   495.6  |
| 16    |       22.20  |        1.39  |   720.7  |
| 32    |       24.11  |        0.75  |  1327.5  |

**结论**：bs=32 时单图 0.75ms，远低于一次工具调用往返延迟，符合 Sidecar 实时检测需求。

### 真实 WSL 盲测（30 条 session，detect.py，threshold=0.5）

- 全部判正常（risk 0.029–0.043），符合预期：这批 session 都是无攻击的日常日志
- 之前盲测结论一致——**0 条攻击样本，所以 0 命中**不能说明模型错
- 仍未在真实数据上验证召回率，需要执行重放管线采集真实攻击轨迹

### 单元测试

- `tests/test_explain.py` 新增 12 项（路径排名、回溯、统一解释），全部通过
- 总计 **40 项测试通过**（graph 11 + openclaw_dataset 2 + openclaw_graph_builder 7 + temporal_gat 8 + explain 12）

### 训练结果（1000条多样化合成数据，CPU）
- 数据扩容（2026-08-30）：新增随机化层 `data/synthetic/diversify.py` + 生成入口 `data/synthetic/generate_v2.py`
  - 值池参数替换 / 良性噪声调用插入 / 正常图 trust 随机化（防 low-trust 捷径）/ 攻击强度变化 / 时间戳抖动
  - 生成 1000 条（800 正常 + 200 攻击，4 攻击类型各 50），graph_id 全唯一
- 重训结果：测试集（150条）图级/节点级 acc/P/R/F1/AUC 仍全 1.000
  - **结论：即使随机化后，合成分布的可分性依然天然过强（source=observation + control_influence 边过于显式），合成指标已无信息量**
- checkpoint: `checkpoints/best_model.pth` + `checkpoints/vocab.json`，结果: `checkpoints/training_results.json`
- 运行: `python -m data.synthetic.generate_v2 --num-normal 800 --num-attack 200 --seed 42 --clean`
  然后 `python -m models.temporal_gat.train --data data/synthetic --epochs 60 --batch-size 32`

### 盲测：30 条真实 WSL session（2026-08-30）
- 工具：`models/temporal_gat/infer.py`（遗留接口，与本模块兼容）
- 结果：全部判定正常，risk 0.017~0.084（mean 0.045），0 条超过 0.5 阈值
  - 符合预期——这 30 条是无攻击的正常运行日志；上一会话 checkpoints_v2 的盲测结论一致（0.001）
- **分布差距量化（核心发现）**：
  - 图规模：合成 5~7 节点 vs 真实 3~546（avg 75，15 倍差距）
  - 工具词表：合成 29 个工具名只有 **1 个**（web_search）出现在真实数据（3.4% 重叠）
  - trust：真实观测 99.5% 为 medium（均匀的合成 trust 分布在真实中不存在）
  - **含义：模型的特征空间与真实数据几乎完全脱节，OOV 工具全零特征导致模型默认输出"正常"。合成→真实迁移在当前形态下不成立**
- 结果文件：`checkpoints/wsl_blind_test.json`

### 重放管线三件套就绪（2026-08-30）
- `scripts/build_replay_manifest.py`：从 balanced 池（1295 条）选可执行 case 生成 manifest
  - 跳过含 `{placeholder}` 模板的 case；产出 `data/replay/manifest.jsonl` 180 条（120 攻击 + 60 正常）
  - delivery 分布：file（IPI 文件投递）102 / inline（直接注入对照）18 / none（正常）60，覆盖 5 个数据来源
- `scripts/replay_wsl.sh`：WSL 内执行器
  - 遍历 manifest，按 delivery 准备 payload 文件/内联注入，调 OpenClaw headless CLI
  - session 目录前后快照 diff 做行为归因，写 `<output>.log.jsonl`
  - ⚠️ CLI 命令留两个候选占位，需在 WSL 里确认 `openclaw agent --session-key ... --message ...` 还是 `openclaw run --session ... --prompt ...`
- `scripts/relabel_graphs.py`：join manifest + 重放日志给转换图打标
  - 主路径 session→replay 映射 + fallback marker 匹配；dry-run 用真实 replay_id 验证通过（attack/normal/unknown 三类映射均正确）
- 配套修复：`tools/openclaw_graph_builder/graph_builder.py` 的 control_influence 边判定——真实 OpenClaw 日志从不打 `source=observation` 标签，改为字段匹配比例 ≥0.5 判定
- 环境阻塞：wsl.exe 被安全中心黑名单拦截，无法从当前环境代跑，需用户在 WSL 终端执行或解除拦截

### 待完成（更新后的优先级）
- [ ] **执行重放（唯一硬需求）**：在 WSL 里确认 CLI 命令形式 → 先跑 5 条烟测 → 放量 180 条
- [ ] 重放产物 collect → 转图 → relabel 打标 → 混合训练（合成+真实重放）→ 重跑盲测验证
- [ ] 路径级检测（第二层）与控制影响回溯（第三层）实现 ✅ **已完成**（见 explain.py + 12 项单元测试）
- [ ] 推理延迟基准测试 ✅ **已完成**（0.75 ms/graph @ bs=32）
- [ ] 数据目录收编：data/synthetic（当前主线）与 data/synthetic_v2（上一会话对照集）并存，建议后续统一为一套

---

## 阶段四：OpenClaw集成工具开发 ⏸️ (离线原型10%)

### 目标
- [ ] 实时因果图构建工具
- [ ] Sidecar服务（FastAPI）
- [ ] before_tool_call钩子集成
- [ ] Docker镜像

### 状态
已完成离线 `parser.py`、`graph_builder.py`、`exporter.py` 原型；实时钩子、Sidecar 和 Docker 仍待模型接口确定后实现

---

## 阶段五：端到端测试与评估 ⏸️ (0%)

### 目标
- [ ] 功能测试
- [ ] 性能测试
- [ ] AgentDojo benchmark
- [ ] 演示视频

### 状态
等待阶段四完成后开始

---

## 阶段六：论文撰写与数据集发布 ⏸️ (0%)

### 目标
- [ ] 学术论文初稿
- [ ] AgentSentry-IPI数据集发布
- [ ] 开源代码仓库
- [ ] 项目网站

### 状态
等待阶段五完成后开始

---

## 关键里程碑

| 日期 | 里程碑 | 状态 |
|------|--------|------|
| 2026-08-29 | 项目启动，完成阶段一 | ✅ |
| 2026-09-05 | 完成100条人工数据集 | ✅ |
| 2026-09-12 | 完成1000条真实数据集 | ⏸️ |
| 2026-09-19 | 完成Temporal GAT模型 | ⏸️ |
| 2026-09-26 | 完成模型训练与评估 | ⏸️ |
| 2026-10-03 | 完成OpenClaw集成 | ⏸️ |
| 2026-10-10 | 完成端到端测试 | ⏸️ |
| 2026-10-24 | 完成论文初稿 | ⏸️ |
| 2026-11-07 | 数据集与代码开源发布 | ⏸️ |

---

## 技术债务与待优化项

### 高优先级
- [ ] 添加更多单元测试覆盖
- [ ] 优化图构建性能（大规模图）
- [ ] 添加配置文件支持（YAML）

### 中优先级
- [ ] 添加日志系统
- [ ] 添加命令行参数验证
- [ ] 改进错误处理

### 低优先级
- [ ] 添加类型注解检查（mypy）
- [ ] 代码风格检查（black, flake8）
- [ ] 性能分析工具集成

---

## 资源需求

### 计算资源
- [x] 本地开发环境（已就绪）
- [ ] GPU服务器（模型训练阶段需要）
- [ ] 云存储（数据集托管）

### 数据资源
- [x] 合成数据生成器（已完成）
- [x] WSL OpenClaw session 读取权限
- [ ] 1000条正式真实数据的采集与标签
- [ ] AgentDojo benchmark数据集

### 人力资源
- [ ] 数据标注（攻击样本验证）
- [ ] 代码审查
- [ ] 论文润色

---

## 风险清单

| 风险 | 影响 | 概率 | 缓解措施 | 状态 |
|------|------|------|----------|------|
| OpenClaw API变更 | 高 | 中 | 维护兼容层，关注更新 | 监控中 |
| 模型性能不达标 | 高 | 中 | 准备消融实验，超参数调优 | - |
| 数据集规模不足 | 中 | 低 | 优先完成人工数据，真实数据作为补充 | - |
| GPU资源不足 | 中 | 低 | 使用小规模模型原型，云GPU租赁 | - |

---

## 更新日志

### 2026-08-29
- ✅ 项目初始化
- ✅ 完成核心图结构定义
- ✅ 完成人工数据生成器（基础版）
- ✅ 完成图可视化工具
- ✅ 生成第一批测试数据（5条）
- ✅ 生成可视化图像（2张）
- ✅ 扩展5种正常任务和4种攻击模式
- ✅ 生成标准100条数据集（80正常 + 20攻击）
- ✅ 修复批量生成的重复ID和随机分布问题
- ✅ 增加数据标签、校验脚本和统计报告
- ✅ 单元测试扩展至11项并全部通过
- ✅ 实现 OpenClaw 轨迹解析、因果图构建和 JSONL 导出
- ✅ 用统一轨迹、逐行事件和 command-lab 记录完成格式烟测
- ✅ 在 WSL Ubuntu 22.04 / OpenClaw 2026.6.10 中完成原生 session 采集
- ✅ 导出 30 条真实 session 图（跳过18条空/生命周期 session）

### 2026-08-30
- ✅ TemporalGAT 模型原型完成（边类型注意力 + 时序编码 + 双头输出）
- ✅ 数据加载器与多图批处理（无 PyG 依赖，纯 PyTorch CPU）
- ✅ 训练/评估脚本：分层切分、图级+节点级指标、checkpoint、结果 JSON
- ✅ 100 条合成数据首次训练：测试集全指标 1.000（管线验证通过）
- ✅ 新增 8 项模型单元测试，全部通过（累计 28 项）
- ✅ 重放管线三件套完成：manifest 生成器（180 cases）+ WSL runner（CLI 待确认）+ relabel 打标（dry-run 验证通过）
- ✅ graph_builder 修复 control_influence 判定（真实日志 0 条控制边的根因）

### 2026-08-30 (晚 21:15, 本轮)
- ✅ Layer 2 路径排名 + Layer 3 控制影响回溯：`models/temporal_gat/explain.py` + 12 项单元测试
- ✅ 端到端 detect 入口：`models/temporal_gat/detect.py`（加载→打分→解释→JSON 报告）
- ✅ 延迟基准：`models/temporal_gat/bench.py`，CPU bs=32 时 **0.75 ms/graph（1327 graphs/s）**
- ✅ OOV 桶修复：`dataset.py` 加 `<<OOV>>`，未知工具不再全零特征，retrain 后 vocab 自动包含
- ✅ 丢失的 `vocab.json` 重建脚本：`scripts/rebuild_vocab.py`
- ✅ 合成 vs WSL 分布差距量化：`scripts/realism_gap.py` → `benchmarks/realism_gap.md`
- ✅ 用重建 vocab 重训模型（198k 参数，CPU 40 epochs），合成指标仍全 1.000（确认分布过强）
- ✅ WSL 盲测新流程（detect.py）：30 条 session 全判正常（risk 0.029–0.043），符合预期
- ✅ 测试套件扩至 40 项，全部通过

### 2026-08-30 (晚 22:35, 准备放量跑)
- ✅ `relabel_graphs.py` fallback 路径补 `replay_id` 字段（之前只填了 `label/attack_type/source_dataset`）
- ✅ `relabel_graphs.py` 在现有 4 条 log + 11 个 xjreplay session 上端到端冒烟通过
  - 41 条图 → 11 attack + 0 normal + 30 unknown
  - attack_type 分布：`Data Security Harm` / `Physical Data` / `indirect_prompt_injection` / `Financial Data` / `mcp_preference_manipulation` 等多源都正确归因
- ✅ `replay_wsl.sh` 新增 `--resume` 标志
  - 第 3 参数 LIMIT 不变，第 4+ 参数扫 `--resume` / `--no-resume`
  - 启用 resume 时不归档已有 log，扫描已有 entry 跳过对应 replay_id
  - 默认（--no-resume）行为不变：归档旧 log 启动新 log
  - 用 3 条 manifest + 假 prior log 烟测通过：skip=1 / processed=0 / log 行数不变
  - 默认路径烟测：旧 log 自动归档为 `*.YYYYMMDD_HHMMSS.bak`，新 log 从空开始
- 准备好放量跑：用户去 WSL 起一次完整 180 条 `--resume` 长跑

---

### 2026-09-15 ~ 09-23（补记）
- ✅ P2 production GAT shadow router（`models/production_gat/`，报告 `reports/graph-learning/P2_PRODUCTION_GAT.md`）：test F1 0.412，仅 Shadow
- ✅ control 边保守重建 + realism gap 复测（`realism-gap.control-rebuilt.md`）
- ✅ 31 条唯一真实 session 人工标注（v1，全部 normal，`annotation-report-20260922.md`）
- ✅ 78 条 replay 攻击证据包 + CANDIDATE 标注（v2 初稿）

### 2026-09-29
- ✅ Git 整理：图学习工作统一提交到 `feat/graph-learning-2.0`；合成数据与含真实凭据的证据包加入 .gitignore
- ✅ v2 复核：78 条 replay 中仅 **9 条注入真正生效**（57 no_effect / 8 refused / 4 no_delivery）
- ✅ 发现 replay_graphs 中 60 条 `synthetic://normal` 为单节点占位图，已剔除
- ✅ `scripts/build_real_dataset.py`：109 图 / 105 组（按工具调用签名合并近重复）
- ✅ `models/temporal_gat/train_real.py`：分组 5 折 CV × 3 seeds + size/bag_of_tools 基线 + replay_only 切片
- ✅ 结果：GAT AUC 0.727 vs bag_of_tools 0.718（replay_only 0.717 vs 0.766）——**9 个正样本下图结构无可测增益**
- 报告：`reports/graph-learning/real-cv-20260929.md`；测试 51 项全部通过

---

**下次更新计划**: 在 WSL 重放可执行（无占位符）注入 case，把 manifested 攻击扩到 ≥60 条 → 重跑 train_real，GAT 需在 replay_only 切片显著超过 bag_of_tools
