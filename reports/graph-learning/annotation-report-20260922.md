# 真实 Session 人工标注报告（v1）

日期：2026-09-22
标注范围：`replay_graphs.control-rebuilt.jsonl` 的 30 条 unknown + `wsl_sessions_final.control-rebuilt.jsonl` 的 30 条 unknown
标注人：agent:zcode-glm5.3（证据包逐条审阅，非抽样）
Schema：`xuanjian-2.0/data/annotation/annotation.schema.json` v1.0

## 1. 关键发现：唯一 session 是 31 条，不是 60 条

两个文件的 unknown 集合**重叠 29 条**（graph 内容逐字节一致，已用节点+边哈希校验）：

```text
replay unknown (30) ∩ wsl unknown (30) = 29 条完全相同
replay 独有：2f86c2cc-bcc9-493f-b759-59ba3f06b0e5
wsl   独有：af24853c-8b20-4656-a5c1-a61ff6dc0625
唯一 session 总数：30 + 30 - 29 = 31
```

一条 session 标注一次，结论同时回写两个文件（`.annotated.jsonl` 副本，原文件未改动）。
**后续任何"60 条真实数据"的口径需要更正为 31 条。**

## 2. 标注结果

| 指标 | 值 |
|---|---:|
| 标注记录 | 31 |
| normal | 31 |
| attack | 0 |
| ambiguous | 0 |
| reviewer_confidence | min 0.85 / mean 0.915 |
| 低置信复核清单（<0.7） | 空 |
| schema 校验错误 | 0 |
| 节点/边引用校验错误 | 0 |

**这批 unknown 真实轨迹中没有攻击。** 它们由两部分构成：

1. **用户本人的真实安全研究轨迹**（约 20 条）：Nacos AI/MCP SSRF 审计闭环（读模板→查重→写 PoC→本地部署验证→GitHub advisory）、Apache Dubbo CVE 挖掘、macrozheng/mall 静态审计、HGAME CTF web 题目（JWT 伪造/密钥爆破/SQLi，全程用户协作）、主机健康体检。所有 exec/write/browser 动作均可追溯到当轮用户明确授权（含"允许 继续"、"可以安装工具（web向）"、"可以在演示站创建一个一次性测试账号"等显式许可）。
2. **回放管线生成的脚本化正常轨迹**（约 11 条）：会话初始化读 SOUL/USER/MEMORY、standup 笔记写入、连通性测试、gateway 配置查询。这些是 replay runner 在 WSL 里跑出来的 session，与真实 session 混在同一目录被一起收集。

## 3. 证据完备性

| 档位 | 数量 | 说明 |
|---|---:|---|
| 原始 session 文件已审 | 11 | 完整用户消息 + 完整工具参数 + 完整观察内容 |
| 仅图节点证据 | 20 | 完整工具参数 + 200 字符观察预览 + 全部用户消息 |

原始 WSL session 文件中 20 条已被清理（含 1 条仅剩 `.reset.` 备份，已恢复使用并核对调用序列与图一致）。图节点证据里**工具调用参数是完整的**，这是判定攻击类型的主要依据；观察预览截断只影响工具返回内容的后半段，对本批判定无实质影响（已逐条确认无可疑未读内容）。20 条图证据样本的 confidence 按 0.85–0.9 记录并逐条标注 `raw_source_available=false`。

## 4. 数据质量警示（影响训练，必须在切分前处理）

### 4.1 standup 近重复簇（9 条）

以下 session 的写入内容逐字相同（三行日报写 `notes/standup-2026-08-20.md`）：

```text
0f4de1ac 186d5a52 9589223c b8342b6a c51a20fa d2b561f9(apply_patch 变体) d2bf4fe5 b21fc60d
+ 结构近似：0a208599 d02521b2 ac7222b9（同模板的 memory 读取簇）
```

若随机切分，测试集会出现训练集的近似复制，**正常误报率指标会虚低**。处理建议：近重复簇整簇同侧切分，或去重后保留 1–2 条。

### 4.2 困难负样本（保留）

`97d8670c`（healthcheck 技能运行）：obs_11 工具结果中包含防护层插入的
`⚠️System Warning: Injection Detected ... permission suspended` 警告文本。
这是**本系统防御组件的输出而非攻击载荷**，且后续调用未被其驱动。
任何以"工具结果含注入指令文本"为特征的检测器都会在这条上误报——
建议保留为回归测试固定样本。该 session 的 3 条 control_influence 候选边
全部来自 process poll 的 `action`/`sessionId` 协议字段回填，与攻击无关。

### 4.3 control_influence 边的语义分布

31 条轨迹共 5 条 control_influence 候选边（全部位于 97d8670c / 116dd195），
全部为轮询协议字段（`action`、`sessionId`、`timeout`）回填，无一条对应攻击传播。
**在真实正常轨迹上，control_influence 目前是"长任务轮询"的信号，不是攻击信号**——
与合成数据"control_influence 几乎只出现在攻击图上"的分布相反。
第 9–11 天的 control 边规则审计应以本轮结论为起点。

## 5. 对 18 天计划的直接影响

| 计划项 | 影响 |
|---|---|
| 第 2–4 天（本任务） | 完成：31/31 唯一 unknown 标注，0 条待复核 |
| 第 5–8 天（扩充 500 条） | **攻击样本 ≥150 无法从现有真实数据获得**——真实 unknown 全部 normal。需要按计划注入攻击轨迹（注入/劫持/外发/投毒/越权/shell 滥用 7 类），并用本轮的 schema + 证据包流程标注；同时注意真实 normal 与脚本 normal 的比例（避免模型学到"脚本腔=normal"） |
| 第 9–11 天（control 边审计） | 起点：真实正常轨迹的 control 边=轮询字段，精确率基数要从这里出发 |
| 第 12–15 天（GAT 训练） | 切分必须按 session_id 分组（29 条 session 有两份图副本，若分属两侧即数据泄漏）；standup 簇整簇同侧 |

## 6. 产出文件清单

| 文件 | 说明 |
|---|---|
| `xuanjian-2.0/data/annotation/annotation.schema.json` | 标签 schema v1.0（含条件约束） |
| `xuanjian-2.0/data/annotation/annotation-guidelines.md` | 标注指南（判定总则、attack_type 判定表、特殊情形） |
| `xuanjian-2.0/data/annotation/annotations.v1.jsonl` | 31 条标注记录（人工判定结论） |
| `xuanjian-2.0/data/annotation/evidence/<session_id>.md` ×31 | 逐 session 证据包（可复现审阅） |
| `xuanjian-2.0/data/annotation/evidence_manifest.jsonl` | 证据包清单 + 摘要哈希 |
| `xuanjian-2.0/data/annotation/raw_sessions/` ×11 | 已恢复的原始 session 文件 |
| `xuanjian-2.0/scripts/build_annotation_evidence.py` | 证据包生成脚本（可复跑） |
| `xuanjian-2.0/scripts/apply_annotations.py` | 校验 + 回写脚本（可复跑） |
| `reports/graph-learning/replay_graphs.control-rebuilt.annotated.jsonl` | 168 条（78 attack / 90 normal），intent 节点已同步 |
| `reports/graph-learning/wsl_sessions_final.control-rebuilt.annotated.jsonl` | 30 条（全 normal） |
| `*.label_queue.annotated.jsonl` ×2 | label queue 副本已填 annotator 字段 |

原文件（`*.control-rebuilt.jsonl`、原 label queue）未改动，标注通过新文件交付。

## 7. 复现方式

```bash
cd xuanjian-2.0
python -m scripts.build_annotation_evidence   # 重新生成证据包
python -m scripts.apply_annotations           # 校验 annotations.v1.jsonl 并回写
```

标注本体（`annotations.v1.jsonl`）是人工判定产物，不由脚本生成；
脚本只负责证据呈现与一致性校验。
