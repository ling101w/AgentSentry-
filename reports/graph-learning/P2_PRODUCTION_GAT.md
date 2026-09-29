# P2 Production Graph Shadow Router

更新时间：2026-09-16

## 状态

P2 已完成离线训练、阈值校准、OOD 回退和 CPU 延迟基准。模型只作为 Shadow/Advisory 组件，不参与 OpenClaw 在线裁决；确定性策略和现有 Semantic Judge 仍是唯一执行控制面。

## 数据

输入是 `production-graph-v1`，来自 Command Lab 受控采样：370 条图、109 个 session。训练按 `session_key` 分组切分：271 train、48 validation、51 test。输入质检结果为 370/370 有效、0 个禁止字段命中，投影截断率 21.62%。

标签是 `policy_outcome != allow` 的 `policy_weak_label`，不是独立攻击真值。`deterministic_block`、最终 decision、status、verdict、findings 和 Judge 输出都没有进入模型特征。

## 模型

`models/production_gat/` 实现纯 PyTorch 关系感知 GAT：2 层、hidden 48、约 15k 参数。节点输入是 58 维结构化特征，边输入是 24 维关系/证据特征。模型输出图风险概率；OOD profile 用训练集结构统计计算，超过 validation P95 阈值时输出 `judge_fallback`。

## 结果

详见：

- `production-gat-training-20260916.json`：训练历史、验证校准、测试指标和 OOD 统计
- `production-gat-scores-20260916.jsonl`：逐图 Shadow 路由结果
- `production-gat-latency-20260916.json`：CPU 推理延迟

当前 Pilot 的主要结果：

| 指标 | 结果 |
|---|---:|
| validation F1 | 0.824 |
| validation recall | 1.000 |
| held-out test F1 | 0.412 |
| held-out test recall | 0.583 |
| CPU inference P95 | 1.80 ms |
| CPU inference P99 | 2.10 ms |

测试集性能明显低于验证集，说明当前样本量、场景重复度和弱标签不足以支持在线接管。这个结果是数据质量信号，不应通过降低阈值来掩盖。

## 复现

```powershell
cd E:\cslearn\AgentSentry\xuanjian\AgentSentry\xuanjian-2.0
python scripts/train_production_gat.py
python scripts/score_production_gat.py `
  --input ..\reports\graph-learning\production-graph-pilot-20260915.jsonl `
  --checkpoint checkpoints\production_gat_router.pth `
  --output ..\reports\graph-learning\production-gat-scores-20260916.jsonl
python scripts/bench_production_gat.py `
  --input ..\reports\graph-learning\production-graph-pilot-20260915.jsonl `
  --checkpoint checkpoints\production_gat_router.pth `
  --output ..\reports\graph-learning\production-gat-latency-20260916.json
```

P3 前置条件：至少 2,000 个图、更多真实正常轨迹、每个攻击族的 evaluator-owned 标签，以及按时间/场景/攻击族的独立盲测。只有在 Shadow 误报率、漏报率和 OOD 回退稳定后，才考虑接入 Judge 调度。 
