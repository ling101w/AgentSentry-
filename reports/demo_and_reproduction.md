# 玄鉴 演示与复现实验指南

更新时间：2026-07-03

## 主入口

比赛展示以 `8765` 为主：

- `http://<服务器IP>:8765/command-lab`：业务测试台。
- `http://<服务器IP>:8765/records`：运行记录与风险观测。
- `http://<服务器IP>:8765/security-screen`：安全态势大屏。
- `http://<服务器IP>:18789/`：OpenClaw Control UI。

`8000` 是历史离线原型和辅助入口，不建议作为主展示入口。

## 推荐展示顺序

1. 打开 `8765/command-lab`，先运行普通健康 API、普通文件写入或普通记忆写入，说明系统不是一刀切。
2. 运行外部内容注入样例，展示邮件/网页/PDF/图片中的隐藏内容如何污染上下文。
3. 展示被污染上下文流向敏感文件、外部邮件或 API 时被阻断。
4. 运行长期记忆投毒，说明普通偏好可写，越权持久化不可写。
5. 运行恶意 Skill 或网关劫持样例，说明工具调用劫持被识别。
6. 切到 `8765/records` 查看每步 `tool_decision`、`guard_finding`、`alert`。
7. 切到 `8765/security-screen` 展示实时统计、拓扑、告警和规则命中。
8. 打开 `reports/project_name_and_benchmark_summary.md` 展示公开 benchmark 结果。
9. 打开 `reports/technical_design_and_algorithms.md` 讲清楚 TaskSpec、污点传播、语义动作图、Memory Guard 和 LLM-Judge 的算法设计。

## 复现命令

```bash
cd /home/ubuntu/AgentSentry-

npm --prefix openclaw-plugin run test:policy
.venv/bin/python -m pytest -q

python3 scripts/run_benchmark_eval.py \
  --max-cases 520 \
  --llm-judge-rate -1 \
  --llm-judge-timeout-ms 15000 \
  --timeout 35 \
  --sleep 0.02 \
  --profile-note xuanjian-risk-tiered

python3 scripts/run_tool_attack_benchmark_eval.py \
  --max-cases 320 \
  --max-agentdefense-attack 120 \
  --max-agentdefense-benign 50 \
  --max-basharena 24 \
  --max-agentharm 80 \
  --max-toolemu 80 \
  --llm-judge-rate -1 \
  --llm-judge-timeout-ms 15000 \
  --timeout 35 \
  --sleep 0.02
```

`--llm-judge-rate -1` 表示不由脚本抽样开关 LLM，而是使用服务端当前调度。当前推荐配置是 `semantic.mode=risk-tiered`。

## 服务检查

```bash
systemctl --user status openclaw-gateway.service --no-pager
curl -sS http://127.0.0.1:8765/api/health | python3 -m json.tool
curl -sS http://127.0.0.1:8765/api/stats | python3 -m json.tool
curl -sS http://127.0.0.1:8765/api/security/overview | python3 -m json.tool | sed -n '1,120p'
```

## 最新输出

- 综合回归报告：`reports/benchmark_risk_tiered/benchmark_eval_report.risk_tiered.md`
- 综合回归原始结果：`reports/benchmark_risk_tiered/benchmark_eval_results.risk_tiered.json`
- 工具专项报告：`reports/benchmark_risk_tiered/tool_attack_benchmark_report.risk_tiered.md`
- 工具专项原始结果：`reports/benchmark_risk_tiered/tool_attack_benchmark_results.risk_tiered.json`
- risk-tiered 长文本留档：`reports/benchmark_risk_tiered/xuanjian_benchmark_risk_tiered_record.txt`
- 技术架构与算法说明：`reports/technical_design_and_algorithms.md`
- 开启/关闭对比：`reports/supervision_ablation/supervision_ablation_explained.md`
- 完整验收：`reports/full_acceptance/full_acceptance_report.latest.md`

## 审批模式演示

系统支持三种模式：

- `observe`：只记录，不阻断，适合作为无防护基线。
- `approval`：高风险动作进入人工审批。
- `block`：高风险动作执行前阻断，适合比赛主展示。

可在网页右上角切换，也可用 OpenClaw 命令：

```text
/agentsentry config set enforcement.mode approval
/agentsentry config set enforcement.mode block
```

## 注意事项

- 危险 shell 样例不会真正破坏主机；实验验证的是执行前裁决。
- 邮件发送使用本机 outbox 受控实现。
- eBPF 当前因权限不可用，健康检查会如实显示 unavailable。
