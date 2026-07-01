# AgentSentry 使用与验收指南

## 访问入口

- `http://<服务器IP>:8000/`：AgentSentry 控制台。用于运行攻击/良性用例、查看事件流、策略裁决、污点传播和评测结果。
- `http://<服务器IP>:8000/security-screen`：AgentSentry 安全态势感知大屏。用于答辩展示真实聚合统计、3D Agent 工具拓扑、实时告警、规则命中和攻击链分布。
- `http://<服务器IP>:8765/`：OpenClaw 插件记录台。用于证明 OpenClaw 工具调用、foundation scan、tool decision、alert 记录已经被 AgentSentry 插件采集。
- `http://<服务器IP>:8765/command-lab`：OpenClaw 业务测试台。输入对抗指令后，系统会映射为发送邮件、读写文件、调用 API、执行命令、写记忆等受控业务工具；只有策略允许的请求会执行，并真实生成策略裁决、工具结果、发现和告警。
- `http://<服务器IP>:8765/security-screen`：OpenClaw 侧态势大屏。默认只统计 OpenClaw 插件真实记录，所以顶部“总事件数”应当等于 `8765/api/stats` 的 `total`。

系统功能清单见 `reports/system_functionality.md`，该文档按功能、入口、数据来源和当前限制客观说明当前已实现能力。

比赛展示建议先打开 8000 控制台讲清实验和防御机制，再打开 8765 业务测试台提交一条恶意指令，最后切到 8765 `/security-screen` 展示新产生的告警和阻断记录。

## 大屏数据来源

`/security-screen` 只使用接口返回的真实统计。页面每 3.2 秒请求一次：

```text
GET /api/security/overview
```

8000 后端支持三种口径：

- `source=openclaw`：只看 OpenClaw 插件记录，8765 大屏默认使用这个口径。
- `source=local`：只看 AgentSentry SQLite 离线实验记录。
- `source=combined`：合并 AgentSentry SQLite 与 OpenClaw 插件记录，适合写报告和研究分析。

8765 大屏默认通过插件代理调用：

```text
GET /api/security/overview
```

返回体中的 `source.mode` 应为 `openclaw`，`source.window` 会显示类似：

```text
latest 254 OpenClaw plugin records
```

如果短时请求失败，大屏会保留上一轮真实数据并标记 `STALE`；首次完全不可用时才显示 `NO API` 和空态提示。

## 比赛要求对照

| 要求 | 当前实现 | 验证方式 |
| --- | --- | --- |
| 至少 3 类攻击场景 | 已覆盖提示注入、工具返回污染、提示词抽取、记忆投毒、自适应攻击、畸形模型动作 | 查看 `reports/competition_report.md` 和 `reports/adversarial_testset.jsonl` |
| 对抗样本与越狱测试集 | JSONL 与 Markdown 均已生成 | `reports/adversarial_testset.jsonl`、`reports/agent_attack_scripts.md` |
| 智能体攻击脚本 | 工具动作链逐场景列出，可用于复现实验输入与预期风险路径 | `reports/agent_attack_scripts.md` |
| 开源智能化应用 | OpenClaw 插件接入，8765 展示真实插件记录 | `systemctl --user status openclaw-gateway.service --no-pager` |
| 受控业务工具 | 8000 独立原型执行 read/write/email/API/memory；8765 业务测试台可显式选择发送邮件、读写文件、调用 API、执行命令、写记忆并审计 | 打开 `/command-lab` 提交恶意指令 |
| 模型调用链路监控插件 | OpenClaw 插件记录 prompt、tool decision、tool result、approval、foundation scan | `curl http://127.0.0.1:8765/api/records?limit=20` |
| 基座模型检测/过滤原型 | 支持 OpenAI-compatible/DeepSeek 配置、JSON 工具动作过滤、畸形输出拒绝、语义扫描开关 | `curl http://127.0.0.1:8000/api/llm/config` |
| 行为监督 allow/ask/deny | 策略引擎对工具调用输出 allow/ask/deny，并写入审计记录 | 8765 `/command-lab` 页面状态显示“已阻断/需确认/已允许” |
| 实时展示告警/阻断 | 8765 `/security-screen` Live Alerts 和拓扑节点实时更新 | `python scripts/check_openclaw_ui.py` |
| UI 可读、无遮挡 | Playwright 自动检查 8000 与 8765 多视口 | `python scripts/check_ui_layout.py && python scripts/check_openclaw_ui.py` |

## 关键功能怎么看

- 顶部 KPI：总事件数、高危拦截、工具调用、污染传播、意图漂移、记忆投毒、策略放行、待审批，均来自真实事件聚合。
- 3D Agent 行为拓扑：节点数量、风险等级、阻断/审批/放行统计来自 `nodes` 字段；节点颜色会随真实风险态变化。
- API 调用流：调用频率、未阻断率、污染事件、策略命中来自 `meshMeta` 字段。
- Live Alerts：展示最近真实 BLOCK/ASK/高危事件，不存在告警时显示空态。
- Defense Modes：风险评分越低越好，基于真实 eval_results 中的 ASR、FPR、危险 sink 释放、检测缺口和防护层关闭缺口计算。
- 攻击链阶段：输入污染、认知偏移、决策越界、工具执行、数据外泄的事件数和拦截率来自真实日志文本、策略裁决和 severity。
- Top Rules：策略命中次数与风险命中率来自真实 rule 字段或事件语义归因。

## 常用验证命令

```bash
cd /home/ubuntu/AgentSentry-
source .venv/bin/activate

systemctl status agentsentry.service --no-pager
curl -sS http://127.0.0.1:8000/api/health
curl -sS 'http://127.0.0.1:8000/api/security/overview?source=combined' | python -m json.tool | sed -n '1,120p'
curl -sS http://127.0.0.1:8765/api/stats
curl -sS http://127.0.0.1:8765/api/security/overview | python -m json.tool | sed -n '1,120p'

pytest -q
python scripts/check_ui_layout.py
python scripts/check_openclaw_ui.py
```

`scripts/check_ui_layout.py` 会生成：

- `reports/ui-screenshots/screen-1920x1080.png`
- `reports/ui-screenshots/screen-1366x768.png`
- `reports/ui-screenshots/screen-1180x760.png`
- `reports/ui-screenshots/layout-check.json`
- `reports/ui-screenshots-8765/browser-functional-report.json`

报告中的 `issue_count: 0` 表示当前检查未发现文字溢出、固定元素越界或关键区域重叠。

## 实验复现

```bash
cd /home/ubuntu/AgentSentry-
source .venv/bin/activate
python scripts/run_competition_experiments.py
pytest -q
python scripts/check_ui_layout.py
```

实验输出文件：

- `reports/competition_report.md`：正式安全风险分析与防御报告。
- `reports/competition_experiment_results.json`：完整实验结果。
- `reports/competition_summary.csv`：防御模式汇总指标。
- `reports/competition_case_results.csv`：逐用例结果。
- `reports/adversarial_testset.jsonl`：对抗样本与越狱测试集。
- `reports/agent_attack_scripts.md`：智能体攻击脚本说明。

## 服务状态

当前部署方式：

- `agentsentry.service`：FastAPI 服务，监听 `0.0.0.0:8000`。
- OpenClaw 插件记录台：监听 `0.0.0.0:8765`。
- OpenClaw 插件网关：本地监听 `127.0.0.1:18789`。
- 当前 OpenClaw 插件配置为 `enforcement.mode=block`，高风险真实工具调用会被阻断；如需展示人工审批，可通过 `/agentsentry config set enforcement.mode approval` 切换。

重启 AgentSentry：

```bash
sudo systemctl restart agentsentry.service
```

查看日志：

```bash
journalctl -u agentsentry.service -n 120 --no-pager
```
