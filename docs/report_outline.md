# AgentSentry 作品报告骨架

## 1. 摘要

AgentSentry 面向大模型智能体应用中的提示注入、工具返回污染、记忆投毒等风险，提出“生命周期拦截点 x 保证强度”的二维运行时监督框架。系统在工具调用边界执行来源标签传播、任务意图约束、确定性 sink 阻断和轻量行为哨兵兜底，并通过中文实时大屏展示调用链、告警和污点传播。

## 2. 威胁模型

- 可信边界：用户原始任务、系统策略、监督层代码、策略文件。
- 不可信来源：网页、邮件、文件、RAG、工具返回、被投毒记忆。
- 攻击目标：越权工具调用、机密数据外泄、持久化控制、规避监督策略。
- 安全性质：确定性阻断已标注数据流到高危 Sink，并用 TaskSpec/allowed_targets 限制任务外工具和目标；行为哨兵覆盖文本诱导和轨迹漂移残余风险。
- 二维定位：五层说明 where，确定性/启发式说明 how hard。

## 3. 系统设计

- 最小 Agent：OpenAI-compatible JSON 动作协议，离线演示使用确定性 FakeLLM。
- 工具 Proxy：所有工具调用必须经过 AgentSentry 裁决。
- 标签传播：数据携带 source、integrity、confidentiality、tainted。
- 策略闸门：YAML DSL 配置 send_email、write_file、call_api 等 Sink 约束。
- 行为哨兵：工具序列、参数、外部地址、路径、近期风险事件等轻量特征。
- 二维矩阵：层 × 保证强度，明确 deterministic / heuristic / lightweight sentry 的边界。
- 监控大屏：实时态势、告警、调用时间线、污点传播、评测指标。

## 4. 攻击用例

中文用例集位于 `cases/agentsentry_cases.yaml`，覆盖：

- 良性网页总结
- 正常白名单邮件
- 间接提示注入
- 工具返回污染
- 记忆投毒
- 自适应慢速投毒
- 畸形模型输出

## 5. 评测协议

- 指标：ASR、TPR、FPR、Business Completion Rate、Bypass Rate、Block TPR、Intervention TPR、Ask Rate、平均延迟，以及 deterministic / heuristic 分组指标。
- 防御模式：full、no_deterministic、no_sentry、no_feedback、none。
- 导出接口：`GET /api/eval/export.csv`、`GET /api/cases/export.json`。
- 后续可接入 AgentDojo / InjecAgent adapter，当前版本提供稳定自建中文集和基准映射字段。

## 6. 当前结果

运行 `POST /api/eval/run?defense_mode=full` 或 `python scripts/demo_run.py` 生成最新结果。默认内置集期望展示：

- 攻击成功率降低
- 阻断召回率高
- 良性任务保持可完成
- 每个阻断动作可解释到策略原因和污点来源

## 7. 局限与未来工作

- 当前行为哨兵为轻量规则/特征基线，还不是完整 GNN/时序图模型。
- 当前真实 AgentDojo/InjecAgent 只保留 adapter 设计和映射字段，尚未直连运行。
- 隐式流、侧信道和长期慢速投毒仍需更系统的实验。
- 真实 LLM 模式需要进一步增强模型输出纠错和多轮工具计划稳定性。
