# src/agentsentry

AgentSentry Python 离线原型包。

主要模块：

- `app.py`：FastAPI 应用入口。
- `policy.py`、`guard.py`、`sentry.py`：离线策略与行为检测。
- `supervisor.py`、`tools.py`：脚本化 agent 和沙箱业务工具。
- `storage.py`、`security_overview.py`：SQLite 存储和安全大屏聚合。
- `evaluation.py`：内置离线评测。

当前比赛展示以 OpenClaw 插件为主，本包作为辅助研究和回归测试保留。
