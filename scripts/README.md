# scripts

可复现实验和检查脚本目录。

| 脚本 | 用途 |
|---|---|
| `run_benchmark_eval.py` | 综合攻击回归 benchmark 评测。 |
| `run_tool_attack_benchmark_eval.py` | 非提示注入工具攻击专项评测。 |
| `run_full_acceptance_tests.py` | 8765 插件完整功能验收。 |
| `run_competition_experiments.py` | 早期 8000 离线原型竞赛实验。 |
| `check_openclaw_ui.py` | 检查 8765 / 18789 页面可访问和基础 UI 状态。 |
| `check_ui_layout.py` | 早期 8000 页面布局检查。 |
| `demo_run.py` | 早期离线原型一键演示。 |

脚本输出不要直接放在本目录，统一写到 `reports/` 或 `runtime/`。
