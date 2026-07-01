# AgentSentry 比赛展示与复现实验说明

## 两个端口怎么用

- `http://<服务器IP>:8000`：AgentSentry 独立原型控制台。用于稳定展示攻击用例、评测指标、污点传播和策略裁决。
- `http://<服务器IP>:8765`：OpenClaw 插件记录台。用于展示真实 OpenClaw 智能体工具调用被插件审计、告警和阻断。

比赛答辩时建议先看 8000 讲清机制和指标，再打开 8765 证明它确实接进了 OpenClaw。

## 当前实验结论

- 无监督基线 ASR：0.833，不安全工具释放数：9。
- AgentSentry full ASR：0.0，TPR：1.0，FPR：0.0，业务完成率：1.0。

## 复现步骤

```bash
cd /home/ubuntu/AgentSentry-
source .venv/bin/activate
python scripts/run_competition_experiments.py
pytest -q
python scripts/check_ui_layout.py
systemctl --user status openclaw-gateway.service --no-pager
systemctl status agentsentry.service --no-pager
```

## 控制台展示顺序

1. 在 8000 选择 DeterministicLLM，运行“良性网页总结”和“正常白名单邮件”，说明良性业务可完成。
2. 运行“间接提示注入”，说明网页内容被标记为不可信，`read_file` 和攻击者邮件被阻断。
3. 运行“工具返回污染”，说明 API 返回夹带的写启动项指令被 `write_file` 策略阻断。
4. 运行“Rita 风格提示词抽取”，说明系统提示读取被 TaskSpec 和敏感资产策略阻断。
5. 运行“记忆投毒”或“自适应慢速投毒”，说明记忆写入审计和外部邮件阻断。
6. 打开 8765，看 OpenClaw 插件记录、foundation scan、tool_decision 和 alert。

## 交付文件

- `reports/competition_report.md`：正式报告。
- `reports/competition_experiment_results.json`：完整机器可读结果。
- `reports/competition_summary.csv`：汇总指标。
- `reports/competition_case_results.csv`：逐用例结果。
- `reports/reproduction_guide.md`：展示脚本和复现说明。
- `reports/ui-screenshots/`：大屏和控制台截图以及布局自动检查结果。
