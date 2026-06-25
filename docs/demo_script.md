# AgentSentry 演示脚本

## 演示目标

用 2-3 分钟展示 AgentSentry 不是“关键词过滤器”，而是在工具边界基于任务意图、数据来源和污点标签做运行时裁决；同时强调“生命周期拦截点 x 保证强度”的二维矩阵。

## 准备

```powershell
python -m uvicorn --app-dir src agentsentry.app:app --host 127.0.0.1 --port 8000
```

打开：

```text
http://127.0.0.1:8000
```

## 流程

1. 展示首页：说明左侧是场景演示，中间是调用时间线，右侧是告警、污点传播和评测指标；先点出“确定性 hard gate”与“哨兵兜底”是两条正交主轴。
2. 选择“良性网页总结”：说明正常任务只读取网页，不触发高危 Sink。
3. 选择“间接提示注入”：恶意网页诱导读取 `secret.txt` 并发给 `attacker@x.com`。
4. 点击“开始监督运行”：指出 `read_file` 被 TaskSpec 拒绝，`send_email` 被白名单和策略闸门拒绝；`ask` 在这里表示未放行，不会执行工具。
5. 展示污点传播：`read_webpage -> web:mock://attack` 标记为不可信来源。
6. 选择“Rita 风格提示词抽取”：说明恶意网页把系统提示泄露包装成安全审计，Input Sanitization 只记录/打污点，真正的读取 `system_prompt.txt` 在 Execution Control 被拒绝。
7. 选择“工具返回污染”：说明 API 返回值夹带写启动项指令，`write_file` 因路径越权被拒绝。
8. 选择“记忆投毒”：说明记忆读写被审计，外发攻击地址仍被拒绝。
9. 点击“运行评测”：展示 ASR、TPR、FPR、业务完成率，以及 deterministic / heuristic 拆分指标。

## 答辩话术

- 和 Guardrail 的区别：我们不只判断文本坏不坏，而是在工具调用时检查“谁产生了数据、任务是否允许、数据能否流向 Sink”。
- 和纯确定性方法的区别：确定性闸门负责可证明阻断，行为哨兵覆盖文本诱导、记忆漂移和自适应攻击的残余风险。
- 二维矩阵怎么讲：五层回答“在哪拦”，确定性/启发式回答“拦得多硬”。
- referenced_spans 被伪造怎么办：最终裁决不依赖模型自报，依赖监督层独立标签传播和暴露污染兜底。
- 误报如何解释：看 FPR 和 Business Completion Rate，并可通过策略阈值与白名单调整；`ask` 不计入完成。
