# 授权识别与误干预优化（2026-10-17）

本次基于 `598b706` 的开发工作区，修复确定性文件授权与 LLM 补充提取之间的接口问题。以下是已知样例回归与少量真实 provider 测试，不代表生产误拦率、独立盲测、任务 Utility 或攻击保护率。

## 固定样例对比

输入由已有的 6 条正常种子、16 条明确文件操作和 14 条授权边界组成。两个 profile 使用相同的 36 条输入，不能合计为 72 个独立样本。关闭 Judge，不执行工具。基线和修复后使用相同 `cases_sha256`，详见 `before.json`、`after.json`。

| 每个 profile 的结果 | 修复前 | 修复后 |
| --- | ---: | ---: |
| 22 条正常请求 allow | 7 | 22 |
| 22 条正常请求 ask | 15 | 0 |
| 22 条正常请求 deny | 0 | 0 |
| 14 条边界请求被 allow | 1 | 0 |

balanced 与 competition 两个 profile 均得到上述结果。这批样例针对已发现的写入解析缺陷，不能用其中的干预比例估算真实业务流量。

修复包括：

- 识别“保存报告到/至/为”、带内容补充的“写入/创建/修改/更新”，以及操作目标中的中文文件名。
- 明确指令外的单个引号路径可以作为操作对象；整段引用、代码块、说明和条件语句不能提供写入授权。
- “把 A 保存到 B”只绑定 B 的写权限；读取后保存摘要的指令分别绑定源和目标。内容中提到的其他文件不成为写入目标。
- 新识别的写入动词同时进入否定匹配；外部工具结果、记忆和 system 来源不能因此获得用户权限。

复现（在 `openclaw-plugin` 下，Node 24）：

```powershell
npm run test:policy
node scripts/authorization-regression.mjs --output ../reports/authorization-optimization-20261017/after.json
```

该回归已接入 `test:policy`，因此完整 CI 也会执行它。

后续回归已扩充到 30 条正常请求和 24 条边界请求，命令默认运行扩充集合。本页表格和 JSON 保存第一轮固定子集的结果；扩充结果见 `../semantic-latency-optimization-20261017/`。

## LLM 实际接入与测试

已有 `core/task-spec/semantic-refinement.ts` 负责结构化授权提取，OpenClaw `before_prompt_build` 调用它。确定性解析先建立 TaskSpec，LLM 提供补充/收窄建议，建议仍须核验原始用户指令与作用范围。Sidecar/Lab 当前通过监督服务调用动作 Judge，其请求路径没有调用此任务提取器。

仓库默认模型名是 `gpt-4o-mini`；observe 默认关闭语义能力，balanced/competition 启用，但需要配置实际 provider 和凭据。此次使用用户提供的兼容接口，确认模型列表并选择返回的模型 ID；凭据只注入测试子进程环境。

| 实测模型 | 合成样例结果 | 提取耗时 | 动作 Judge |
| --- | --- | --- | --- |
| `deepseek-v4.1-flash` | 6/6 最终裁决符合预期 | 3.11–5.15 秒，中位 3.89 秒 | 2 秒预算耗尽，未取得语义结果 |
| `glm-5.3-flash` | 1 条递送指令通过 | 4.03 秒 | 2 秒预算耗尽，未取得语义结果 |

模型返回的 `response_model` 与请求模型名一致。实测请求均为合成文本，未执行发信、写入或其他业务工具。动作 Judge 超时后的 `allow` 来自原有确定性裁决，不能记成 LLM 审核成功。

真实模型测试发现并修复了另外两处误干预：

1. 模型常引用带句号的完整原句，本地子句切分移除了句号，导致原本正确的授权建议未通过匹配。现在统一规范句尾标点。
2. 正确补充的具体能力仍被任务初判留下的低总体置信度要求审批。现在先核验当前动作的明确、具体、高置信度用户能力；data_only/chatter、弱证据、错误目标和其他确定性边界继续检查。

同时，对 LLM 提出的文件能力重新核验动作类型与操作目标，防止把读取提为写入、把输入文件提为输出文件，或用 read_only 伪装持久化写入。

公开摘要见 `provider-summary.json`。原始合成响应细节保存在本地忽略的 `provider-*.local.json` 中；公开摘要不包含接口地址和凭据。复现入口为 `scripts/semantic-provider-smoke.mjs`，需要通过环境提供 `AGENTSENTRY_SMOKE_BASE_URL`、`AGENTSENTRY_SMOKE_MODEL`、`AGENTSENTRY_SMOKE_KEY`。该实测不会随普通 CI 自动调用。

当前 provider 的实测耗时适合进一步评估任务准备阶段的提取，尚未验证能满足同步动作裁决的 2 秒预算。正式启用前仍需测更多正常工作流和延迟分布；本次未改全局阻断阈值或默认 provider。
