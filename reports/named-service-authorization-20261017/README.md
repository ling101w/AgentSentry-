# 命名服务授权与历史 API 映射修复（2026-10-17）

本轮让用户用服务名称请求健康检查时，可以从可信配置确定精确地址。继续回放同一份冻结开发集：210 条来源标签为 allow 的工作流，另有 3 条 ask 对照。输入、标签、阈值和 Judge 开关均保持原值；本轮零模型调用。

## 固定样本结果

| 配置 | 阶段 | allow | ask | deny | 拒绝比例 | 审批或拒绝比例 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| balanced | 本轮前 | 151 | 6 | 53 | 25.2% | 28.1% |
| balanced | 本轮后 | 161 | 6 | 43 | 20.5% | 23.3% |
| competition | 本轮前 | 151 | 0 | 59 | 28.1% | 28.1% |
| competition | 本轮后 | 161 | 0 | 49 | 23.3% | 23.3% |

每个配置新增 10 条 deny → allow，未把 deny 改成 ask，也未对原先 allow 的工作流新增干预。两个配置重复使用相同样本，不能合并为 420 个独立任务。3 条原标签 ask 的对照仍全部 deny，单列、不纳入 210 条分母。

主集合 SHA-256 仍为 `1e98ff2a6cf1a1adcd003bb0fa9bf167ebb282e2b4c9c16c445525f5e91b6b16`。`before-replay.json` 保留上一轮结果，`after-replay.json` 为本轮最终回放，`comparison.json` 校验逐条 input hash 并列出所有变化。最终回放、对照和原生运行各自记录源码指纹；它们的最终指纹相同，单次运行前后一致。

这仍是包含模板变体、已知样本和旧适配错误的开发测量。上述比例是 source-labelled normal 的策略干预比例，不能宣称线上 FPR、独立 holdout 成绩或原始 MCP 任务的完成率。纯回放不执行工具，遇到首次 ask/deny 即停止，Utility 保持为空。

## 43 条旧 API 映射的真实情况

本地历史报告及 `scripts/run_tool_attack_benchmark_eval.py` 的旧适配代码确认：原始 MCP 操作曾统一替换成 `call_api`，目标统一改成 `http://127.0.0.1:8765/api/health`，用户请求也改成了本地健康检查。部分原始 URL 已被覆盖；业务参数却保留了下来。

`mapping-audit.json` 记录 43 条的原始工具名、描述及残留参数字段，来源报告 SHA-256 为 `7edef8f18953a4d0756af6f6574c2282f10e65d7161b20e3f17bf3dbe6394fe4`。

- 10 条只含映射后的健康检查 URL，可以满足当前精确 GET 契约。本轮恢复的是这 10 条**映射后的健康检查授权**。
- 33 条还带着 model、code、query、data、source/destination、日历标题等原业务参数。它们不符合健康接口契约，继续 deny，并给出对应工具适配提示。

这些拒绝不能简单归为对原始正常 MCP 操作的误报。没有恢复原始 endpoint、业务授权和实际工具契约，就不能声称完成了模型预测、数据库写入或日历创建。

本轮同时修改未来的 benchmark 导入：没有适配器的 MCP 操作保留原工具名、参数和业务描述，停止生成假的健康检查调用。冻结的历史 JSONL 不重写、不删除、不重新标注，因此本轮前后仍可逐条比较。

## 产品实现

`policy.namedServices` 保存管理员配置的服务 ID、名称、用途和完整地址。当前只支持 `health_read`，限定 GET。内置 AgentSentry 健康服务根据已启用控制台的本地监听地址与端口生成，默认名称包含 AgentSentry、玄鉴和本地 API；它只绑定自身 `/api/health`。端口变更或控制台关闭会在下一次评估生效，配置为 localhost 时保留该主机名。

授权需要同时满足：用户在权威请求中点名服务并要求健康检查；名称只匹配一个服务；目标、方法与参数符合该操作；工具仍使用已知内置 HTTP 执行契约。否定、条件、引用、未知名称、名称冲突和工具返回内容不会建立新权限。用户另行禁止 API/网络访问时，健康检查也不会获得该权限。

这类能力只存在于当次评估快照，不写入已提交 TaskSpec 或 checkpoint。后续撤销服务、修改 endpoint 或替换工具契约不能复用旧授权。异步评估继续使用自己的配置快照。

参数仅接受 URL/方法的常规别名及审计 reason；别名之间必须一致。请求体、任意 headers、其他业务字段、不同端口/路径、query、fragment 和 URL 用户凭据均不满足健康契约。网页读取及其别名的通用只读豁免也不能绕过这些检查。现有 API host 限制、污点规则和调用频率限制继续生效。

Lab 执行器复用同一参数检查，并对命名服务关闭重定向；底层 HTTP 客户端现在正确支持 `maxRedirects: 0`。本地临时 HTTP 服务测试验证：合法 GET 返回成功；健康端点重定向后，下一地址收到的请求数为零；非法 POST 在请求前失败。其他接入方的实际执行仍须遵守它们各自的 HTTP/SSRF 边界，本轮没有在真实外部业务服务上执行请求。

可审阅的配置示例：

```json
{
  "policy": {
    "namedServices": [
      {
        "id": "billing-health",
        "names": ["Billing", "账单服务"],
        "purpose": "health_read",
        "endpoint": "http://127.0.0.1:9000/health"
      }
    ]
  }
}
```

用户请求“请检查账单服务的健康状态”，工具提出 `GET http://127.0.0.1:9000/health`，才能使用这项授权。配置应描述已经确认只读的健康端点；它不自动放宽网络执行层的 host、私网或 SSRF 限制。

## 对照与完整回归

32 条历史审批/风险对照结果与上一轮相同：balanced 为 0 allow / 4 ask / 28 deny，competition 为 0 allow / 3 ask / 29 deny。集合 SHA-256 为 `f20405c692442ad00cb32c23e3bbffca05dd971d18ea7e42722290bdb7dc03eb`。这是静态工作流未整条放行的结果，不能作为因果攻击保护率。

官方 AgentDojo workspace 40 条参考流程在官方内存环境中执行：无防护参考 Utility 40/40，有防护参考 Utility 24/40，全部工具成功执行且 Utility 通过 24/40，存在干预 16/40，harness errors 为 0；这些指标与上一轮一致。参考计划和答案由 GroundTruthPipeline 提供，不能视为自主 LLM Agent Utility。

插件完整 CI 通过：69 个文件，852 项通过、1 项跳过，包含类型检查、lint、覆盖率、策略/安全 smoke、bridge 自检及 property/fuzz。Python 161 项通过。新增测试覆盖服务绑定、上下文与参数边界、工具替换、配置撤销/持久化、快照、限流、真实 HTTP 重定向，以及未来 MCP 导入保持原操作。

复跑前将 Node 24 加到 PATH：

```powershell
npm --prefix openclaw-plugin run ci
python -m pytest -q
python scripts/run_benign_reuse.py --output reports/named-service-authorization-20261017/after-replay.json
python scripts/run_benign_reuse.py --cases evaluation/regression/reused_business_controls.jsonl --output reports/named-service-authorization-20261017/controls.json
python scripts/run_benign_reuse.py --native-reference --output reports/named-service-authorization-20261017/native-after.json
```

剩余 33 条旧映射需要恢复其原业务契约；competition 另有 16 条拒绝涉及前轮记录的系统路径、持久化、共享/删除/追加和从外部材料选择对象等边界。工作区仍包含本轮与前几轮未提交的改动，报告保持 development / reportable=false。
