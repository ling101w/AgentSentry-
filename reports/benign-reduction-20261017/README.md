# 正常请求干预率的第二轮修复（2026-10-17）

本轮继续使用上一轮冻结的 210 条 source-labelled allow 工作流和 3 条 ask 对照，另跑 32 条历史审批/风险对照。没有调整样本、标签、风险阈值或 Judge 开关。两种配置都关闭 Judge，全部测量均为零模型调用。

## 固定集合结果

| 配置 | 阶段 | allow | ask | deny | 拒绝比例 | 审批或拒绝比例 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| balanced | 本轮前 | 143 | 13 | 54 | 25.7% | 31.9% |
| balanced | 本轮后 | 151 | 6 | 53 | 25.2% | 28.1% |
| competition | 本轮前 | 141 | 7 | 62 | 29.5% | 32.9% |
| competition | 本轮后 | 151 | 0 | 59 | 28.1% | 28.1% |

本轮分别恢复 8 条和 10 条完整回放；两个配置共享同一组输入，不能合并为独立样本。此前 allow 的工作流没有新增干预。3 条原标签 ask 的对照仍全部 deny，单独保留，不计入 210 条分母。

主集合 SHA-256 为 `1e98ff2a6cf1a1adcd003bb0fa9bf167ebb282e2b4c9c16c445525f5e91b6b16`。`before-replay.json` 保留上一轮末状态，`after-replay.json` 是本轮最终状态，`comparison.json` 校验逐条 input hash 并列出恢复项。两次最终回放和原生运行使用同一检测器源码指纹 `bd4d6eea9434234131d7d3b0b41589e8799921850c6d874845c82393e2ea5547`，单次运行前后指纹一致。

这些是已经看过并用于开发的来源标签样本，包含模板变体和历史映射；比例不代表生产 FPR 或独立 holdout 表现。纯回放在首次 ask/deny 处停止，不执行业务工具，也不推断任务 Utility。

## 修复内容及约束

1. **文档主题词与敏感值区分。** 文档名里的 password/token 等词不再重复增加 45 分风险。实际凭据值、私钥、`.env` 和管理员明确配置的敏感资产仍受保护；规范化后的真实路径继续检查工作区边界。
2. **查询词与凭据区分。** `queryFields` 是注册工具契约里的签名元数据。只有声明为自身数据、只读、无外发、无敏感输入的工具，其声明字段中的文本查询才采用这项词汇修正。实际密钥、密码赋值、未声明字段和其他账户参数仍保留原检查，返回结果的标签和后续 sink 检查也继续生效。
3. **目录级输出授权。** “把日志写入 notes 目录下的文本文件”允许选择该目录内的输出名称。目录必须由用户明确指定，不能从根目录、home、遍历路径或通配符推断授权；真实路径检查继续阻断 junction/symlink 越界，敏感、记忆、Skill 等路径规则继续检查。写入次数和 UTF-8 字节预算写回会话，首次写入也检查完整内容大小。
4. **明确命令授权。** “运行 date 查看时间”绑定到用户点名的命令。不会授权 date 的修改时间参数、其他命令或追加执行；否定、讨论、条件和引用不形成授权。
5. **日历创建参数定位。** 复合任务里的前一项“总结日程描述”不再被误当作后一项新建日程的 description。创建指令自己的标题、描述、时长继续精确绑定，收件人和时间范围仍校验。
6. **云盘新建文件独立建模。** manifest mapping 1.3.0 将 `create_file` 映射到 `remote_file_create`，使用独立 `remote_file` 能力。要求注册契约明确为当前用户云盘、具体文件名、固定新建操作，并只接受 filename/content。一次创建不会授权本机路径、其他文件名、追加、删除、共享、其他账户或自定义目的地址。保持持久化/外部写入风险与污点 sink，调用预算为一次。

恢复项为文档读取 1 条、目录输出 2 条、时间命令 1 条、邮箱查询 3 条、日历参数定位 1 条。competition 额外恢复 2 条云盘新建流程；balanced 的这两条此前已经放行。

## 风险对照与官方内存环境

32 条历史审批/风险对照的集合 SHA-256 为 `f20405c692442ad00cb32c23e3bbffca05dd971d18ea7e42722290bdb7dc03eb`，本轮前后结果一致：

| 配置 | allow | ask | deny |
| --- | ---: | ---: | ---: |
| balanced | 0 | 4 | 28 |
| competition | 0 | 3 | 29 |

这是静态工作流未整条放行的数量，不能据此声称实测攻击保护率或无漏报。新增定向测试另覆盖凭据值、越界路径、目录 junction、参数/参与者替换、云盘操作混用、撤销及预算。

AgentDojo 0.1.35 workspace v1.2.2 的 40 条官方参考流程只在官方内存环境执行：

| 指标 | 本轮前 | 本轮后 |
| --- | ---: | ---: |
| 无防护参考 Utility | 40/40 | 40/40 |
| 有防护参考 Utility | 22/40 | 24/40 |
| 全部参考工具执行且 Utility 通过 | 19/40 | 24/40 |
| 存在策略干预 | 21/40 | 16/40 |
| harness errors | 0 | 0 |

新完整执行的是 user_task_22、23、31、36、39。纯回放里恢复的 user_task_4，在官方参考执行中仍因参与者与用户明确地址不匹配等检查被干预，未把回放 allow 冒称任务完成。

参考计划和最终答案来自 GroundTruthPipeline；这些结果是契约兼容性，并非自主 LLM Agent 的 Utility。只读任务即使工具失败也可能凭给定答案通过，因此始终单列全部工具成功执行的完成数。被拒绝的工具从未执行。

## 剩余拒绝与下一步

两个配置都有 43 条旧 API 映射缺少可信目标。用户文本只提“本地 API 健康检查”，通用 call_api 参数却自行提供具体地址。需要从原 MCP 契约或管理员配置恢复命名服务与 endpoint 的绑定，再验证用户请求确实授权相应操作。不能只根据工具参数中的 URL 授权，也不能把这些条目删掉重算比例。

competition 另外 16 条仍涉及系统路径、未指定目标的持久化操作、云盘删除/追加/共享及从外部材料选择对象或推导动作。应继续建立可验证的对象 ID、来源和操作绑定。它们当前仍在报告中；将其统称为误报并全部放行缺乏依据。

## 验证和复跑

完整插件 CI 通过：68 个测试文件，801 项通过、1 项跳过，包含类型检查、lint、覆盖率、策略/安全 smoke、bridge 自检及 property/fuzz。Python 155 项通过，其中新增 5 条真实官方参考执行回归。日志保存在本目录的 `ci.log`、`pytest.log`（Git 忽略日志文件）。

先将 Node 24 加到 PATH，再执行：

```powershell
npm --prefix openclaw-plugin run ci
python -m pytest -q
python scripts/run_benign_reuse.py --output reports/benign-reduction-20261017/after-replay.json
python scripts/run_benign_reuse.py --cases evaluation/regression/reused_business_controls.jsonl --output reports/benign-reduction-20261017/controls.json
python scripts/run_benign_reuse.py --native-reference --output reports/benign-reduction-20261017/native-after.json
```

工作区仍包含本轮与前几轮尚未提交的改动；报告标记 development / reportable=false。
