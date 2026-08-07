# Dataset Pipeline

这里保存 AgentSentry 的可复现数据登记信息和本地生成的数据集。数据分三层：

1. `third_party/benchmarks/` 是只读 raw 仓库，收集器不会改写样本。
2. `normalized/` 和 `cleaned/` 是研究格式，保留原始 user/attacker/tool response、raw record、版本与哈希。
3. `agentsentry/benchmark_cases.jsonl` 是严格的 `BenchmarkCase` 执行格式，专门供 `/api/lab/command` 使用。

大 JSONL 产物和第三方仓库默认被 Git 忽略；`raw_manifest.json`、`manifest/source_registry.jsonl`、Schema 和本文档可进入版本控制。

## 一次跑通

```powershell
python -m pip install -e ".[dev,dataset]"

python scripts/import_dataset_registry.py `
  "D:\download\玄鉴_数据集六类威胁简表_2026-08-06.xlsx"

python scripts/collect_benchmarks.py
python scripts/prepare_dataset.py --require-records
python scripts/run_dataset.py --dry-run
```

完整构建默认 fail closed：六个 adapter 必须全部 `loaded`、零解析错误且非空，raw manifest 的 status、commit、origin URL、tree SHA-256 必须与本地 clean checkout 一致，研究 Schema 不能有 invalid。单源调试或容许部分来源时必须写到独立目录，防止覆盖全量产物：

```powershell
python scripts/prepare_dataset.py `
  --source MSB `
  --holdout-source MSB `
  --dataset-root dataset-work/msb
```

只有确实需要保存不完整诊断产物时才加 `--allow-partial`；该参数同样禁止使用默认 `dataset/` 输出目录。`collect_benchmarks.py --source ...` 会合并原 manifest，不会删掉未选择来源的登记项。

默认执行文件保留全部 cleaned 样本。日常训练或较快回归可改用确定性的 80/20 子集：

```powershell
python scripts/run_dataset.py `
  --input dataset/agentsentry/benchmark_cases.balanced.jsonl `
  --dry-run
```

启动 AgentSentry Dashboard 后，先关闭外部语义裁判跑确定性基线。balanced 与 full 必须使用不同输出路径，避免互相覆盖：

```powershell
python scripts/run_dataset.py `
  --input dataset/agentsentry/benchmark_cases.balanced.jsonl `
  --base-url http://127.0.0.1:8765 `
  --semantic-judge off `
  --output dataset/agentsentry/run_results.balanced.json `
  --report dataset/agentsentry/run_report.balanced.md

python scripts/run_dataset.py `
  --input dataset/agentsentry/benchmark_cases.jsonl `
  --base-url http://127.0.0.1:8765 `
  --semantic-judge off `
  --output dataset/agentsentry/run_results.full.json `
  --report dataset/agentsentry/run_report.full.md
```

需要验证 LLM Judge 时再显式使用 `--semantic-judge default` 或 `on`，并记录模型、API 和成本配置。执行结果保存逐 case 决策、micro overall、macro by source、macro by primary threat，以及逐来源和逐威胁指标。没有 attack 或 benign 有效分母的分组显示 `N/A`，不会按 0% 纳入 macro。攻击 case 按 scenario 的危险 sink 逐动作计分；任一危险 sink 放行即为漏放。harness error 和无法定位 sink 的 case 不进入安全指标分母，并使命令返回非零。

已完成的旧结果可在不重新调用 Dashboard 的情况下补齐 metadata、macro 和保真声明；必须显式指定新输出路径：

```powershell
python scripts/run_dataset.py `
  --results-input dataset/agentsentry/run_results.full.json `
  --output dataset/agentsentry/run_results.full.enriched.json `
  --report dataset/agentsentry/run_report.full.enriched.md
```

## 执行保真边界

RedTeamCUA、MSB、AgentDojo、InjecAgent 的执行命令使用 `agentsentry.command-envelope.v1` JSON 信任信封，分别保存可信用户指令和不可信外部内容。内容不翻译、不摘要、不截断，结构化序列化可防止攻击文本伪造分隔符。AgentDojo 的 `GOAL` 明确标记为 `attack_goal_proxy`；InjecAgent 执行完整 `Tool Response`，`Attacker Instruction` 仅保留为研究标注。

Dashboard 当前仍按 `scenario` 生成固定的本地安全动作，并不原生复现每个上游环境。因此 `export_report.json` 将这些 case 标为 `synthetic_command_lab_proxy`，其结果只能解释为 AgentSentry command-lab 代理评测，不能当作上游 benchmark 的原生 ASR。需要 AgentDojo 原生环境成绩时使用 `scripts/run_agentdojo_native.py`。MSB 的 3,840 条攻击记录是 task、implementation、attack-type 的确定性实验配置组合，也不代表 3,840 次独立 MCP server 原生交互。

## 独立步骤

```powershell
python scripts/build_dataset.py --require-records
python scripts/validate_dataset.py --fail-on-invalid
python scripts/deduplicate_dataset.py
python scripts/split_dataset.py --holdout-source InjecAgent
```

`validate_dataset.py` 实际执行 Draft 2020-12 ResearchCase Schema，并把不完整样本标为 `quality.status=invalid`，不会静默删除。`deduplicate_dataset.py` 只删除来源、完整标签和执行投影都一致的精确副本，并在 `all.annotated.jsonl` 保留审计记录；近似重复跨标签分组但不删除。切分对 content hash、near-duplicate group 和攻击模板族取联合连通分量，防止任一约束泄漏到 train/test。

## 主要产物

| 路径 | 用途 |
|---|---|
| `raw_manifest.json` | 六个 raw 仓库的 URL、commit、license、SHA-256 与下载时间 |
| `manifest/source_registry.jsonl` | Excel 的 36 条数据源登记记录及原行号/文件哈希 |
| `schemas/*.schema.json` | 研究格式和严格 `BenchmarkCase` 的 JSON Schema |
| `normalized/all.jsonl` | 完整研究 Schema；不运行 AgentSentry |
| `cleaned/all.cleaned.jsonl` | 校验、精确去重后的训练/统计输入 |
| `cleaned/all.balanced.jsonl` | 不伪造 benign 的确定性 80/20 日常训练/回归子集 |
| `cleaned/all.annotated.jsonl` | 包含被移除精确副本的完整去重审计集 |
| `splits/{train,val,test}.jsonl` | 按模板/重复组隔离的常规切分 |
| `splits/cross_dataset_{train,test}.jsonl` | 来源级留出测试 |
| `agentsentry/benchmark_cases.jsonl` | 严格执行格式 |
| `agentsentry/benchmark_cases.balanced.jsonl` | 与平衡子集对应的较小执行集 |
| `quality_report.json` | valid/invalid、attack/benign、来源和 T1-T6 分布 |

## 数据不变量

- 不做 AI 润色、翻译替换、语法修正或攻击 prompt 改写。
- `raw` 保留上游对象，`content` 只统一换行和首尾空白；攻击正文不做 NFKC，保留精确 Unicode 码点。
- synthetic wrapper / trust envelope 只存在于 `agentsentry` 映射，并在 provenance 与 export report 中标记。
- ID 来自来源和原始定位的稳定哈希，不使用 shuffle 后序号。
- 没有 benign 的来源不会伪造 benign；适配器只从来源自身的正常 task/experience 生成基线。
- Registry 的 T1-T6 是默认先验，最终标签落在每条样本上，并允许 secondary labels。

当前可复现快照为 7,227 条 valid/cleaned、1,295 条 80/20 balanced；常规 train/val/test 为 907/194/194，InjecAgent cross-dataset holdout 为 5,119/2,108。为保证模板完整，同一 split 内的 attack/benign 比例不强求分别等于 80/20。
