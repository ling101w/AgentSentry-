# AgentDojo Benchmark 迁移部署指南

本包是自包含的 AgentDojo native benchmark 执行单元（AgentSentry 主工程 + full_v1 selection）。

## 架构说明（先读这个）

这条 benchmark 链**不需要**运行 OpenClaw 本体，也**不需要**本机跑模型：

```
run_agentdojo_native.py (Python)
  ├── agentdojo==0.1.35        纯 Python 内存模拟环境（邮件/银行/旅行/Slack）
  ├── agentsentry (editable)   Python adapter
  └── JsonlNodeBridgeClient
        └── node openclaw-plugin/scripts/agentdojo-policy-bridge.mjs
              └── openclaw-plugin/dist/  已 build 的策略引擎（隔离 bridge 进程）

模型与 Semantic Judge：均通过 .env 的 baseurl 走 OpenAI 兼容 API（DeepSeek v4 Pro 云端）。
新机器只需要能访问该 baseurl。
```

OpenClaw 只是插件的**生产宿主形态**；benchmark 走 isolated policy bridge，node 子进程直接加载 dist/config.js，不依赖 OpenClaw 运行。

## 前置要求

| 组件 | 版本 | 用途 |
|---|---|---|
| Python | 3.13.x | agentdojo + adapter |
| Node.js | >= 22 | policy bridge |
| 网络 | — | 访问 .env 里 baseurl 的模型 API |

如需跑本地小模型臂（Qwen2.5-7B 等）：额外需要 GPU + vLLM，
起 OpenAI 兼容服务后把 .env 的 baseurl 指向 `http://127.0.0.1:8000/v1`。

## 安装步骤

```bash
# 1. 解压后在工程根目录（含 pyproject.toml）
python -m pip install agentdojo==0.1.35 pandas openai pydantic
python -m pip install -e . --no-build-isolation --no-deps

# 2. 重建 node 依赖（Windows 上 build 的 node_modules 含 win32 原生二进制，已从包中排除）
npm --prefix openclaw-plugin install
# dist/ 已随包携带，无需重新 build；若修改源码则:
# npm --prefix openclaw-plugin run build

# 3. 配置 .env（包内已带，key 为敏感信息，用完妥善处理）
#    baseurl=...  key=...  model=...
```

## 验证序列（务必按顺序，前两步不需要 API key）

```bash
export baseurl=...  key=...  model=...   # 或 Windows: 从 .env 读取

# a. 环境体检：检查 agentdojo 版本、bridge ping、manifest hash 冻结校验
python scripts/run_agentdojo_native.py \
  --selection evaluation/native/native_banking_full_v1_selection.json \
  --defense agentsentry --policy-profile competition --doctor

# b. 任务计划核对
python scripts/run_agentdojo_native.py --selection ... --plan

# c. 工具边界契约（真实跑一个只读任务，无 LLM、无密钥）
python scripts/run_agentdojo_native.py --selection ... --contract
```

## 正式跑（单 suite 示例）

```bash
export OPENAI_COMPATIBLE_BASE_URL=$baseurl
export OPENAI_COMPATIBLE_API_KEY=$key
export AGENTSENTRY_API_KEY=$key

python scripts/run_agentdojo_native.py \
  --selection evaluation/native/native_banking_full_v1_selection.json \
  --defense agentsentry \
  --policy-profile competition \
  --model openai-compatible \
  --model-id "$model" \
  --openai-compatible-system-role system \
  --node node \
  --provider-timeout-seconds 90 --provider-max-retries 2 \
  --judge-base-url "$baseurl" --judge-model "$model" --judge-timeout-ms 20000 \
  --output-root runtime/agentdojo-full-rerun/agentsentry/banking
```

四个 suite：workspace / banking / travel / slack（selection 文件在 `evaluation/native/`）。
换防御臂：`--defense no-defense`（去掉 judge 参数）。

## 注意事项

1. **版本冻结**：agentdojo==0.1.35、workspace v1.2.2、manifest hash 均被 bridge_doctor 硬校验，
   跨机器结果可比有机制保障。换版本前先想清楚。
2. **--allow-dirty**：工作区有未提交改动时结果标记 reportable=false。正式数字必须在
   干净 checkout 上跑。
3. **AgentWard 臂**：`scripts/agentward_agentdojo_bridge.mjs` + WSL shell 脚本是 Windows/WSL 专用，
   Linux 机器需把 .sh 里的路径改成原生。
4. **Node 路径**：原机器 bat 里 node 写死了 `C:\Users\ling1\.workbuddy\binaries\...`（WorkBuddy 托管运行时），
   新机器用系统 Node 即可，`--node node` 或写绝对路径。
5. Python 用本机任意 3.13 均可，依赖装在哪个解释器就用哪个。
