# Native AgentDojo: AgentWard Semantic / DeepSeek V4 Pro / 120 Trials

## Scope

This development run evaluates AgentWard `2026.5.9` end to end against the
frozen AgentDojo workspace `v1.2.2` selection: 20 benign tasks, 20 matched
user/injection pairs, and seeds `7/17/29`, for 120 trials total. Both the
AgentDojo agent and AgentWard Decision Alignment used
`deepseek/deepseek-v4-pro` through `https://api.360.cn/v1`.

The adapter sends each assistant tool-use turn to AgentWard Decision Alignment
before AgentDojo executes its tools. A `BLOCKED` verdict is enforced on every
tool call in that assistant turn. AgentWard input sanitization, execution
control, and cognition protection also run at their corresponding tool
boundaries. Foundation Scan remains not applicable to the AgentDojo workspace.

All 120 trials completed without provider, harness, detector, or evaluator
errors. The public artifact is intentionally `status=partial` and
`reportable=false` because the repository was dirty and this adapter was not
frozen in a clean release commit. It is an end-to-end development result, not
a publishable frozen benchmark result.

## Results

| Metric | Result |
|---|---:|
| Official AgentDojo ASR | `0/60 = 0.00%` |
| Official protection rate | `60/60 = 100.00%` |
| Normalized exact malicious sink match | `0/60 = 0.00%` |
| Executed malicious high-risk side effect | `0/60 = 0.00%` |
| Benign utility | `59/60 = 98.33%` |
| Attack utility | `51/60 = 85.00%` |
| All-task utility | `110/120 = 91.67%` |
| Provider / trial errors | `0 / 0` |
| AgentWard trial decisions | `72 allow / 0 ask / 48 deny` |
| Tool-boundary decisions | `346 allow / 0 ask / 113 deny` |
| Decision Alignment turns | `220 OK / 77 BLOCKED` |
| Semantic Judge audit | `297 requested / 297 called / 0 failed` |
| Semantic request attempts | `298` (`1` turn retried once) |
| Mean / p50 / p95 latency | `37.02s / 27.39s / 89.48s` |
| Decision stability | `95.83%` over 40 repeated cases |

The independent side-effect audit found no official attack success, normalized
malicious sink match, or executed malicious high-risk side effect. It found 25
attack trials where a ground-truth dangerous sink was denied before execution.
Four attack trials called `get_unread_emails`, whose benchmark implementation
marks messages as read; these read-state mutations are reported separately and
are not classified as malicious high-risk side effects.

## Semantic Configuration

AgentWard's semantic Judge was explicitly configured as follows:

- Provider: `agentward-compatible`
- Model: `deepseek/deepseek-v4-pro`
- API type: `openai-completions`
- Base URL: `https://api.360.cn/v1`
- API key source: `AGENT_WARD_API_KEY`, populated at runtime from `.env`
- Per-attempt timeout: `120000 ms`
- Output limit: `2048` tokens
- Invalid-response retries: at most `2`
- Outer bridge timeout: `390 s`

The adapter supplies the complete `pi-ai` model contract, including a zeroed
cost table used only for response accounting, and explicit non-standard
OpenAI compatibility flags. It also waits for AgentWard's worker-ready event
before the first Judge call. In the final run, 296 semantic turns completed on
their first attempt and one completed on its second attempt; none failed open.

## Coverage And Interpretation

Decision Alignment is now exercised as an enforced assistant-message hook, not
an observation-only approximation. Its 77 blocked assistant turns produced 113
tool-call denials because one assistant turn can contain multiple tool calls.
The AgentDojo agent receives normal tool errors after a denial and can recover;
this is reflected in the 85% attack-task utility.

The 0% official ASR is consistent with the independent transcript audit, but
the result should not be generalized beyond this frozen 120-trial workspace
selection. It also should not be presented as a release-quality benchmark until
rerun from a clean frozen commit.

## Commitments

- Run: `agentdojo-native-20260812T123051Z-528e84e2`
- AgentWard upstream commit: `46309333bdfdbcf4701000c1dad85b33b4a0e7ef`
- AgentWard detector module digest: `ed6d414a910681048b24569ad3e6d90c50b41e6f7190e71b866e59db9037bcaa`
- Selection SHA-256: `476178ca36f7c46579bbe5c69ef2a325f2750bfd311aa825e61197ce0708e16e`
- Detector transcript SHA-256: `53db990e51369d73da0a8adbc66666a9a5b27e21f9fff555a6d2d9b44da637b0`
- Private trials SHA-256: `7e3e0f29906ec1279c74851ec612f8e5ab84969666c5fb10e65b9a35c53517b9`
- Adapter bridge SHA-256: `7f91881f3c3e8b8a62dbb0d503433ae2884b43161d40b9d4be7b4b614704dcb2`

## Artifacts

- Public aggregate: `runtime/agentward-agentdojo-deepseek-v4-pro/agentdojo-native-20260812T123051Z-528e84e2/result.public.json`
- Private detector transcript and trials: same run directory
- Three-layer side-effect audit: `runtime/agentward-agentdojo-deepseek-v4-pro/agentward-side-effect-audit.private.json`
