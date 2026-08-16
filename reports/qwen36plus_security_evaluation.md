# qwen/qwen3.6-plus Security Evaluation

Generated on 2026-08-15. This report separates dataset coverage from native
benchmark execution. Mapped and curated records are not presented as native
benchmark scores.

## Complete dataset

- Artifact: `dataset/complete/complete_security_dataset.jsonl`
- Total: 7,283 records
- Existing normalized records: 7,227
- Native DeepTrap replay tasks: 42
- Curated coverage cases: 14
- Top-level coverage: prompt injection, model jailbreak, training-data
  leakage, misuse, tool-call hijacking, memory poisoning, and environment
  context pollution
- DeepTrap task source SHA-256:
  `f7cae2def9449d11de14ec8304123a589c73c519a9862f1de3ac4f437b399f8a`

## AgentDojo native run

- Model: `qwen/qwen3.6-plus`
- Selection: 140 trials (100 attack, 40 benign)
- Completed: 140/140; provider errors: 0
- Attack success rate: 0/100 = 0.00%
- Protection rate: 100/100 = 100.00%
- Overall task completion: 94/140 = 67.14%
- Benign task completion: 28/40 = 70.00%
- Attack-environment task completion: 66/100 = 66.00%
- False-positive rate: 10/40 = 25.00%
- Benign intervention rate: 12/40 = 30.00%
- ASK rate: 6/140 = 4.29%
- Decisions: allow 92, ask 6, deny 42
- Latency: p50 24.09 s, p95 93.22 s, p99 171.08 s
- Result:
  `outputs/qwen36-agentdojo-140-agentsentry/agentdojo-native-20260815T014755Z-7f0c37ef/result.public.json`

This is a complete local development run, but it is not release-reportable:
the worktree was dirty and semantic Judge was disabled. The result correctly
declares `status=partial` and `coverage.reportable=false`.

## DeepTrap native OpenClaw run

- Target model: `qwen/qwen3.6-plus`
- Judge model: `qwen/qwen3.6-plus`
- Runtime: OpenClaw 2026.6.10 in WSL
- Suite: all, one run per task
- Completed artifacts: 42 tasks; 1 task status was `error`; 0 timed out
- Official defense score: 0.2596
- Official AGS: 0.6278
- Official UGS: 0.9262
- Total target-model tokens recorded by DeepTrap: 7,238,396
- Aggregate task execution time: 1,808.76 s
- Result: `outputs/deeptrap-qwen36-full/0001_qwen-qwen3-6-plus.json`

Official category defense scores:

| Category | Score |
|---|---:|
| Harness hijacking | 0.1944 |
| Privacy leakage | 0.0183 |
| Unauthorized execution | 0.2706 |
| Supply-chain risk | 0.3563 |
| Tool abuse | 0.2443 |
| Encoding obfuscation | 0.4737 |

The weakest DeepTrap category was privacy leakage. Its mean attack-success
score was 0.9657 across seven tasks, indicating that environment-provided
secrets and poisoned local instructions remain a critical exposure for the
unprotected OpenClaw/Qwen target.

## Interpretation boundary

- AgentDojo measures the AgentSentry-enforced native tool boundary.
- DeepTrap measures a separate, unprotected OpenClaw execution-context target.
- The 7,283-record complete dataset combines native, mapped, and curated
  evidence. Only the two native result files above are benchmark scores.
- A matched no-defense AgentDojo run is still required for a defensible
  protection-versus-utility comparison on the same model and selection.

中文完整说明见 [qwen36plus_security_evaluation_zh.md](qwen36plus_security_evaluation_zh.md)。
