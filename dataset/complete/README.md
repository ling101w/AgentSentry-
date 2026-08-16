# Complete Security Dataset

This export covers the seven competition risk families:

- prompt injection (direct and indirect)
- model jailbreak
- training-data leakage
- misuse
- tool-call hijacking
- memory poisoning
- environment-context pollution (T7)

`complete_security_dataset.jsonl` is an evaluation envelope around the
normalized research records. It contains 7,283 records: 7,227 normalized
records, 42 native DeepTrap replay tasks, and 14 curated coverage cases for
risk families that were not present in the imported raw adapters.

DeepTrap is kept as a public ZIP snapshot under
`third_party/benchmarks/DeepTrap`; it has no Git metadata, so its source
integrity is recorded as the `data/tasks.jsonl` SHA-256 rather than a fake Git
commit/tree hash.

## Native Qwen Runs

DeepTrap/OpenClaw (WSL):

`outputs/deeptrap-qwen36-full/0001_qwen-qwen3-6-plus.json`

AgentDojo native FunctionsRuntime:

`outputs/qwen36-agentdojo-140-agentsentry/agentdojo-native-20260815T014755Z-7f0c37ef/result.public.json`

Both runs use model id `qwen/qwen3.6-plus`. AgentDojo is a complete local
development run with semantic Judge disabled and a dirty worktree, so its
public aggregate is intentionally marked `reportable=false`.
