# Realism Gap: Synthetic vs Real OpenClaw Sessions
_Synthetic: 1000 graphs from `data/synthetic_v2`_
_Real: 30 graphs from `data/openclaw/wsl_sessions_scripted.jsonl`_

## Graph Size
| metric | synthetic | real |
|---|---|---|
| nodes/mean | 8.57 | 75.73 |
| nodes/median | 8.5 | 9.0 |
| nodes/min | 3 | 3 |
| nodes/max | 14 | 546 |
| edges/mean | 10.27 | 108.5 |
| edges/median | 10.0 | 10.5 |
| edges/min | 2 | 2 |
| edges/max | 18 | 802 |

## Vocabulary
- synthetic tools: 26, tasks: 7
- real tools: 14, tasks: 5
- overlap: 0 tools (0.0%), 4 tasks (50.0%)

## Trust Distribution (synthetic)
- high (>0.7): 1553
- medium (0.4-0.7): 1229
- low (<0.4): 5792
- total: 8574

## Trust Distribution (real)
- high (>0.7): 0
- medium (0.4-0.7): 1047
- low (<0.4): 1225
- total: 2272

## Node Types (synthetic vs real)
| type | synthetic | real |
|---|---|---|
| entity | 297 | 119 |
| intent | 1000 | 30 |
| observation | 3279 | 1052 |
| tool_call | 3998 | 1071 |

## Edge Types (synthetic vs real)
| type | synthetic | real |
|---|---|---|
| call_sequence | 2998 | 1041 |
| control_influence | 200 | 0 |
| data_dependency | 2498 | 1013 |
| data_derivation | 3576 | 1171 |
| intent_drives | 1000 | 30 |

## Dangerous Tools & Control Influence
- Dangerous tool calls (synthetic): 293
- Dangerous tool calls (real): 0
- Control_influence edges (synthetic): 200
- Control_influence edges (real): 0

## Implications
- Synthetic graph size is ~7-12 nodes; real OpenClaw sessions scale to 100s of nodes (mean 8.6 synthetic vs larger for real), so synthetic cannot model the long-horizon tool chains in real sessions.
- Synthetic trust distribution is uniform across (high/medium/low); real sessions are dominated by trust=medium (system observations) — the model cannot learn low-trust signals from current synthetic mix.
- Tool vocab overlap is small (<10%); with the OOV bucket fix the model now has a non-zero signal for unseen tools, but the structural features (control_influence edges, call_sequence chains) must carry the load. Synthetic emits control_influence almost exclusively on attack graphs (0.0 trust edges), which makes synthetic distribution trivially separable — model accuracy of 1.000 is misleading.
- Real graphs have ~0 control_influence edges in the current parser output (the prior fix added a fallback heuristic when source=observation is missing, but real OpenClaw logs still lack the explicit control_influence edge type). Need a stronger classifier for 'observation drove dangerous tool' that doesn't depend on edge-type labels.
