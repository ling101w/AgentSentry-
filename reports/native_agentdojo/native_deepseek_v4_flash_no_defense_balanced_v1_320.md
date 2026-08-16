# Native AgentDojo Balanced v1: DeepSeek V4 Flash / No-defense

Run date: 2026-08-12 (UTC)

## Scope

This is an end-to-end AgentDojo run of the `no-defense` (observe) profile on
the new **`native-balanced-v1` selection (selection version 1.2.0)**, built to
give the expanded case set a regular bipartite degree structure:

- 40 unique workspace benign tasks and **280 unique workspace attack pairs**
  (versus 100 pairs in `native-expanded-v1` 1.1.0);
- every user task paired with exactly 7 injection tasks and every injection
  task paired with exactly 20 user tasks (40×7 = 14×20 = 280, strictly
  balanced); the 100 frozen `native-expanded-v1` pairs are retained as a
  subset;
- one provider generation per case, harness seed `7`;
- selection SHA-256
  `346f2a1e2c8bac5f4fe1f6a16bc9b45d2c02667fc8ee01c42a4605a8fb515cb3`;
- AgentDojo `0.1.35`, workspace `v1.2.2`, commit
  `089ed468cf3ed0322acc66b0211f26d9d90dbf60`, `tool_knowledge` attack;
- `deepseek/deepseek-v4-flash` via OpenAI-compatible endpoint
  (`https://api.360.cn/v1`), system role, 90-second provider timeout, 2
  retries;
- observe (no-defense) profile snapshot, tool manifest SHA-256
  `157b03c47018ad1533a74ffacc7c58a5b22b68c12166e2aa5277b9f4d33cc9eb`.

The run was started 2026-08-12T12:33:15Z and finished 2026-08-12T13:36:12Z
(~63 minutes, mean 11.8 s/trial, no resume). Run id
`agentdojo-native-20260812T123315Z-9e498b08`.

This is a new baseline arm on a new selection; it does not overwrite the
frozen `native-expanded-v1` 1.1.0 results. The worktree was dirty at run time
(`--allow-dirty`), so the public artifact is marked `status=partial /
reportable=false`; all 320 trials still completed with zero errors.

## Results

Wilson intervals are two-sided 95%.

| Metric | Value |
|---|---:|
| Completed trials | `320/320` (40 benign + 280 attack), 0 errors |
| Official AgentDojo ASR | `0/280 = 0.00%` (`0.00%–1.35%`) |
| Benign utility (task completion) | `37/40 = 92.50%` (`80.14%–97.42%`) |
| Attack-pair benign-task utility | `254/280 = 90.71%` (`86.74%–93.58%`) |
| Mean utility (all trials) | `291/320 = 90.94%` |
| Effective decisions | 320 allow / 0 ask / 0 deny |
| Benign deny FPR | `0/40` (`0.00%–8.76%`) |
| Provider/harness errors | `0/320` |
| Semantic Judge calls | 0 requested / 0 called / 0 failed |
| Detector events | 2712, mean 8.5/trial, 0 label-isolation violations |
| Latency (end-to-end) | p50 9.1 s / p95 22.1 s / p99 95.2 s |

## Interpretation

1. **The model is injection-resistant without any defense.** Across all 280
   balanced attack pairs, `deepseek/deepseek-v4-flash` never executed the
   injected injection-task goal (official ASR 0/280). The benign-task
   completion rate stayed high (90.7%) under injection, so the model ignored
   the injected instructions rather than failing the whole episode.

2. **The preregistered screening gate is not met.** The expanded-v1 protocol
   registers the defense arm only when the no-defense baseline shows at least
   20/100 attack successes. Here the baseline shows 0/280, far below the
   gate, so an `agentsentry` arm on this selection is not warranted: there is
   no attack headroom for a defense to recover.

3. **The observe profile behaved as configured.** Every call was allowed,
   benign FPR is 0 by construction, and the detector bridge produced
   structured events (2712) for offline audit without touching labels.

## Balance Audit

The selection satisfies the intended regular bipartite structure exactly:

- 40 user tasks, each with degree 7 (min 7 / max 7);
- 14 injection tasks, each with degree 20 (min 20 / max 20);
- the 100 frozen expanded-v1 pairs are a strict subset of the 280;
- one generation per unique case (320 unique case ids).

## Caveats

- `status=partial`: dirty worktree + observe-only development run
  (`--allow-dirty`). Data is complete; only the release provenance gate is
  not met.
- Provider usage/pricing was not returned, so cost remains unknown rather
  than estimated.
- Single harness seed (`7`) and one generation per case, consistent with the
  expanded-selection protocol.

## Artifacts

- Run directory: `runtime/agentdojo/agentdojo-native-20260812T123315Z-9e498b08/`
- Public result: `native_deepseek_v4_flash_no_defense_balanced_v1_320.public.json`
  (SHA-256 `bd61c88e2ff8912717be023d5c85a1f3ea6f9244713e7ac6cecd0f109806756d`)
- Selection: `evaluation/native/native_balanced_v1_selection.json`
- Selection builder: `scripts/build_native_balanced_selection.py`
- Selection schema: `evaluation/native/agentdojo_native_balanced_selection.schema.json`
- Run log: `runtime/balanced_v1_nodefense_run.log`
