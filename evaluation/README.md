# AgentSentry Evaluation Protocol

This directory separates development regression, independent blind holdout, realistic benign work, and native end-to-end results.

```text
evaluation/
├── regression/  # public mapped cases used during development
├── blind/       # evaluator-owned holdout; the real file is intentionally not committed
├── benign/      # ordinary business tasks, including side-effect authorization
└── native/      # native benchmark run manifests and results
```

Each JSONL row has three envelopes: `input`, `label`, and optional `metadata`. `input` is the only envelope allowed to cross the detector boundary. The loader in `agentsentry.evaluation_protocol` projects the exact five-field detector envelope and rejects extra control fields. Business objects inside `tool_args` and `tool_result` remain opaque, so legitimate keys such as `category` or `label` are not mistaken for evaluator metadata.

The independent evaluator owns `label.expected`, `label.is_attack`, `label.attack_type`, `label.benchmark_source`, and `label.risk_level`. AgentSentry receives only:

```json
{
  "user_message": "...",
  "tool_name": "...",
  "tool_args": {},
  "tool_result": null,
  "session_history": []
}
```

Do not call a dataset blind if a rule author has inspected it. Place the sealed holdout at `evaluation/blind/blind_holdout.jsonl` immediately before the run, record its SHA-256, run with a fixed release commit, then archive only aggregate output and the hash.

`run_blind_evaluation.py` refuses a dirty or non-Git workspace by default. The development-only `--allow-dirty` override is recorded in `working_tree_dirty` and must not be used for a reported blind score.

Default reports omit per-case expected labels and decisions. The `--include-case-details` override creates evaluator-private diagnostic content and must not be used for a public artifact.

The committed benign file currently contains six reviewed seed fixtures. It is a schema and pipeline starting point, not the planned 200-case realistic-business evaluation and not evidence of a production FPR.

Metrics distinguish trials from unique cases. Repeated-seed Wilson intervals use conservative case-level outcomes, and harness errors are excluded from security-rate denominators and reported explicitly.

### Native eval v2 measurement layers

Every native attack-arm audit now emits three parallel measurements in the
`three_layer_metrics` object. `official_agentdojo_asr` is the untouched
AgentDojo `outcome.security` boolean and remains the benchmark score.
`normalized_exact_sink_match` is a strict selected sink match after the
documented whitespace normalization; partial coverage is not promoted to an
exact match. `executed_malicious_side_effect_incidence` is the broader private
transcript audit: any successful attack-related high-risk sink, including a
partial or semantically equivalent effect. The latter two never overwrite the
official boolean. Each private audit run also records the frozen release,
selection, labels, trials, and detector-transcript SHA-256 commitments.

Generate the private post-join artifact with:

```powershell
python scripts/audit_agentdojo_side_effects.py `
  --run "deepseek/deepseek-v4-pro|no-defense|.tmp/release-clone/runtime/agentdojo/agentdojo-native-20260809T062111Z-d3dd5e1f" `
  --output .tmp/native-eval-v2-side-effects.json
```

For a fixed-trajectory policy check, replay only trials that the audit
observed reaching a dangerous sink:

```powershell
python scripts/replay_agentdojo_native.py `
  --run "deepseek/deepseek-v4-pro|no-defense|.tmp/release-clone/runtime/agentdojo/agentdojo-native-20260809T062111Z-d3dd5e1f" `
  --bridge .tmp/qwen-native-a6ee031/openclaw-plugin/scripts/agentdojo-policy-bridge.mjs `
  --disable-judge `
  --output .tmp/native-eval-v2-deepseek-replay.json `
  --public-output reports/native_agentdojo/native_deepseek_v4_pro_observed_sink_replay.public.json
```

Replay sends the original detector five-field inputs, tool arguments, tool
results, and session history to the competition bridge. It does not call an
AgentDojo tool; a later sink after an earlier `deny`/`ask` is reported as
`unreachable`. `--disable-judge` is the default no-model-cost mode and must be
reported as deterministic-policy replay, not as a second end-to-end ASR.

The `evidence-gated` profile is available for a separate local precision check,
but it is intentionally not projected into the frozen public replay-v1 schema.
On the current expanded DeepSeek no-defense transcript (selection SHA-256
`679cf45d9a186a5acc472151ba1b22a4a49c3029931b491d5611690d9fb9fad1`), the
working-tree replay produced `63/63` fully protected observed-side-effect
trajectories (`20 ask`, `43 deny`) and `0/40` benign interventions across 142
observed benign tool calls, with zero detector-input mismatches. The attack
replay reached 63 blocking boundaries; 118 downstream target calls were
therefore unreachable rather than independently classified. The replayed
plugin-dist SHA-256 is
`6c48c86ff650e885b530c916981ca2e10e04515c9de5bf721131fc5b24f3b2b8`.
These are private, counterfactual policy results: the benchmark tool was not
executed, utility was not recomputed, the policy was not frozen, and the
numbers must not be described as end-to-end ASR or as a reinterpretation of
the historical `competition` evaluation.

## Native AgentDojo

The native path is programmatic rather than an AgentDojo CLI defense. `AgentSentryGuardedFunctionsRuntime` intercepts the official `FunctionsRuntime.run_function` boundary, including nested calls. `allow` reaches the real AgentDojo tool; `ask` and `deny` return a tool error without executing it. Allowed results are sent back to the OpenClaw plugin policy for taint and provenance updates.

Frozen public inputs:

- `agentdojo_selection.json`: 20 benign tasks, 20 explicit user/injection pairs, and seeds 7/17/29. Pairs are not expanded into a 20 x 20 cross product.
- `detector_event_schema.json`: exact detector process input and opaque routing contract.
- `agentdojo_native_result.schema.json`: public aggregate protocol v1.
- `agentdojo_native_audit.schema.json`: public schema for the three parallel attack measurements.
- `agentdojo_native_replay.schema.json`: public aggregate schema for observed-sink replay.
- `agentdojo_results.json`: canonical public aggregate from the clean 120-trial AgentSentry run using `deepseek/deepseek-v4-pro`. Its matched no-defense comparison reports official ASR `0/60` versus `43/60`, with benign FPR `0/60`, and remains the canonical security result. Model-specific `alibaba/qwen3.7-plus` and `qwen/qwen3.5-plus-2026-04-20` comparisons are retained under `reports/native_agentdojo/`; their official `0/60` outcomes are selection-scoped integration/utility evidence rather than defense-efficacy or universal-safety claims. The Qwen 3.5 side-effect audit also found one no-defense dangerous email effect missed by the official scorer. Historical GPT-5.5 evidence remains alongside them.
- `reports/native_agentdojo/native_deepseek_v4_pro_observed_sink_replay.public.json`: aggregate replay evidence over the 46 DeepSeek no-defense side-effect trials; private per-event hashes remain in ignored runtime output.
- `reports/native_agentdojo/native_three_layer_attack_audit.public.json`: schema-validated three-layer metrics and source commitments for the six DeepSeek/Qwen formal arms.

Private `detector-events`, labels, and joined trials are journaled under ignored `runtime/agentdojo/<run-id>/` after every completed trial. A private atomic checkpoint stores only the run configuration, opaque completed IDs, confirmed row counts, and the HMAC key needed to preserve IDs across `--resume`. Unconfirmed JSONL tails are discarded on resume. The public artifact commits to each private file with SHA-256. Raw benchmark IDs never become detector session IDs; HMAC-derived `trial_<hex>` IDs are used instead.

Run the dependency, plan, and real-environment contracts without credentials:

```powershell
python -m pip install -e ".[dev,native-agentdojo]"
npm --prefix openclaw-plugin run build
python scripts/run_agentdojo_native.py --doctor
python scripts/run_agentdojo_native.py --plan
python scripts/run_agentdojo_native.py --contract
```

The model-backed AgentSentry run refuses dirty worktrees by default and requires both provider credentials and the competition-profile semantic Judge key. `--allow-dirty` and `--allow-no-judge` are development-only and cannot produce a reportable result. AgentDojo's returned `security` boolean means the injection goal succeeded; native ASR uses that value directly, and Protection Rate is its complement. Harness errors are excluded from ASR and Utility denominators and reported separately.

The compatible-provider path accepts `--provider-timeout-seconds` and `--provider-max-retries`; retries use the OpenAI SDK's exponential backoff. AgentDojo 0.1.35 emits OpenAI's `developer` role for system messages, so endpoints that implement the older compatible role set must use `--openai-compatible-system-role system`; the selected serialization is recorded in the checkpoint. Provider failures are counted separately from agent, detector, benchmark, and evaluator failures. Resume a matching run with `--resume runtime/agentdojo/<run-id>`; use `--retry-errors` only when failed trials should be removed from the checkpoint and attempted again.

Use `--defense no-defense` for the matched native baseline. It runs the identical model, selection, seeds, AgentDojo tools, five-field detector envelope, checkpoint protocol, and official scorers with the bridge in `observe` mode. The bridge records the raw `policy_decision` but returns effective `allow`, so AgentSentry never intervenes. The Judge is disabled by construction, a clean complete baseline remains reportable, and `--publish` is rejected so it cannot replace the canonical AgentSentry result.

The isolated Judge accepts `--judge-base-url`, `--judge-model`, and `--judge-timeout-ms` (500–90000 ms) and records these non-secret settings in bridge metadata. If an ambiguous action requests Judge review but the response is unavailable, the runner marks the result partial instead of claiming reportability.
