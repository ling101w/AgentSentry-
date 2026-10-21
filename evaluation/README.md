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

`regression/authorization_write_cases.jsonl` adds 16 explicit file-operation requests and 14 paired authorization boundaries for development. `openclaw-plugin/scripts/authorization-regression.mjs` checks these alongside the six seeds with Judge disabled and no tool execution. It reports deny and ask separately and runs in `test:policy`; its curated counts are not a production FPR or a task-completion estimate. Before/after evidence and the separate opt-in provider probe are documented in `reports/authorization-optimization-20261017/`.

`regression/authorization_quoted_targets.jsonl` adds eight ordinary quoted-address/URL/query requests and ten matching boundaries. The current combined development check has 30 benign and 24 boundary cases; the profiles reuse the same inputs. See `reports/semantic-latency-optimization-20261017/` for the expanded before/after comparison and provider/cache latency probes.

Metrics distinguish trials from unique cases. Repeated-seed Wilson intervals use conservative case-level outcomes, and harness errors are excluded from security-rate denominators and reported explicitly.

## Reused local business workflows

`benign/reused_business_workflows.jsonl` freezes 210 source-labelled allow workflows and three ask controls from existing local data. This workflow format has an evaluator-owned `label` and `provenance`, with a `steps` array of exact five-field detector envelopes. It is a development set, not the six-row seed file, a sealed holdout, or an independently reviewed production-FPR sample.

`benign/reuse_inventory.json` pins the source hashes and transformations. `scripts/build_benign_reuse.py` imports the local sources and deduplicates exact input sequences; contradictory expectations are excluded for adjudication. `scripts/run_benign_reuse.py` replays without tools or models and reports ask/deny separately, with Utility unset. `--native-reference` executes 40 official workspace reference paths inside AgentDojo memory; its oracle-supplied answers prevent treating that score as autonomous agent Utility. Full results and limitations are in `reports/benign-reuse-20261017/`.

The second pass in `reports/benign-reduction-20261017/` retains the same case/input hashes. It covers lexical read queries, bounded output directories, literal read commands, compound calendar operands, and provider file creation. Competition improves from 141/210 to 151/210 automatic allows, with ask/deny reported separately; complete official reference execution improves from 19/40 to 24/40. The same 43 historical API mappings still lack a trusted endpoint binding. These remain development measurements with Judge disabled.

The next pass in `reports/named-service-authorization-20261017/` adds trusted named health-service bindings. On the same frozen inputs, 10 mapped health GETs recover: competition reaches 161 allow / 0 ask / 49 deny. Another 33 historical API mappings carry business arguments incompatible with a health endpoint and remain blocked. `mapping-audit.json` records the overwritten operations; these results do not measure original MCP task completion. Future imports preserve unsupported MCP names/arguments instead of substituting a health call. The 32 controls and 24/40 complete official reference workflows are unchanged.

## Native AgentDojo

The native path is programmatic rather than an AgentDojo CLI defense. `AgentSentryGuardedFunctionsRuntime` intercepts the official `FunctionsRuntime.run_function` boundary, including nested calls. `allow` reaches the real AgentDojo tool; `ask` and `deny` return a tool error without executing it. Allowed results are sent back to the OpenClaw plugin policy for taint and provenance updates.

Frozen public inputs:

- `agentdojo_selection.json`: 20 benign tasks, 20 explicit user/injection pairs, and seeds 7/17/29. Pairs are not expanded into a 20 x 20 cross product.
- `detector_event_schema.json`: exact detector process input and opaque routing contract.
- `agentdojo_native_result.schema.json`: public aggregate protocol v1.
- `agentdojo_results.json`: currently `not_run`; it contains no fabricated zero metrics.

Private `detector-events`, labels, and joined trials are created under ignored `runtime/agentdojo/<run-id>/` only after all detector subprocesses have exited. The public artifact commits to each private file with SHA-256. Raw benchmark IDs never become detector session IDs; HMAC-derived `trial_<hex>` IDs are used instead.

Run the dependency, plan, and real-environment contracts without credentials:

```powershell
python -m pip install -e ".[dev,native-agentdojo]"
npm --prefix openclaw-plugin run build
python scripts/run_agentdojo_native.py --doctor
python scripts/run_agentdojo_native.py --plan
python scripts/run_agentdojo_native.py --contract
```

The model-backed run refuses dirty worktrees by default and requires both provider credentials and the competition-profile semantic Judge key. `--allow-dirty` and `--allow-no-judge` are development-only and cannot produce a reportable result. AgentDojo's returned `security` boolean means the injection goal succeeded; native ASR uses that value directly, and Protection Rate is its complement. Harness errors are excluded from ASR and Utility denominators and reported separately.
