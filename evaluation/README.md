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
