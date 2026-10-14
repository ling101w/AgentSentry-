# Security boundary maintenance validation

Date: 2026-10-13. Base: `79d46899b406b84d1362b8b66a71e5e1a1a03f85`. Branch: `fix/security-boundaries`.

## Separate commits

| Commit | Change | Focused validation |
| --- | --- | --- |
| `4e85c10` | Preserve unsatisfiable authorization constraints across merge/refinement/validation | 51 tests, including cross-turn conflicts and 250 generated monotonicity cases |
| `ca907bf` | Enforce deny as hard block and ask as approval in enforcing modes | 21 hook/enforcement/cache tests |
| `04b5bad` | Separate host, private CIDR and exact loopback-origin permissions | 25 HTTP/dashboard/config tests; metadata regressions |
| `fa28c3f` | Bound queued and in-flight audit data, expose health and failure counters | 23 writer/store/dashboard tests |
| `9f3441a` | Separate provenance index from preview and prioritize exact evidence | 55 provenance/policy tests |
| `f7ca939` | Shared semantic budget and asynchronous bounded shadow telemetry | 64 semantic/shadow/hook/performance tests |

## Combined results at f7ca939

- `npm test`: 60 Vitest files passed; 542 tests passed, one platform-dependent test skipped. Policy smoke, AgentDojo bridge self-test, security smoke and property/fuzz scripts passed.
- `npm run lint` and `npm run typecheck`: passed.
- Python evaluation checks: 86 tests passed in 12.94 seconds across label isolation, native result protocol, mapped step scoring, blind runner, native runner, AgentDojo adapter and official calendar contracts.
- `python scripts/run_agentdojo_native.py --doctor`: ready; AgentDojo 0.1.35, workspace v1.2.2, 24 tools. Selection SHA-256 `476178ca36f7c46579bbe5c69ef2a325f2750bfd311aa825e61197ce0708e16e`.
- `python scripts/run_agentdojo_native.py --contract`: official read-only calendar task passed the Utility evaluator. `search_calendar_events` was allowed and actually executed; labels were not visible to the detector. No model client was created and no credentials were read.

These counts overlap and must not be summed as independent experiments.

## Remaining evaluation

No live agent-model/Judge credentials are configured in this execution environment. The new branch has not completed a model-backed 120-trial run or independent blind holdout. Historical canonical/development results remain unchanged and must not be described as scores for these commits. Local timeout tests are scheduling contracts, not production P95/P99 or model-cost measurements.

For native re-evaluation, use a clean checkout of the final commit, build the plugin, run `--doctor`, `--contract` and `--plan`, then configure the model and Judge through environment variables. Run the existing frozen selection without `--allow-dirty` or `--allow-no-judge`, inspect execution evidence and Utility, and publish only after all trials complete without harness errors. The new source snapshots must match before and after the run; retry merges require the same source snapshot. Keep provider/model/profile/selection/seeds fixed for comparisons and report approvals/interventions separately from attack success.

An independent evaluator must supply a holdout after release freeze. Samples authored during these fixes remain developer regressions. Segmented audit logs, durable-before-execution enforcement, arbitrary translation provenance and a broad policy-module decomposition are not implemented by this maintenance series.

## Runner hardening validation

The final evaluator maintenance change adds detector/evaluator source snapshots, before/after commit and clean-worktree checks, and model/Judge runtime configuration fingerprints. A retry may remain a development result but cannot become reportable when its source run was dirty, changed revision, used another model configuration/selection, or has no verifiable snapshots. Credentials are excluded from source and runtime configuration material. Native runner/protocol/calendar tests: 36 passed, including actual calendar tool contracts.

The complete evaluation-protocol subset was rerun after runner hardening: 88 tests passed in 6.28 seconds.

Final HTTP follow-up: metadata hard-deny checks also normalize embedded IPv4 addresses in IPv4-mapped/compatible IPv6, NAT64 and 6to4 forms. The six HTTP tests, scoped ESLint and typecheck passed after this change.
