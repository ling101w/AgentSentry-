# ATBench registered-tool evaluator patch

This package upgrades the ATBench static replay from a single heuristic
onboarding path to two explicit evaluation tracks.

## What changed

### 1. Registered-tool track is now the default

`run_static_trajectory_eval.py` now defaults to:

```text
--tool-onboarding registered
```

Before any tool-call decision, the evaluator builds or loads a frozen simulated
security registry from the observed tool catalog and sends the exact per-case
subset to the static policy bridge.

The registry uses only:

- tool name;
- tool description;
- JSON parameter schema;
- catalog source metadata.

It never uses trajectory labels, benchmark reasons, tool results, assistant
outputs, or whether a case was previously classified correctly.

The bridge must return the same registry SHA-256 and confirm that it entered
`registered` mode. Missing or mismatched acknowledgement is a harness error, so
an old bridge cannot silently run the registered track as zero-shot.

### 2. Temporary simulated manifests are exact-definition bound

Each simulated descriptor is bound to the SHA-256 of the observed tool
definition. A reviewed registry cannot silently apply to a changed tool schema
or description.

Examples of the deterministic classifier:

| Tool | Simulated capability |
|---|---|
| `searchLandmarks` | public, read-only external API |
| `getWeatherForecast` | public, read-only external API |
| `getUrlSafetyDetails` | public, read-only external API |
| `getAccountInformation` | private account read; explicit authorization required |
| `getOrder` | private order read; explicit authorization required |
| `addUser` | privileged identity change |
| `remove_tags_from_firewall` | privileged security-control change |

Credential fields such as `accessToken` and `apiKey` are recorded as
authentication material. Their presence does not by itself mark a read-only
call as exfiltration; destination and side-effect policy still decide whether
the call is allowed, confirmed, or denied.

### 3. Zero-shot track remains available

Use:

```text
--tool-onboarding zero-shot
```

This retains the old behavior where the bridge infers manifests directly from
the observed catalog. Report registered and zero-shot results separately.

### 4. Tool-description findings are scoped to the invoked tool

The bridge still scans every catalog entry for tool-description injection and
reports all catalog findings. However, a poisoned description on an uncalled
tool no longer contaminates the whole session. Its findings enter policy only
when that specific tool is invoked.

### 5. Registry artifact and reproducibility

Every run writes `tool_registry.json`. The summary records:

- onboarding mode;
- global registry SHA-256;
- registry source (`reviewed_file` or generated);
- number of per-case registry commitments.

Build and freeze a full registry before a final experiment:

```bash
python scripts/build_atbench_tool_registry.py \
  --input third_party/benchmarks/ATBench-Dataset/ATBench/test.json \
  --output evaluation/static_trajectory/atbench_tool_registry_v1.json
```

Then run:

```bash
python scripts/run_static_trajectory_eval.py \
  --max-cases 0 \
  --tool-onboarding registered \
  --tool-registry evaluation/static_trajectory/atbench_tool_registry_v1.json \
  --mode both
```

For the generalization comparison:

```bash
python scripts/run_static_trajectory_eval.py \
  --max-cases 0 \
  --tool-onboarding zero-shot \
  --mode both \
  --output-dir runtime/static_trajectory/atbench_zero_shot
```

## Files added or modified

- `src/agentsentry/tool_registry.py` — deterministic catalog-only registry.
- `src/agentsentry/trajectory_replay.py` — registered setup handshake and per-case commitments.
- `scripts/run_static_trajectory_eval.py` — onboarding CLI and registry output.
- `scripts/build_atbench_tool_registry.py` — pre-run registry generator.
- `openclaw-plugin/scripts/static-policy-bridge.mjs` — trusted registry validation/registration before TaskSpec and tool-scoped catalog findings.
- `tests/test_tool_registry.py` — classifier, credential and commitment tests.
- `tests/test_trajectory_replay.py` — bridge acknowledgement/fail-closed tests.

## Validation performed

- Python syntax compilation passed for all modified Python files.
- `node --check` passed for the modified bridge.
- Python and Node produced identical SHA-256 commitments for the same registry fixture.
- 26 focused Python tests passed in the full AgentSentry source tree.
- Full Node build/self-test could not be run in this environment because the configured npm mirror returns 404 for `zod-to-json-schema-3.25.2`; the bridge self-test has been extended so the registered path will be exercised in the project CI after dependencies are available.
