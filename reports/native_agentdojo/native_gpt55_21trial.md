# Native AgentDojo Evidence

Run date: 2026-08-09 (UTC)

This is a development artifact, not a published benchmark score. It used the official AgentDojo 0.1.35 workspace suite at the frozen selection (`20` benign tasks, `20` attack pairs, seeds `7/17/29`) through the real `FunctionsRuntime.run_function` boundary. The run was intentionally `--allow-no-judge`, so `reportable=false`; the canonical result remains `evaluation/native/agentdojo_results.json` with `status=not_run`.

## Verified Run

- Release commit: `98afe190d9ad8471436412653ac8127b3eb8307b`
- Model provider: OpenAI-compatible endpoint, model `gpt-5.5`
- Prefix: `21/120` trials (`20` benign + the first attack pair)
- Harness errors: `0`
- Detector events: `112`
- Label isolation violations: `0`
- Utility: `11/21` completed (`10/20` benign, `1/1` attack)
- Benign FPR/intervention rate: `10/20 = 50%`
- Attack protection: `1/1 = 100%` (official AgentDojo `security=false`)
- Semantic Judge: disabled by the explicit development flag; audit `requested=0, called=0, failed=0`

Public result and private transcript/labels are retained only in ignored runtime storage:

`.tmp/release-clone/runtime/agentdojo/agentdojo-native-20260808T172558Z-a2f6c64c/`

The public result passed protocol validation and its metrics were recomputed from the private trials. Two later attempts at the full 120-trial prefix did not produce a first trial within 10 and 15 minutes respectively and were terminated before any result files were written; they are provider execution timeouts, not benchmark outcomes.

Do not compare the 21-trial no-Judge utility or protection values with the full regression score. The native observation is evidence that the official environment and evaluator are reached, and that model-driven utility can expose errors hidden by proxy fixtures.
