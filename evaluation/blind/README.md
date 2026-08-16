# Blind Holdout Protocol

`blind_holdout*.jsonl` is ignored by Git. An evaluator places or generates the
sealed file only after the release code is frozen, then runs it through
`scripts/run_blind_evaluation.py` with labels joined after detector decisions.

For a local protocol run:

```powershell
python scripts/generate_local_blind_holdout.py
$env:AGENTSENTRY_DASHBOARD_TOKEN = "<dashboard token>"
python scripts/run_blind_evaluation.py --cases evaluation/blind/blind_holdout.jsonl
```

The local generator creates 36 authorization-boundary pairs across the six
high-risk sinks. It is useful for validating label isolation, repetition, and
confidence-interval reporting, but it is not an externally authored benchmark.
Do not publish the example fixture or a dirty `--allow-dirty` run as blind
holdout evidence.
