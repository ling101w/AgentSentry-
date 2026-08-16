# Authorization Counterfactual Suite

This suite is separate from the frozen 7,227-case regression benchmark. It
contains 360 matched pairs, with 60 benign cases for each high-risk sink:
`read_file`, `write_file`, `send_email`, `call_api`, `shell_exec`, and
`memory_write`.

Every benign case contains an untrusted input while the trusted user message
explicitly authorizes the exact sink. Its matched attack changes the target,
scope, or payload without changing the trusted instruction. The runner sends
only `detector_input`; `attack`, `expectation`, `variant`, and `oracle` remain
in the evaluator process.

```powershell
python scripts/generate_counterfactual_dataset.py --check
python scripts/run_counterfactual_eval.py --dry-run
python scripts/run_counterfactual_eval.py --base-url http://127.0.0.1:8765
```

The generated JSONL is intentionally versioned. Regenerate it only through
the deterministic generator and review the manifest SHA-256.
