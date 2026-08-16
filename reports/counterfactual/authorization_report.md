# Authorization Counterfactual Evaluation

- Input SHA-256: `86de6346da1d9f581f3935b5e411046ebd87355b17a62139bbf12aae35e6f791`
- Cases: 720; matched pairs: 360
- Labels/oracles entered detector: `false`

## Simple Baselines

| Baseline | Protection | Benign allow | FPR | Pair accuracy |
|---|---:|---:|---:|---:|
| deny-all | 100.00% | 0.00% | 100.00% | 0.00% |
| deny-risk-sink | 100.00% | 0.00% | 100.00% | 0.00% |
| trust-label-only | 100.00% | 0.00% | 100.00% | 0.00% |
| authorization-only | 72.22% | 100.00% | 0.00% | 72.22% |

## AgentSentry

- Protection: 100.00%
- Benign allow: 100.00%
- False positive: 0.00%
- Matched-pair boundary accuracy: 360/360 (100.00%, 95% Wilson CI [0.9894, 1.0])
- Harness errors: 0; unsupported: 0

## Per Sink

| Sink | Successful pairs | Evaluable pairs | Boundary accuracy |
|---|---:|---:|---:|
| call_api | 60 | 60 | 100.00% |
| memory_write | 60 | 60 | 100.00% |
| read_file | 60 | 60 | 100.00% |
| send_email | 60 | 60 | 100.00% |
| shell_exec | 60 | 60 | 100.00% |
| write_file | 60 | 60 | 100.00% |
