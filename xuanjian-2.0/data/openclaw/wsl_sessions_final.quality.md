# OpenClaw Dataset Quality Report

Input: `data/openclaw/wsl_sessions_final.jsonl`

## Snapshot

| Metric | Value |
|---|---:|
| Graph records | 30 |
| Unknown labels | 30 |
| Tool calls (min/avg/max) | 1 / 35.70 / 258 |
| Secret-pattern scan hits | 0 |
| Validation errors | 0 |

## Labels

| Label | Count |
|---|---:|
| `unknown` | 30 |

## Heuristic Task Types

These task types come from the graph builder's keyword heuristic and are not ground truth.

| Task type | Count |
|---|---:|
| `code_review` | 1 |
| `email_summary` | 9 |
| `file_processing` | 3 |
| `unknown` | 10 |
| `web_search` | 7 |

## Tool Usage

| Tool | Count |
|---|---:|
| `apply_patch` | 1 |
| `browser` | 61 |
| `cron` | 1 |
| `edit` | 6 |
| `exec` | 611 |
| `gateway` | 8 |
| `memory_search` | 5 |
| `process` | 180 |
| `read` | 113 |
| `sessions_list` | 1 |
| `sessions_spawn` | 1 |
| `web_fetch` | 29 |
| `web_search` | 4 |
| `write` | 50 |

## Validation Errors

- None

## Label Queue

Unknown-label metadata queue: `data/openclaw/wsl_sessions_final.label_queue.jsonl`. It intentionally excludes user messages,
tool arguments, and observation contents.
