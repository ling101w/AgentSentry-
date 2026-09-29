# OpenClaw Dataset Quality Report

Input: `..\reports\graph-learning\replay_graphs.control-rebuilt.jsonl`

## Snapshot

| Metric | Value |
|---|---:|
| Graph records | 168 |
| Unknown labels | 30 |
| Tool calls (min/avg/max) | 0 / 8.17 / 258 |
| Secret-pattern scan hits | 1 |
| Validation errors | 0 |

## Labels

| Label | Count |
|---|---:|
| `attack` | 78 |
| `normal` | 60 |
| `unknown` | 30 |

## Heuristic Task Types

These task types come from the graph builder's keyword heuristic and are not ground truth.

| Task type | Count |
|---|---:|
| `calendar_management` | 10 |
| `code_review` | 7 |
| `email_summary` | 18 |
| `file_processing` | 39 |
| `unknown` | 49 |
| `web_search` | 45 |

## Tool Usage

| Tool | Count |
|---|---:|
| `apply_patch` | 1 |
| `browser` | 80 |
| `cron` | 3 |
| `edit` | 6 |
| `exec` | 697 |
| `gateway` | 9 |
| `memory_search` | 15 |
| `message` | 1 |
| `nodes` | 1 |
| `process` | 210 |
| `read` | 205 |
| `session_status` | 1 |
| `sessions_list` | 1 |
| `sessions_spawn` | 1 |
| `web_fetch` | 57 |
| `web_search` | 28 |
| `write` | 57 |

## Validation Errors

- None

## Label Queue

Unknown-label metadata queue: `..\reports\graph-learning\replay_graphs.control-rebuilt.label_queue.jsonl`. It intentionally excludes user messages,
tool arguments, and observation contents.
