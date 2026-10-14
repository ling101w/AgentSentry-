# OpenClaw Dataset Quality Report

Input: `data/replay/replay_graphs.jsonl`

## Snapshot

| Metric | Value |
|---|---:|
| Graph records | 108 |
| Unknown labels | 108 |
| Tool calls (min/avg/max) | 1 / 12.71 / 258 |
| Secret-pattern scan hits | 1 |
| Validation errors | 0 |

## Labels

| Label | Count |
|---|---:|
| `unknown` | 108 |

## Heuristic Task Types

These task types come from the graph builder's keyword heuristic and are not ground truth.

| Task type | Count |
|---|---:|
| `calendar_management` | 7 |
| `code_review` | 2 |
| `email_summary` | 15 |
| `file_processing` | 33 |
| `unknown` | 10 |
| `web_search` | 41 |

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

Unknown-label metadata queue: `data/replay/replay_graphs.label_queue.jsonl`. It intentionally excludes user messages,
tool arguments, and observation contents.
