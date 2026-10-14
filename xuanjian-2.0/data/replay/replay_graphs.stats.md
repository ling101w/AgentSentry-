# Replay Dataset Statistics

Source: `/mnt/e/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0/data/replay/replay_graphs.jsonl`

## Overview

| Metric | Value |
|---|---:|
| Total records | 168 |
| Normal | 60 |
| Attack | 78 |
| Unknown / unlabeled | 30 |
| Average nodes per graph | 17.95 |
| Average edges per graph | 24.26 |

## Labels

| Label | Count | Share |
|---|---:|---:|
| `attack` | 78 | 46.4% |
| `normal` | 60 | 35.7% |
| `unknown` | 30 | 17.9% |

## Task Types (intent node)

| Task type | Count |
|---|---:|
| `unknown` | 49 |
| `web_search` | 45 |
| `file_processing` | 39 |
| `email_summary` | 18 |
| `calendar_management` | 10 |
| `code_review` | 7 |

## Attack Types

| Attack type | Count |
|---|---:|
| `mcp_search_term_deception` | 7 |
| `Data Security Harm` | 6 |
| `Others` | 6 |
| `indirect_prompt_injection` | 6 |
| `mcp_prompt_injection` | 6 |
| `Financial Data` | 5 |
| `mcp_name_overlap` | 5 |
| `Physical Harm` | 4 |
| `mcp_preference_manipulation` | 4 |
| `mcp_preference_manipulation-out_of_scope_parameter` | 4 |
| `mcp_prompt_injection-simulated_user` | 4 |
| `mcp_simulated_user` | 4 |
| `Physical Data` | 3 |
| `mcp_preference_manipulation-simulated_user` | 3 |
| `mcp_false_error` | 2 |
| `mcp_prompt_injection-false_error` | 2 |
| `mcp_tool_transfer` | 2 |
| `Availability/Resource/CPU` | 1 |
| `Availability/Resource/Disk` | 1 |
| `Availability/Resource/Service` | 1 |
| `Financial Harm` | 1 |
| `Integrity/Delete/Normal` | 1 |

## Graph Schema Usage

### Nodes

| Node type | Count |
|---|---:|
| `tool_call` | 1373 |
| `observation` | 1353 |
| `intent` | 168 |
| `entity` | 121 |

### Edges

| Edge type | Count |
|---|---:|
| `data_derivation` | 1474 |
| `call_sequence` | 1265 |
| `data_dependency` | 1164 |
| `intent_drives` | 108 |
| `control_influence` | 65 |
