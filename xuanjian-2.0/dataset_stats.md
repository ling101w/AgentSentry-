# Synthetic Dataset Statistics

Generated from `data/synthetic`.

## Overview

| Metric | Value |
|---|---:|
| Total records | 1000 |
| Normal | 800 |
| Attack | 200 |
| Average nodes per graph | 5.54 |
| Average edges per graph | 5.02 |

## Labels

| Label | Count | Share |
|---|---:|---:|
| `attack` | 200 | 20.0% |
| `normal` | 800 | 80.0% |

## Task Types

| Task type | Count |
|---|---:|
| `calendar_management` | 160 |
| `code_review` | 160 |
| `email_summary` | 210 |
| `file_processing` | 210 |
| `log_analysis` | 50 |
| `memory_management` | 50 |
| `web_search` | 160 |

## Attack Types

| Attack type | Count |
|---|---:|
| `IPI` | 50 |
| `data_exfiltration` | 50 |
| `memory_poisoning` | 50 |
| `privilege_escalation` | 50 |

## Graph Schema Usage

### Nodes

| Node type | Count |
|---|---:|
| `entity` | 100 |
| `intent` | 1000 |
| `observation` | 1000 |
| `tool_call` | 3439 |

### Edges

| Edge type | Count |
|---|---:|
| `call_sequence` | 2076 |
| `control_influence` | 200 |
| `data_dependency` | 640 |
| `data_derivation` | 1100 |
| `intent_drives` | 1000 |
