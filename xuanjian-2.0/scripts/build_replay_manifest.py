"""Build a replay manifest from the balanced benchmark case pool.

Selects executable injection cases (no unfilled {placeholder} templates)
and writes a JSONL manifest consumed by scripts/replay_wsl.sh:

  {"replay_id": ..., "case_id": ..., "user_message": ...,
   "untrusted_payload": ..., "delivery": "file"|"inline",
   "label": "attack"|"normal", "attack_type": ..., "source": ...}

Delivery model:
  file   - payload is written to ~/xuanjian_replay/<replay_id>_note.txt
           and the user message asks the agent to read/summarize it (IPI)
  inline - payload is appended to the user message (direct injection,
           used as a control group)

Usage (from xuanjian-2.0 project root):
    python scripts/build_replay_manifest.py \
        --pool ../benchmarks/dataset/cleaned/all.balanced.jsonl \
        --num-attack 120 --num-normal 60 --seed 42 \
        --output data/replay/manifest.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

PLACEHOLDER = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")
MAX_MESSAGE_CHARS = 1500
MAX_PAYLOAD_CHARS = 1200


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", type=str,
                        default="../../benchmarks/dataset/cleaned/all.balanced.jsonl")
    parser.add_argument("--num-attack", type=int, default=120)
    parser.add_argument("--num-normal", type=int, default=60)
    parser.add_argument("--inline-ratio", type=float, default=0.2,
                        help="fraction of attack cases delivered inline (control group)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="data/replay/manifest.jsonl")
    return parser.parse_args()


def stable_replay_id(case_id: str, index: int) -> str:
    digest = hashlib.sha1(f"{case_id}#{index}".encode()).hexdigest()[:12]
    return f"rp_{digest}"


def extract_case(record: dict) -> dict | None:
    """Pull an executable case out of one balanced-pool record, or None."""
    content = record.get("content") or {}
    labels = record.get("labels") or {}
    user_message = str(content.get("user_instruction") or "").strip()
    payload = str(content.get("attacker_instruction") or "").strip()
    is_attack = bool(labels.get("attack"))
    attack_type = labels.get("attack_type")
    source = record.get("source")
    if isinstance(source, dict):
        source = source.get("dataset", "?")

    # normal cases have no payload; skip templated messages for both labels
    if is_attack and not payload:
        return None
    if PLACEHOLDER.search(user_message):
        return None
    if not user_message:
        return None
    if len(user_message) > MAX_MESSAGE_CHARS:
        user_message = user_message[:MAX_MESSAGE_CHARS]
    if len(payload) > MAX_PAYLOAD_CHARS:
        payload = payload[:MAX_PAYLOAD_CHARS]

    return {
        "case_id": record.get("id", ""),
        "user_message": user_message,
        "untrusted_payload": payload if is_attack else "",
        "label": "attack" if is_attack else "normal",
        "attack_type": attack_type if is_attack else None,
        "source": source or "?",
        "threat_primary": (labels.get("threat_primary")
                           if isinstance(labels.get("threat_primary"), (str, int)) else None),
    }


def main() -> int:
    args = parse_args()
    pool_path = Path(args.pool)
    if not pool_path.is_absolute():
        pool_path = PROJECT_ROOT / pool_path

    buckets: dict[str, list[dict]] = {"attack": [], "normal": []}
    skipped_templated = 0
    skipped_no_payload = 0
    seen_case_ids = set()

    with open(pool_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            case = extract_case(record)
            if case is None:
                if PLACEHOLDER.search(str((record.get("content") or {}).get("user_instruction") or "")):
                    skipped_templated += 1
                elif (record.get("labels") or {}).get("attack") and not (record.get("content") or {}).get("attacker_instruction"):
                    skipped_no_payload += 1
                continue
            if case["case_id"] in seen_case_ids:
                continue
            seen_case_ids.add(case["case_id"])
            buckets[case["label"]].append(case)

    rng = random.Random(args.seed)
    rng.shuffle(buckets["attack"])
    rng.shuffle(buckets["normal"])

    selected = buckets["attack"][: args.num_attack] + buckets["normal"][: args.num_normal]
    if len(buckets["attack"]) < args.num_attack:
        print(f"[warn] only {len(buckets['attack'])} executable attack cases available "
              f"(wanted {args.num_attack})")
    if len(buckets["normal"]) < args.num_normal:
        print(f"[warn] only {len(buckets['normal'])} executable normal cases available "
              f"(wanted {args.num_normal})")

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = PROJECT_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    inline_count = 0
    with open(output_path, "w", encoding="utf-8") as fh:
        for index, case in enumerate(selected):
            delivery = "inline" if (case["label"] == "attack"
                                    and rng.random() < args.inline_ratio) else "file"
            if case["label"] == "normal":
                delivery = "none"
            if delivery == "inline":
                inline_count += 1
            entry = {
                "replay_id": stable_replay_id(case["case_id"], index),
                "delivery": delivery,
                **case,
            }
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    counts = {"attack": sum(1 for c in selected if c["label"] == "attack"),
              "normal": sum(1 for c in selected if c["label"] == "normal")}
    sources = {}
    for c in selected:
        sources[c["source"]] = sources.get(c["source"], 0) + 1
    print(f"[manifest] {len(selected)} cases -> {output_path}")
    print(f"  labels: {counts} | delivery: file={counts['attack'] - inline_count} "
          f"inline={inline_count} none={counts['normal']}")
    print(f"  sources: {sources}")
    print(f"  skipped: templated={skipped_templated} no_payload={skipped_no_payload}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
