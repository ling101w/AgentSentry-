"""Build the phase-5/8 expansion manifest for replay collection.

Combines two sources into one manifest for `scripts/replay_wsl.sh`:

  1. RE-RUNS of manifest entries whose previous replay produced a dead
     session (LLM backend outage on 2026-08-30T16). Re-runs keep their
     original replay_id so relabel_graphs.py mappings stay valid.
     The dead list is derived by cross-referencing the WSL session files
     against the existing graph file (see data/replay/xjreplay_wsL_files.txt
     for the file listing snapshot).
  2. FRESH cases drawn from the balanced benchmark pool, excluding every
     case_id already present in any prior manifest, stratified across
     attack_type families so the expansion does not over-concentrate on
     one benchmark category.

Usage (from xuanjian-2.0 project root):
    python scripts/build_replay_manifest2.py \
        --pool ../../benchmarks/dataset/cleaned/all.balanced.jsonl \
        --prior-manifests data/replay/manifest.jsonl \
        --dead-list data/replay/dead_replay_ids.json \
        --new-attack 90 --new-normal 150 \
        --output data/replay/manifest2.jsonl
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

PLACEHOLDER = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")
MAX_MESSAGE_CHARS = 1500
MAX_PAYLOAD_CHARS = 1200

# attack_type families in the pool that are worth replaying. Long-tail
# Integrity/Availability/RAG families stay in too — they map to distinct
# schema categories (unauthorized_mutation / shell_abuse).
FAMILY_MIN = 1  # per-family minimum before filling to quota


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", type=str,
                        default="../../benchmarks/dataset/cleaned/all.balanced.jsonl")
    parser.add_argument("--prior-manifests", type=str, nargs="+",
                        default=["data/replay/manifest.jsonl"])
    parser.add_argument("--dead-list", type=str,
                        default="data/replay/dead_replay_ids.json")
    parser.add_argument("--new-attack", type=int, default=90)
    parser.add_argument("--new-normal", type=int, default=150)
    parser.add_argument("--inline-ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=20260922)
    parser.add_argument("--output", type=str, default="data/replay/manifest2.jsonl")
    return parser.parse_args()


def stable_replay_id(case_id: str, salt: str) -> str:
    digest = hashlib.sha1(f"{case_id}#{salt}".encode()).hexdigest()[:12]
    return f"rp_{digest}"


def extract_case(record: dict) -> dict | None:
    content = record.get("content") or {}
    labels = record.get("labels") or {}
    user_message = str(content.get("user_instruction") or "").strip()
    payload = str(content.get("attacker_instruction") or "").strip()
    is_attack = bool(labels.get("attack"))
    attack_type = labels.get("attack_type")
    source = record.get("source")
    if isinstance(source, dict):
        source = source.get("dataset", "?")
    if is_attack and not payload:
        return None
    if PLACEHOLDER.search(user_message) or not user_message:
        return None
    return {
        "case_id": record.get("id", ""),
        "user_message": user_message[:MAX_MESSAGE_CHARS],
        "untrusted_payload": payload[:MAX_PAYLOAD_CHARS] if is_attack else "",
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

    used_case_ids: set[str] = set()
    for pm in args.prior_manifests:
        pmp = Path(pm)
        if not pmp.is_absolute():
            pmp = PROJECT_ROOT / pmp
        with open(pmp, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    used_case_ids.add(json.loads(line)["case_id"])

    dead_path = PROJECT_ROOT / args.dead_list
    with open(dead_path, "r", encoding="utf-8") as fh:
        dead_ids = set(json.load(fh))
    with open(PROJECT_ROOT / "data/replay/manifest.jsonl", "r", encoding="utf-8") as fh:
        prior = {json.loads(l)["replay_id"]: json.loads(l) for l in fh if l.strip()}
    rerun = [prior[rid] for rid in sorted(dead_ids) if rid in prior]
    # attack re-runs first: if the batch is interrupted mid-way we still
    # recover the scarcer class first
    rerun.sort(key=lambda e: 0 if e["label"] == "attack" else 1)
    for entry in rerun:
        used_case_ids.add(entry["case_id"])

    # bucket fresh pool cases by (label, attack family)
    attack_by_family: dict[str, list[dict]] = collections.defaultdict(list)
    normal_cases: list[dict] = []
    seen: set[str] = set()
    with open(pool_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            case = extract_case(json.loads(line))
            if case is None or case["case_id"] in seen:
                continue
            seen.add(case["case_id"])
            if case["case_id"] in used_case_ids:
                continue
            if case["label"] == "attack":
                attack_by_family[case["attack_type"] or "Others"].append(case)
            else:
                normal_cases.append(case)

    rng = random.Random(args.seed)
    for lst in attack_by_family.values():
        rng.shuffle(lst)
    rng.shuffle(normal_cases)

    # stratified attack selection: round-robin families until quota
    families = sorted(attack_by_family, key=lambda f: -len(attack_by_family[f]))
    selected_attack: list[dict] = []
    ring = list(families)
    while ring and len(selected_attack) < args.new_attack:
        fam = ring.pop(0)
        selected_attack.append(attack_by_family[fam].pop(0))
        if attack_by_family[fam]:
            ring.append(fam)
    selected_normal = normal_cases[: args.new_normal]

    output: list[dict] = []
    for entry in rerun:
        output.append(dict(entry))
    for case in selected_attack:
        delivery = "inline" if rng.random() < args.inline_ratio else "file"
        output.append({
            "replay_id": stable_replay_id(case["case_id"], "m2"),
            "delivery": delivery,
            **case,
        })
    for case in selected_normal:
        output.append({
            "replay_id": stable_replay_id(case["case_id"], "m2"),
            "delivery": "none",
            **case,
        })

    out_path = PROJECT_ROOT / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for entry in output:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    fam_counts = collections.Counter(c["attack_type"] for c in selected_attack)
    src_counts = collections.Counter(c["source"] for c in selected_attack + selected_normal)
    print(f"[manifest2] {len(output)} cases -> {out_path}")
    print(f"  reruns: {len(rerun)} (attack={sum(1 for e in rerun if e['label']=='attack')}, "
          f"normal={sum(1 for e in rerun if e['label']=='normal')})")
    print(f"  fresh attack: {len(selected_attack)} across {len(fam_counts)} families")
    for fam, n in fam_counts.most_common():
        print(f"    {fam}: {n}")
    print(f"  fresh normal: {len(selected_normal)}")
    print(f"  sources: {dict(src_counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
