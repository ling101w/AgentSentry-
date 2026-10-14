"""Quick sanity check: distribution of attack tool_call `source` field in v3."""
import json
import glob
from collections import Counter

sources = Counter()
attack_files = sorted(glob.glob("data/synthetic_v3/attack_*.json"))
for fp in attack_files:
    g = json.load(open(fp, encoding="utf-8"))
    for n in g["nodes"]:
        if n["node_type"] == "tool_call" and n.get("tool_name") in (
            "send_email", "upload_file", "delete_file", "update_memory"
        ):
            sources[n.get("source")] += 1

print(f"[v3] {len(attack_files)} attack files")
print(f"[v3] attack tool_call source distribution: {dict(sources)}")
total = sum(sources.values())
for k, v in sources.items():
    print(f"        {k}: {v} ({100*v/total:.1f}%)")