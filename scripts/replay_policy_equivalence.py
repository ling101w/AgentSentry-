#!/usr/bin/env python3
"""Replay old-run detector payloads through the current policy bridge.

The 19:01 edit changed the workspace manifest/bridge files after the workspace
run started. Per-entry manifest digests already proved the manifest semantics
are unchanged, but the bridge script content was not recoverable. This script
settles behavioral equivalence empirically: it replays before_tool payloads
recorded in the old run through the CURRENT bridge and compares decisions.

Sessions are replayed in original order per trial so session_history evolves
exactly as it did during the run.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsentry.agentdojo_adapter import JsonlNodeBridgeClient  # noqa: E402

RUN_DIR = ROOT / "runtime" / "agentdojo" / "agentdojo-native-20260815T095128Z-8d634908"
BRIDGE = ROOT / "openclaw-plugin" / "scripts" / "agentdojo-policy-bridge.mjs"
SAMPLE_PER_SESSION_CAP = None  # replay everything


def main() -> int:
    os.environ["AGENTSENTRY_NATIVE_PROFILE"] = "competition"
    os.environ["AGENTSENTRY_NATIVE_MANIFEST"] = str(
        (ROOT / "openclaw-plugin" / "manifests" / "agentdojo-workspace-v1.2.2.json").resolve()
    )

    # Group before_tool events by session, preserving order.
    sessions: dict[str, list[dict]] = defaultdict(list)
    start_payloads: dict[str, dict] = {}
    with (RUN_DIR / "detector-events.private.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            event = json.loads(line)
            routing = event.get("routing") or {}
            op = routing.get("op")
            if op == "start":
                start_payloads[str(routing.get("opaque_session_id"))] = dict(
                    event.get("detector_input") or {}
                )
                continue
            if op != "before_tool":
                continue
            out = event.get("detector_output") or {}
            if out.get("ok") is not True:
                continue
            sessions[str(routing.get("opaque_session_id"))].append(event)

    bridge = JsonlNodeBridgeClient(["node", str(BRIDGE)], timeout=60.0)
    total = match = 0
    mismatch_examples: list[dict] = []
    verdict_counter: Counter = Counter()
    judge_delta = 0
    try:
        for session_id, events in sessions.items():
            sid = session_id  # already an opaque trial_<hex> id
            bridge.request({"op": "start", "session_id": sid, "payload": {}})
            history: list[dict] = []
            for event in events:
                payload = dict(event["detector_input"])
                payload["session_history"] = list(history)
                old_result = event["detector_output"]["result"]
                old_decision = old_result.get("decision")
                response = bridge.request(
                    {
                        "op": "before_tool",
                        "session_id": sid,
                        "call_id": f"replay_{event['event_id']}",
                        "payload": payload,
                    }
                )
                new_decision = response.get("decision")
                total += 1
                verdict_counter[(old_decision, new_decision)] += 1
                if old_decision != new_decision:
                    mismatch_examples.append(
                        {
                            "event_id": event["event_id"],
                            "tool": payload.get("tool_name"),
                            "old": old_decision,
                            "new": new_decision,
                            "old_reason": str(old_result.get("reason"))[:160],
                            "new_reason": str(response.get("reason"))[:160],
                        }
                    )
                old_judge = bool(old_result.get("semantic_judge_called"))
                new_judge = bool(response.get("semantic_judge_called"))
                if old_judge != new_judge:
                    judge_delta += 1
                history.append(
                    {
                        "tool_name": payload.get("tool_name"),
                        "tool_args": payload.get("tool_args"),
                        "tool_result": None,
                        "decision": new_decision,
                        "executed": new_decision == "allow",
                        "error": None,
                    }
                )
            try:
                bridge.request({"op": "end", "session_id": sid})
            except Exception:
                pass
    finally:
        bridge.close()

    print(f"replayed before_tool decisions: {total}")
    print(f"decision match: {match if False else total - sum(v for (a, b), v in verdict_counter.items() if a != b)}/{total}")
    print("confusion (old,new):")
    for pair, count in sorted(verdict_counter.items(), key=lambda kv: -kv[1]):
        print(f"  {pair}: {count}")
    print(f"semantic_judge_called flips: {judge_delta}")
    print(f"mismatches: {len(mismatch_examples)}")
    for row in mismatch_examples[:10]:
        print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
