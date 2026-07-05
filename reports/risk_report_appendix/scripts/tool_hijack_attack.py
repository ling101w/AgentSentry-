#!/usr/bin/env python3
"""工具调用劫持场景批量复现脚本。

脚本只提交受控样例到 OpenClaw 实验台，用于生成审计日志。
危险命令和外发动作由实验台记录裁决与意图，不真实破坏主机。
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path


TOOL_HIJACK_SOURCES_IN_COMPREHENSIVE = {"MSB", "MCPSecBench"}


def iter_jsonl(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def normalize_case(item: dict) -> dict:
    return {
        "case_id": item["case_id"],
        "source": item["source"],
        "source_ref": item.get("source_ref"),
        "category": item["category"],
        "scenario": item["scenario"],
        "command": item["command"],
        "tool": item.get("tool") or "",
        "target": item.get("target") or "",
        "params": item.get("params"),
        "notes": item.get("notes"),
    }


def load_cases(start: int = 0, limit: int = 0) -> list[dict]:
    root = Path(__file__).resolve().parents[3]
    comprehensive_path = root / "reports" / "benchmark_risk_tiered" / "benchmark_cases.risk_tiered.jsonl"
    tool_path = root / "reports" / "benchmark_risk_tiered" / "tool_attack_cases.risk_tiered.jsonl"
    cases = [
        normalize_case(item)
        for item in iter_jsonl(comprehensive_path)
        if item.get("source") in TOOL_HIJACK_SOURCES_IN_COMPREHENSIVE
    ]
    cases.extend(normalize_case(item) for item in iter_jsonl(tool_path))
    if start:
        cases = cases[start:]
    if limit:
        cases = cases[:limit]
    return cases

def post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "http_status": exc.code, "error": body}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--out", default=None)
    parser.add_argument("--start", type=int, default=0, help="从第几个样例开始运行，默认 0")
    parser.add_argument("--limit", type=int, default=0, help="最多运行多少条，默认 0 表示全部")
    args = parser.parse_args()

    endpoint = args.base_url.rstrip("/") + "/api/lab/command"
    out_path = Path(args.out) if args.out else Path(__file__).resolve().parents[1] / "logs" / "tool_hijack_attack_log.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    records = []
    cases = load_cases(args.start, args.limit)
    print(f"loaded {len(cases)} tool-hijack benchmark cases")
    for index, case in enumerate(cases):
        payload = {
            "command": case["command"],
            "scenario": case["scenario"],
            "tool": case["tool"],
            "target": case["target"],
            "params": case["params"],
            "clientId": "appendix_tool_hijack",
            "resetSession": index == 0,
            "benchmarkCaseId": case["case_id"],
            "benchmarkSource": case["source"],
        }
        response = post_json(endpoint, payload)
        records.append({
            "case_id": case["case_id"],
            "source": case["source"],
            "source_ref": case["source_ref"],
            "category": case["category"],
            "tool": case["tool"],
            "target": case["target"],
            "command": case["command"],
            "params": case["params"],
            "notes": case["notes"],
            "response_ok": response.get("ok"),
            "run_id": response.get("record", {}).get("run_id"),
            "record_id": response.get("record", {}).get("id"),
            "decision_summary": response.get("summary") or response.get("outcome") or response.get("error"),
            "raw_response": response,
        })
        time.sleep(0.2)

    out_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"saved {len(records)} records to {out_path}")


if __name__ == "__main__":
    main()
