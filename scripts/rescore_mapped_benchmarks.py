"""Read-only legacy input audit; write new reports, never overwrite source files."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from mapped_benchmark_scoring import DEFAULT_ANNOTATIONS, load_annotations, score_result
import run_benchmark_eval as general
import run_tool_attack_benchmark_eval as tools

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=ROOT / "reports/benchmark_risk_tiered")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "reports" / ("mapped-scoring-audit-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    parser.add_argument("--annotations", type=Path, default=DEFAULT_ANNOTATIONS)
    args = parser.parse_args()
    registry = load_annotations(args.annotations)
    # Refuse existing paths to keep both originals and previous audits intact.
    args.output_dir.mkdir(parents=True, exist_ok=False)
    summaries = []
    for filename, runner in [("benchmark_eval_results.risk_tiered.json", general),
                             ("tool_attack_benchmark_results.risk_tiered.json", tools)]:
        path = args.input_dir / filename
        raw = path.read_bytes()
        payload = json.loads(raw)
        original = payload["results"]
        rescored = []
        for row in original:
            updated = score_result(row, registry)
            updated["legacy_scores"] = {k: row.get(k) for k in ("ok", "protected", "unsafe_release", "false_positive", "allowed_all")}
            rescored.append(updated)
        payload.update(results=rescored, summary=runner.summarize(rescored),
                       original_generated_at=payload.get("generated_at"),
                       generated_at=datetime.now(timezone.utc).isoformat(),
                       audit={"source": str(path), "source_sha256": hashlib.sha256(raw).hexdigest(),
                              "method": "offline-rescore-no-new-detector-requests"})
        stem = "tool" if runner is tools else "general"
        (args.output_dir / f"{stem}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        runner.write_csv(payload, args.output_dir / f"{stem}.csv")
        (args.output_dir / f"{stem}.md").write_text(runner.render_report(payload), encoding="utf-8")
        summaries.append({"suite": stem, "legacy_protected": sum(r.get("protected") is True for r in original),
                          **payload["summary"]["overall"]})
    (args.output_dir / "summary.json").write_text(json.dumps(summaries, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output_dir": str(args.output_dir), "summary": summaries}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
