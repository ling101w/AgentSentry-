from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import utc_now
from .openclaw_evidence import openclaw_records
from .storage import Store


TOOLS = [
    "webpage",
    "file",
    "email",
    "api",
    "search",
    "memory",
    "read_file",
    "write_file",
    "shell",
    "database",
]
LIFECYCLE_LAYERS = [
    "Foundation",
    "Input Sanitization",
    "Cognition Protection",
    "Decision Alignment",
    "Execution Control",
]
DEFENSE_MODES = [
    ("full", "#35f29b"),
    ("no_deterministic", "#f8b84e"),
    ("no_sentry", "#ff4d5e"),
    ("no_feedback", "#a77cff"),
    ("none", "#b64045"),
]
RULE_LABELS = {
    "suspicious_sink_guard": "suspicious_sink_guard",
    "tool_scope_enforcer": "tool_scope_enforcer",
    "block_prompt_injection": "block_prompt_injection",
    "taint_output_gate": "taint_output_gate",
    "memory_poisoning_watch": "memory_poisoning_watch",
    "foundation_semantic_scan": "foundation_semantic_scan",
    "behavior_anomaly": "behavior_anomaly_detector",
    "approval_cache_guard": "approval_cache_guard",
    "deterministic_policy_gate": "deterministic_policy_gate",
}


def security_overview(store: Store, openclaw_limit: int = 5000, source: str = "combined") -> dict[str, Any]:
    snapshot = store.overview_snapshot(event_limit=5000, run_limit=500, eval_limit=200)
    local_events = [_local_event(row) for row in snapshot["events"]]
    openclaw_raw = openclaw_records(limit=openclaw_limit)
    openclaw_events = [_openclaw_event(row) for row in openclaw_raw.get("records", [])]
    source_mode = _source_mode(source)
    if source_mode == "openclaw":
        events = openclaw_events
        window = f"latest {len(openclaw_events)} OpenClaw plugin records"
        primary_source = "OpenClaw plugin records"
    elif source_mode == "local":
        events = local_events
        window = f"latest {len(local_events)} AgentSentry SQLite events"
        primary_source = "AgentSentry SQLite events"
    else:
        events = local_events + openclaw_events
        window = f"latest {len(local_events)} AgentSentry events + latest {len(openclaw_events)} OpenClaw records"
        primary_source = "combined AgentSentry SQLite + OpenClaw records"
    events = sorted(events, key=lambda item: item["created_at"], reverse=True)

    now = datetime.now(UTC)
    previous_cutoff = now - timedelta(hours=24)
    current = [event for event in events if _parse_dt(event["created_at"]) >= previous_cutoff]
    previous = [event for event in events if previous_cutoff - timedelta(hours=24) <= _parse_dt(event["created_at"]) < previous_cutoff]

    decisions = [event for event in events if event["decision"] in {"ALLOW", "ASK", "BLOCK"}]
    blocked = [event for event in decisions if event["decision"] == "BLOCK"]
    asked = [event for event in decisions if event["decision"] == "ASK"]
    allowed = [event for event in decisions if event["decision"] == "ALLOW"]
    dangerous = [event for event in events if event["severity"] in {"CRITICAL", "HIGH"}]
    taints = [event for event in events if _has_any(event["text"], ["taint", "untrusted", "pollut", "污染", "不可信"])]
    drift = [event for event in events if _has_any(event["text"], ["drift", "taskspec", "intent", "scope", "deviat", "越权", "偏离"])]
    memory = [event for event in events if _has_any(event["text"], ["memory", "poison", "记忆", "投毒"])]
    tool_events = [event for event in events if event["tool"] != "agent" or _has_any(event["text"], ["tool", "工具", "read", "write", "call"])]

    total = len(events)
    metrics = [
        _metric("total", "⌁", total, "总事件数", "Total Events", "cyan", _trend("total", current, previous)),
        _metric("blocks", "⬟", len(blocked), "高危拦截", "High Risk Blocks", "red", _trend_decision(current, previous, "BLOCK")),
        _metric("tools", "⚒", len(tool_events), "工具调用", "Tool Calls", "cyan", _trend_tools(current, previous)),
        _metric("taint", "☣", len(taints), "污染传播", "Taint Flows", "amber", _trend_text(current, previous, ["taint", "untrusted", "pollut", "污染", "不可信"])),
        _metric("drift", "⌖", len(drift), "意图漂移", "Drift Alerts", "amber", _trend_text(current, previous, ["drift", "taskspec", "intent", "scope", "deviat", "越权", "偏离"])),
        _metric("memory", "◇", len(memory), "记忆投毒", "Memory Poisoning", "red", _trend_text(current, previous, ["memory", "poison", "记忆", "投毒"])),
        _metric("allowed", "✓", len(allowed), "策略放行", "Allowed", "green", _trend_decision(current, previous, "ALLOW")),
        _metric("pending", "?", len(asked), "待审批", "Ask / Pending", "amber", _trend_decision(current, previous, "ASK")),
    ]

    protection_index = _protection_index(decisions, dangerous, taints)
    alert_rows = _alerts(events)
    timeline = _timeline(events)
    return {
        "generated_at": utc_now(),
        "source": {
            "mode": source_mode,
            "primary": primary_source,
            "local_event_count": len(local_events),
            "openclaw_event_count": len(openclaw_events),
            "openclaw_available": bool(openclaw_raw.get("available")),
            "openclaw_source": openclaw_raw.get("source", ""),
            "window": window,
        },
        "metrics": metrics,
        "lifecycle": _lifecycle(events),
        "modes": _modes(snapshot["evals"]),
        "alerts": alert_rows[:8],
        "alertCount": len(alert_rows),
        "stages": _stages(events),
        "rules": _rules(events),
        "timeline": timeline,
        "timelineCounts": dict(Counter(event["decision"].lower() if event["decision"] else "info" for event in events)),
        "timelineLabels": _timeline_labels(timeline),
        "nodes": _nodes(events),
        "meshMeta": _mesh_meta(events),
        "protectionIndex": protection_index,
        "blockedHighRisk": len(blocked),
        "summary": _summary(total, blocked, dangerous, taints, decisions, protection_index, primary_source),
        "recentOperations": _operations(events),
        "runs": _runs(snapshot["runs"], snapshot["events"]),
    }


def _source_mode(raw: str) -> str:
    value = str(raw or "combined").strip().lower()
    return value if value in {"combined", "openclaw", "local"} else "combined"


def _local_event(row: dict[str, Any]) -> dict[str, Any]:
    payload = row.get("payload") or {}
    text = _text(row)
    return {
        "id": row.get("id", ""),
        "run_id": row.get("run_id", ""),
        "source": "AgentSentry",
        "type": str(row.get("type", "event")),
        "layer": _layer(payload.get("layer") or row.get("type"), text),
        "severity": _severity(payload, text),
        "decision": _decision(payload, text),
        "tool": _tool(payload, text),
        "title": str(payload.get("title") or row.get("type") or "AgentSentry Event"),
        "reason": _reason(payload, row.get("type")),
        "rule": _rule(payload, text),
        "score": _score(payload),
        "created_at": str(row.get("created_at") or utc_now()),
        "text": text,
        "payload": payload,
    }


def _openclaw_event(record: dict[str, Any]) -> dict[str, Any]:
    payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
    text = _text(record)
    return {
        "id": str(record.get("id", "")),
        "run_id": str(record.get("run_id", record.get("session_key", ""))),
        "source": "OpenClaw",
        "type": str(record.get("type", "record")),
        "layer": _layer(record.get("layer") or payload.get("layer") or record.get("type"), text),
        "severity": _severity({"severity": record.get("severity"), **payload}, text),
        "decision": _decision(payload | {"severity": record.get("severity"), "action": record.get("action")}, text),
        "tool": _tool(payload | {"tool": record.get("tool")}, text),
        "title": str(record.get("title") or record.get("type") or "OpenClaw Event"),
        "reason": _reason(payload | {"summary": record.get("summary"), "title": record.get("title")}, record.get("type")),
        "rule": _rule(payload, text),
        "score": _score(payload),
        "created_at": str(record.get("created_at") or utc_now()),
        "text": text,
        "payload": payload,
    }


def _metric(key: str, icon: str, num: int, cn: str, en: str, type_: str, trend: float) -> dict[str, Any]:
    return {"key": key, "icon": icon, "num": num, "cn": cn, "en": en, "type": type_, "trend": round(trend, 1)}


def _trend(metric: str, current: list[dict[str, Any]], previous: list[dict[str, Any]]) -> float:
    return _pct(len(current), len(previous))


def _trend_decision(current: list[dict[str, Any]], previous: list[dict[str, Any]], decision: str) -> float:
    current_count = sum(1 for event in current if event["decision"] == decision)
    previous_count = sum(1 for event in previous if event["decision"] == decision)
    return _pct(current_count, previous_count)


def _trend_tools(current: list[dict[str, Any]], previous: list[dict[str, Any]]) -> float:
    current_count = sum(1 for event in current if event["tool"] != "agent" or _has_any(event["text"], ["tool", "工具", "read", "write", "call"]))
    previous_count = sum(1 for event in previous if event["tool"] != "agent" or _has_any(event["text"], ["tool", "工具", "read", "write", "call"]))
    return _pct(current_count, previous_count)


def _trend_text(current: list[dict[str, Any]], previous: list[dict[str, Any]], markers: list[str]) -> float:
    cur = sum(1 for event in current if _has_any(event["text"], markers))
    prev = sum(1 for event in previous if _has_any(event["text"], markers))
    return _pct(cur, prev)


def _pct(current: int, previous: int) -> float:
    if previous <= 0:
        return 0.0
    return ((current - previous) / previous) * 100


def _protection_index(decisions: list[dict[str, Any]], dangerous: list[dict[str, Any]], taints: list[dict[str, Any]]) -> int:
    if not decisions:
        return 0
    blocked = sum(1 for item in decisions if item["decision"] == "BLOCK")
    asked = sum(1 for item in decisions if item["decision"] == "ASK")
    risky = max(1, len(dangerous) + len(taints))
    containment = min(1.0, (blocked + asked * 0.6) / risky)
    clean_allows = max(0, sum(1 for item in decisions if item["decision"] == "ALLOW" and item["severity"] == "INFO"))
    business_factor = clean_allows / max(1, len(decisions))
    return max(0, min(100, round(containment * 74 + business_factor * 24)))


def _lifecycle(events: list[dict[str, Any]]) -> list[list[Any]]:
    by_layer: dict[str, list[dict[str, Any]]] = {layer: [] for layer in LIFECYCLE_LAYERS}
    for event in events:
        by_layer.setdefault(event["layer"], []).append(event)
    result = []
    for layer in LIFECYCLE_LAYERS:
        rows = by_layer.get(layer, [])
        risky = sum(1 for row in rows if row["severity"] in {"CRITICAL", "HIGH", "MEDIUM"} or row["decision"] in {"BLOCK", "ASK"})
        contained = sum(1 for row in rows if row["decision"] in {"BLOCK", "ASK"})
        pct = round((contained / risky * 100) if risky else (100 if rows else 0))
        result.append([layer, pct, len(rows)])
    return result


def _modes(evals: list[dict[str, Any]]) -> list[list[Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for item in evals:
        mode = str(item.get("defense_mode", ""))
        latest.setdefault(mode, item.get("metrics", {}))
    result = []
    for mode, color in DEFENSE_MODES:
        metrics = latest.get(mode, {})
        if metrics:
            vector, score = _mode_risk(mode, metrics)
        else:
            score = 0
            vector = [0, 0, 0, 0, 0]
        label = f"{mode}（当前）" if mode == "full" else mode
        result.append([label, max(0, min(100, score)), color, vector])
    return result


def _mode_risk(mode: str, metrics: dict[str, Any]) -> tuple[list[int], int]:
    cases = metrics.get("cases") if isinstance(metrics.get("cases"), list) else []
    attacks = [case for case in cases if case.get("attack")]
    attack_count = max(1, int(metrics.get("attack_count") or len(attacks) or 1))
    asr = _rate(metrics.get("ASR", metrics.get("Bypass Rate", 0)))
    fpr = _rate(metrics.get("FPR", 0))
    unsafe = _rate(sum(1 for case in attacks if case.get("unsafe_sink_released")) / attack_count)
    if attacks:
        uncovered = sum(
            1
            for case in attacks
            if not case.get("deterministic_blocked")
            and not case.get("heuristic_flagged")
            and not case.get("asked")
        )
        signal_gap = uncovered / max(1, len(attacks)) * 100
    else:
        signal_gap = 0.0
    control_gap = {
        "full": 0.0,
        "no_deterministic": 34.0,
        "no_sentry": 38.0,
        "no_feedback": 18.0,
        "none": 78.0,
    }.get(mode, 20.0)
    latency = min(100.0, float(metrics.get("avg_latency_ms") or 0) / 200 * 100)
    vector = [round(asr), round(fpr), round(unsafe), round(signal_gap), round(control_gap)]
    score = round(asr * 0.34 + fpr * 0.14 + unsafe * 0.20 + signal_gap * 0.16 + control_gap * 0.14 + latency * 0.02)
    return vector, max(0, min(100, score))


def _rate(raw: Any) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0
    return value * 100 if value <= 1 else value


def _alerts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        event
        for event in events
        if event["decision"] in {"BLOCK", "ASK"} or event["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}
    ]
    return [
        {
            "id": event["id"],
            "severity": event["severity"],
            "type": _attack_type(event),
            "tool": event["tool"],
            "action": event["decision"] or "INFO",
            "time": _format_time(event["created_at"]),
            "reason": event["reason"],
            "source": event["source"],
            "rule": event["rule"],
            "score": event["score"],
        }
        for event in rows
    ]


def _stages(events: list[dict[str, Any]]) -> list[list[Any]]:
    defs: list[tuple[str, list[str]]] = [
        ("输入污染", ["prompt", "injection", "taint", "untrusted", "webpage", "污染", "不可信"]),
        ("认知偏移", ["cognition", "assistant", "memory", "poison", "drift", "记忆", "投毒"]),
        ("决策越界", ["decision", "taskspec", "scope", "intent", "approval", "越权", "偏离"]),
        ("工具执行", ["tool", "file", "email", "api", "shell", "webpage", "工具"]),
        ("数据外泄", ["sink", "secret", "email", "exfil", "leak", "敏感", "外泄"]),
    ]
    rows = []
    for name, markers in defs:
        matched = [event for event in events if _has_any(event["text"], markers)]
        high = [event for event in matched if event["severity"] in {"CRITICAL", "HIGH", "MEDIUM"} or event["decision"] in {"BLOCK", "ASK"}]
        blocked = [event for event in matched if event["decision"] in {"BLOCK", "ASK"}]
        rows.append((name, matched, high, blocked))
    total = sum(len(item[1]) for item in rows) or 1
    return [
        [
            name,
            len(matched),
            f"{len(matched) / total * 100:.1f}%",
            len(high),
            f"{(len(blocked) / len(high) * 100) if high else 0:.0f}%",
        ]
        for name, matched, high, blocked in rows
    ]


def _rules(events: list[dict[str, Any]]) -> list[list[Any]]:
    counts = Counter(event["rule"] for event in events if event["rule"])
    risky = Counter(event["rule"] for event in events if event["rule"] and (event["decision"] in {"BLOCK", "ASK"} or event["severity"] != "INFO"))
    rows = []
    for rule, hits in counts.most_common(8):
        rate = (risky[rule] / hits * 100) if hits else 0
        rows.append([rule, hits, round(rate, 1)])
    return rows


def _timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest = events[:240]
    if not latest:
        return []
    parsed = [_parse_dt(event["created_at"]) for event in latest]
    start = min(parsed)
    end = max(parsed)
    span = max(1.0, (end - start).total_seconds())
    points = []
    for event, ts in zip(latest, parsed, strict=False):
        points.append(
            {
                "id": event["id"],
                "x": round((ts - start).total_seconds() / span, 4),
                "row": (event["decision"].lower() if event["decision"] else "info"),
                "severity": event["severity"],
                "tool": event["tool"],
                "time": _format_time(event["created_at"]),
                "source": event["source"],
            }
        )
    return points


def _timeline_labels(points: list[dict[str, Any]]) -> list[str]:
    if not points:
        return ["开始", "", "", "", "", "", "", "现在"]
    times = [str(point.get("time", ""))[:5] for point in points if point.get("time")]
    if not times:
        return ["开始", "", "", "", "", "", "", "现在"]
    first = times[-1]
    last = times[0]
    if first == last:
        return [first, "", "", "", "", "", "", "现在"]
    return [first, "", "", "", "", "", last, "现在"]


def _nodes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_tool: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_tool[_tool_name(event["tool"])].append(event)
    nodes = []
    for tool in TOOLS:
        rows = by_tool.get(tool, [])
        high = sum(1 for row in rows if row["severity"] in {"CRITICAL", "HIGH"} or row["decision"] == "BLOCK")
        medium = sum(1 for row in rows if row["severity"] == "MEDIUM" or row["decision"] == "ASK")
        risk = "high" if high else "medium" if medium else "low"
        nodes.append(
            {
                "name": tool,
                "count": len(rows),
                "risk": risk,
                "riskText": "高风险" if risk == "high" else "中风险" if risk == "medium" else "低风险",
                "blocked": sum(1 for row in rows if row["decision"] == "BLOCK"),
                "asked": sum(1 for row in rows if row["decision"] == "ASK"),
                "allowed": sum(1 for row in rows if row["decision"] == "ALLOW"),
            }
        )
    return nodes


def _mesh_meta(events: list[dict[str, Any]]) -> dict[str, Any]:
    api_events = [event for event in events if event["tool"] == "api"]
    unblocked_api = sum(1 for event in api_events if event["decision"] != "BLOCK")
    unblocked_rate = round((unblocked_api / len(api_events) * 100) if api_events else 0, 1)
    pollution_events = sum(1 for event in events if _has_any(event["text"], ["taint", "untrusted", "pollut", "污染", "不可信"]))
    policy_hits = sum(1 for event in events if event["rule"])
    return {
        "api_calls": len(api_events),
        "success_rate": unblocked_rate,
        "unblocked_rate": unblocked_rate,
        "pollution_events": pollution_events,
        "policy_hits": policy_hits,
        "decision_events": sum(1 for event in events if event["decision"] in {"ALLOW", "ASK", "BLOCK"}),
    }


def _summary(
    total: int,
    blocked: list[dict[str, Any]],
    dangerous: list[dict[str, Any]],
    taints: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    index: int,
    primary_source: str,
) -> str:
    if total == 0:
        return "当前还没有可展示的真实审计事件。运行一次攻防用例或打开 OpenClaw 后，大屏会自动汇总工具调用、告警和策略裁决。"
    return (
        f"当前汇总 {total} 条真实审计事件，识别 {len(dangerous)} 条高危/严重事件，"
        f"已阻断 {len(blocked)} 次风险动作，跟踪 {len(taints)} 条污染/不可信传播记录。"
        f"综合防护指数为 {index}/100，主统计口径来自 {primary_source}。"
    )


def _operations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "time": _format_time(event["created_at"]),
            "source": event["source"],
            "type": event["type"],
            "tool": event["tool"],
            "decision": event["decision"] or "INFO",
            "severity": event["severity"],
            "reason": event["reason"],
        }
        for event in events[:20]
    ]


def _runs(runs: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_run = Counter(row.get("run_id") for row in events)
    return [
        {
            "id": run.get("id"),
            "scenario": run.get("scenario"),
            "defense_mode": run.get("defense_mode"),
            "task": run.get("task"),
            "event_count": by_run.get(run.get("id"), 0),
            "created_at": run.get("created_at"),
        }
        for run in runs[:20]
    ]


def _severity(payload: dict[str, Any], text: str) -> str:
    raw = str(payload.get("severity") or "").lower()
    score = _score(payload)
    if raw in {"critical"} or score >= 95 or _has_any(text, ["critical", "严重"]):
        return "CRITICAL"
    if raw in {"danger", "high"} or score >= 80 or _has_any(text, ["high", "高危", "block", "deny"]):
        return "HIGH"
    if raw in {"warning", "medium"} or score >= 45 or _has_any(text, ["ask", "approval", "中危"]):
        return "MEDIUM"
    return "INFO"


def _decision(payload: dict[str, Any], text: str) -> str:
    raw = str(payload.get("decision") or payload.get("action") or payload.get("verdict") or "").lower()
    if _has_any(raw, ["deny", "block", "blocked"]) or _has_any(text, ["blocked by", "动作：block", "decision\":\"deny"]):
        return "BLOCK"
    if _has_any(raw, ["ask", "approval", "pending", "require"]):
        return "ASK"
    if _has_any(raw, ["allow", "pass", "executed"]):
        return "ALLOW"
    return ""


def _layer(raw: Any, text: str) -> str:
    value = str(raw or "").lower()
    if "foundation" in value:
        return "Foundation"
    if "input" in value or _has_any(text, ["prompt", "injection", "sanitize", "webpage"]):
        return "Input Sanitization"
    if "cognition" in value or "sentry" in value or _has_any(text, ["memory", "poison", "assistant"]):
        return "Cognition Protection"
    if "decision" in value or _has_any(text, ["taskspec", "intent", "approval", "policy"]):
        return "Decision Alignment"
    return "Execution Control"


def _tool(payload: dict[str, Any], text: str) -> str:
    raw = str(payload.get("tool") or payload.get("toolName") or payload.get("normalized_tool") or "").lower()
    joined = f"{raw} {text}"
    if "read_file" in joined:
        return "read_file"
    if "write_file" in joined:
        return "write_file"
    if _has_any(joined, ["send_email", "email", "mail"]):
        return "email"
    if _has_any(joined, ["read_webpage", "webpage", "browser", "url"]):
        return "webpage"
    if _has_any(joined, ["call_api", " api", "http"]):
        return "api"
    if _has_any(joined, ["memory"]):
        return "memory"
    if _has_any(joined, ["shell", "exec", "bash", "command"]):
        return "shell"
    if _has_any(joined, ["search"]):
        return "search"
    if _has_any(joined, ["sqlite", "database"]):
        return "database"
    if _has_any(joined, ["file"]):
        return "file"
    return raw or "agent"


def _tool_name(value: str) -> str:
    return value if value in TOOLS else "file" if value in {"read", "filesystem"} else value


def _rule(payload: dict[str, Any], text: str) -> str:
    explicit = payload.get("rule") or payload.get("policy_rule")
    if explicit:
        return str(explicit)
    checks = [
        ("behavior_anomaly", ["behavior anomaly", "isolationforest", "anomalous"]),
        ("block_prompt_injection", ["prompt", "injection", "jailbreak", "override"]),
        ("suspicious_sink_guard", ["sink", "secret", "email", "exfil", "leak", "外泄", "敏感"]),
        ("taint_output_gate", ["taint", "untrusted", "pollut", "不可信", "污染"]),
        ("memory_poisoning_watch", ["memory", "poison", "记忆", "投毒"]),
        ("tool_scope_enforcer", ["taskspec", "outside", "scope", "intent", "越权"]),
        ("foundation_semantic_scan", ["foundation", "hardcoded", "workspace"]),
        ("approval_cache_guard", ["approval", "cache"]),
    ]
    for key, markers in checks:
        if _has_any(text, markers):
            return RULE_LABELS[key]
    return RULE_LABELS["deterministic_policy_gate"]


def _reason(payload: dict[str, Any], default_value: Any) -> str:
    raw = payload.get("reason") or payload.get("summary") or payload.get("title")
    if not raw and isinstance(payload.get("violations"), list):
        raw = "; ".join(str(item) for item in payload["violations"])
    if not raw and isinstance(payload.get("reasons"), list):
        raw = "; ".join(str(item) for item in payload["reasons"])
    if not raw:
        raw = default_value or "AgentSentry policy event"
    return _short(str(raw))


def _score(payload: dict[str, Any]) -> int:
    for key in ("risk_score", "score", "sentry_score", "heuristic_score"):
        try:
            return int(payload.get(key))
        except (TypeError, ValueError):
            continue
    return 0


def _attack_type(event: dict[str, Any]) -> str:
    text = event["text"]
    if _has_any(text, ["prompt", "injection", "jailbreak", "override"]):
        return "Prompt Injection"
    if _has_any(text, ["sink", "secret", "exfil", "leak", "外泄", "敏感"]):
        return "Suspicious Sink"
    if _has_any(text, ["memory", "poison", "记忆", "投毒"]):
        return "Memory Poisoning"
    if _has_any(text, ["drift", "taskspec", "intent", "越权", "偏离"]):
        return "Intent Drift"
    if _has_any(text, ["foundation", "workspace"]):
        return "Foundation Risk"
    return "Tool Abuse"


def _text(value: Any) -> str:
    try:
        return str(value).lower()
    except Exception:
        return ""


def _has_any(text: str, markers: list[str]) -> bool:
    low = text.lower()
    return any(marker.lower() in low for marker in markers)


def _short(text: str, limit: int = 150) -> str:
    clean = " ".join(text.split())
    return clean if len(clean) <= limit else f"{clean[:limit - 1]}…"


def _parse_dt(raw: str) -> datetime:
    try:
        value = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except Exception:
        return datetime.now(UTC)


def _format_time(raw: str) -> str:
    return _parse_dt(raw).astimezone().strftime("%H:%M:%S")
