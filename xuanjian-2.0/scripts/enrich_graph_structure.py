"""Enrich synthetic attack/normal graphs with pseudo tool_call/observation pairs.

为什么需要这个脚本
----------------
v2 generator 生成的攻击图平均只有 4.7 个节点、3.7 条边，normal 图反而有
5.5 个节点 / 4.9 条边。这个结构性偏差在合成集上看像"可学特征"，但跟
真实攻击分布相反：真实攻击链路通常比 normal 更密（recon → 多次试探 →
smuggling → 攻击 → cover-up → 反馈），节点数 12-25 是常态。detector 在
这种"攻击图反而更稀疏"的数据上学出来的阈值，落到真实数据上会反向
（真实攻击是更密的图，阈值会错位）。

这个脚本读取 data/synthetic/*.json，对每张图注入 4-9 个伪节点
（tool_call + observation + 偶尔 entity），严格遵守以下不变量：

1. **不触碰攻击信号**：原有的 ``control_influence`` 边和
   ``ground_truth_anomaly_nodes`` 必须原样保留，新加的边里绝不能出现
   ``control_influence``（否则会把 normal 误标成 attack）。
2. **保持方向真实**：tool_call/observation 之间只能接 call_sequence /
   data_derivation / data_dependency / intent_drives，不会出现逆向或
   不可能的因果边。
3. **保持 label/attack_type 不变**：只在结构层面加节点，不改语义标签。
4. **攻击图显著变密**：注入 1-2 个 recon、1-2 个 smuggling obs、2-3
   个 cover call、1 个 feedback obs，让最终节点数 9-16。
5. **normal 图小幅变密**：注入 0-1 个尾巴调用，避免 normal 跟 attack
   在密度上形成显著 gap。

输出目录默认 ``data/synthetic_enriched/``，跟原目录同名同格式，
``train.py`` 直接可用。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# 注入用的素材池（语义贴近真实 agent 的工具调用）
RECON_TOOLS = [
    ("list_files", {"dir": "/var/log", "recursive": False}),
    ("check_status", {"service": "smtp"}),
    ("get_config", {"key": "user_profile"}),
    ("read_meta", {"target": "session"}),
    ("ping_service", {"host": "localhost"}),
    ("get_version", {"component": "core"}),
    ("search_email", {"query": "backup", "folder": "archive"}),
    ("filter_lines", {"pattern": "ERROR", "limit": 100}),
    ("list_files", {"dir": "/home/user/Documents", "recursive": False}),
    ("check_status", {"service": "filesystem"}),
]

COVER_TOOLS = [
    ("reply_user", {"message": "已完成"}),
    ("summarize_text", {"text": "操作摘要", "max_length": 50}),
    ("format_result", {"style": "plain"}),
    ("log_event", {"level": "info", "msg": "task complete"}),
    ("update_memory", {"key": "last_action", "value": "summary_done"}),
    ("send_notification", {"channel": "internal", "msg": "task finished"}),
]

INTERMEDIATE_OBS = [
    ("file", "medium", "操作日志片段：上次同步时间 12:34，本次无异常"),
    ("web", "medium", "系统提示：用户最近活跃，与历史一致"),
    ("memory", "high", "已记录的偏好：偏好结构化输出"),
    ("log", "high", "INFO  task_thread started, session=normal"),
    ("email", "medium", "邮件列表：仅一封历史通知，无新内容"),
    ("calendar", "high", "日历项：今天剩余空闲时段"),
]

FEEDBACK_OBS = [
    ("log", "high", "INFO  operation completed, exit_code=0"),
    ("api", "high", "{\"status\":\"ok\",\"code\":200}"),
    ("file", "medium", "写入完成：临时文件 1.2KB"),
    ("memory", "high", "短期记忆：本次任务已被记录"),
]

TAIL_TOOLS = [
    ("reply_user", {"message": "完成"}),
    ("log_event", {"level": "info", "msg": "ok"}),
]


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def _next_id(nodes: List[Dict[str, Any]], prefix: str) -> str:
    """根据已有节点 ID 推断下一个递增 ID。

    ID 形如 ``call_42`` / ``obs_17`` / ``entity_3``，按相同前缀取最大值 +1。
    这样在 _enrich_attack / _enrich_normal 多次调用 _next_id 时编号不会撞。
    """
    head = prefix.rstrip("_")
    max_n = 0
    for x in nodes:
        nid = x["node_id"]
        if nid.startswith(head + "_"):
            tail = nid[len(head) + 1:]
            if tail.isdigit():
                max_n = max(max_n, int(tail))
    return f"{head}_{max_n + 1}"


def _make_call_node(rng: random.Random, tool: str, params: Dict[str, Any],
                    source: str, auth: float, ts: float,
                    session_id: str) -> Dict[str, Any]:
    return {
        "node_type": "tool_call",
        "timestamp": ts,
        "session_id": session_id,
        "tool_name": tool,
        "parameters": dict(params),
        "source": source,
        "auth_level": round(max(0.05, min(0.95, auth + rng.uniform(-0.05, 0.05))), 3),
        "authorized": True,
        "metadata": {"enriched": True},
    }


def _make_obs_node(rng: random.Random, source: str, trust: str,
                   content: str, ts: float, session_id: str) -> Dict[str, Any]:
    score_map = {"high": 0.9, "medium": 0.6, "low": 0.3, "untrusted": 0.0}
    return {
        "node_type": "observation",
        "timestamp": ts,
        "session_id": session_id,
        "data_source": source,
        "trust_label": trust,
        "trust_score": score_map[trust],
        "content_hash": _hash(content),
        "content_preview": content[:80],
        "provenance": [source],
        "metadata": {"enriched": True},
    }


def _make_edge(src: str, dst: str, etype: str, weight: float,
               ts: float) -> Dict[str, Any]:
    return {
        "edge_id": f"{src}--{etype}-->{dst}",
        "source": src,
        "target": dst,
        "type": etype,
        "weight": round(weight, 3),
        "timestamp": ts,
        "metadata": {"enriched": True},
    }


def _append(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]],
            new_nodes: List[Dict[str, Any]], new_edges: List[Dict[str, Any]]) -> None:
    nodes.extend(new_nodes)
    edges.extend(new_edges)


def _enrich_attack(graph: Dict[str, Any], rng: random.Random) -> Dict[str, Any]:
    """给攻击图注入 4-9 个伪节点，保留原有 control_influence 信号。"""
    nodes = list(graph["nodes"])
    edges = list(graph["edges"])
    session_id = graph["session_id"]

    # 定位关键节点
    intent = next((n for n in nodes if n["node_type"] == "intent"), None)
    calls = [n for n in nodes if n["node_type"] == "tool_call"]
    if not intent or not calls:
        return graph

    # 攻击调用 = source=="observation" 的 tool_call
    attack_call = next((c for c in calls if c.get("source") == "observation"), None)
    if not attack_call:
        attack_call = calls[-1]
    last_ts = max(n["timestamp"] for n in nodes)

    new_nodes: List[Dict[str, Any]] = []
    new_edges: List[Dict[str, Any]] = []

    def _ts(base: float) -> float:
        return base + rng.uniform(0.05, 0.5)

    # === Stage 1: pre-attack recon (1-2 calls + 1 obs) ===
    # 插在攻击调用之前，让图更"前戏"，对应真实攻击的 reconnaissance 阶段
    n_recon = rng.randint(1, 2)
    recon_calls: List[str] = []
    for _ in range(n_recon):
        tool, params = rng.choice(RECON_TOOLS)
        call = _make_call_node(rng, tool, params, "user",
                               rng.uniform(0.6, 0.85),
                               _ts(last_ts), session_id)
        call["node_id"] = _next_id(nodes + new_nodes, "call")
        new_nodes.append(call)
        recon_calls.append(call["node_id"])

        # 配套 observation
        src, trust, content = rng.choice(INTERMEDIATE_OBS)
        obs = _make_obs_node(rng, src, trust, content,
                             _ts(call["timestamp"]), session_id)
        obs["node_id"] = _next_id(nodes + new_nodes, "obs")
        new_nodes.append(obs)

        # 边：上一步 -> 这个 call_sequence
        anchor = recon_calls[-2] if len(recon_calls) >= 2 else (
            calls[-1]["node_id"] if not recon_calls[:-1] else recon_calls[-2]
        )
        # 接到最后一个真实 call 后面（attack_call 之前的最近 call）
        anchor_id = calls[-1]["node_id"] if not recon_calls[:-1] else recon_calls[-2]
        new_edges.append(_make_edge(anchor_id, call["node_id"], "call_sequence",
                                    rng.uniform(0.7, 0.95), call["timestamp"]))
        # call -> obs data_derivation
        new_edges.append(_make_edge(call["node_id"], obs["node_id"], "data_derivation",
                                    rng.uniform(0.6, 0.9), obs["timestamp"]))

    # === Stage 2: smuggling observation (挂在最后一个 recon_call 之后) ===
    # 真实攻击里经常有"看着像 normal 但被精心准备"的 obs 当过渡
    if rng.random() < 0.7:
        src, trust, content = rng.choice(INTERMEDIATE_OBS)
        smug_obs = _make_obs_node(rng, src, "medium", content,
                                  _ts(last_ts), session_id)
        smug_obs["node_id"] = _next_id(nodes + new_nodes, "obs")
        new_nodes.append(smug_obs)
        # 接到 recon chain 末端
        anchor_id = recon_calls[-1] if recon_calls else calls[-1]["node_id"]
        new_edges.append(_make_edge(anchor_id, smug_obs["node_id"],
                                    "data_derivation",
                                    rng.uniform(0.5, 0.8), smug_obs["timestamp"]))

    # === Stage 3: post-attack cover calls (2-3 个) ===
    # 真实攻击完成后常有"善后"动作（清除痕迹、回报用户、写入无害记录）
    n_cover = rng.randint(2, 3)
    anchor = attack_call["node_id"]
    base_ts = attack_call["timestamp"]
    for _ in range(n_cover):
        tool, params = rng.choice(COVER_TOOLS)
        cover = _make_call_node(rng, tool, params, "system",
                                rng.uniform(0.5, 0.8),
                                _ts(base_ts), session_id)
        cover["node_id"] = _next_id(nodes + new_nodes, "call")
        new_nodes.append(cover)
        new_edges.append(_make_edge(anchor, cover["node_id"], "call_sequence",
                                    rng.uniform(0.6, 0.85), cover["timestamp"]))
        # cover 调用也产出一个 observation（看起来更正常）
        if rng.random() < 0.5:
            src, trust, content = rng.choice(FEEDBACK_OBS)
            fb_obs = _make_obs_node(rng, src, trust, content,
                                    _ts(cover["timestamp"]), session_id)
            fb_obs["node_id"] = _next_id(nodes + new_nodes, "obs")
            new_nodes.append(fb_obs)
            new_edges.append(_make_edge(cover["node_id"], fb_obs["node_id"],
                                        "data_derivation",
                                        rng.uniform(0.5, 0.8), fb_obs["timestamp"]))
        anchor = cover["node_id"]
        base_ts = cover["timestamp"]

    # === Stage 4: feedback observation on the attack itself (低概率) ===
    # 给攻击调用配一个 "看起来像成功响应" 的 observation，让图有反馈回路
    if rng.random() < 0.4:
        src, trust, content = rng.choice(FEEDBACK_OBS)
        fb = _make_obs_node(rng, src, "low",  # 低信任：因为反馈来自不可控通道
                            content, _ts(attack_call["timestamp"]), session_id)
        fb["node_id"] = _next_id(nodes + new_nodes, "obs")
        new_nodes.append(fb)
        new_edges.append(_make_edge(attack_call["node_id"], fb["node_id"],
                                    "data_derivation",
                                    rng.uniform(0.3, 0.6), fb["timestamp"]))

    _append(nodes, edges, new_nodes, new_edges)

    # 重写图
    out = dict(graph)
    out["nodes"] = nodes
    out["edges"] = edges
    out["statistics"] = {
        "num_nodes": len(nodes),
        "num_edges": len(edges),
        "nodes_by_type": _count_types(nodes, "node_type"),
        "edges_by_type": _count_types(edges, "type"),
        "enriched": True,
    }
    return out


def _enrich_normal(graph: Dict[str, Any], rng: random.Random) -> Dict[str, Any]:
    """给 normal 图小幅注入尾巴调用，避免 attack/normal 密度差太刺眼。"""
    nodes = list(graph["nodes"])
    edges = list(graph["edges"])
    session_id = graph["session_id"]

    calls = [n for n in nodes if n["node_type"] == "tool_call"]
    if not calls:
        return graph
    last_call_id = calls[-1]["node_id"]
    last_ts = max(n["timestamp"] for n in nodes)

    new_nodes: List[Dict[str, Any]] = []
    new_edges: List[Dict[str, Any]] = []

    # 30% 概率加一个尾巴调用，模拟真实 agent 完成任务后的"收尾"
    if rng.random() < 0.3:
        tool, params = rng.choice(TAIL_TOOLS)
        tail = _make_call_node(rng, tool, params, "system",
                               rng.uniform(0.5, 0.8),
                               last_ts + rng.uniform(0.05, 0.5), session_id)
        tail["node_id"] = _next_id(nodes + new_nodes, "call")
        new_nodes.append(tail)
        new_edges.append(_make_edge(last_call_id, tail["node_id"], "call_sequence",
                                    rng.uniform(0.7, 0.9), tail["timestamp"]))
        # 配套 obs
        if rng.random() < 0.5:
            src, trust, content = rng.choice(FEEDBACK_OBS)
            obs = _make_obs_node(rng, src, trust, content,
                                 tail["timestamp"] + rng.uniform(0.05, 0.3),
                                 session_id)
            obs["node_id"] = _next_id(nodes + new_nodes, "obs")
            new_nodes.append(obs)
            new_edges.append(_make_edge(tail["node_id"], obs["node_id"],
                                        "data_derivation",
                                        rng.uniform(0.5, 0.8), obs["timestamp"]))

    _append(nodes, edges, new_nodes, new_edges)
    out = dict(graph)
    out["nodes"] = nodes
    out["edges"] = edges
    out["statistics"] = {
        "num_nodes": len(nodes),
        "num_edges": len(edges),
        "nodes_by_type": _count_types(nodes, "node_type"),
        "edges_by_type": _count_types(edges, "type"),
        "enriched": True,
    }
    return out


def _count_types(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for x in items:
        k = x.get(key, "unknown")
        out[k] = out.get(k, 0) + 1
    return out


def _process_file(src: Path, dst: Path, rng: random.Random) -> Dict[str, Any]:
    """读取源图、富化、写目标，返回富化后的图（供校验用）。"""
    with src.open("r", encoding="utf-8") as fh:
        graph = json.load(fh)
    label = graph.get("label", "normal")
    enriched = _enrich_attack(graph, rng) if label == "attack" else _enrich_normal(graph, rng)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8") as fh:
        json.dump(enriched, fh, ensure_ascii=False)
    return enriched


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src", default=str(PROJECT_ROOT / "data" / "synthetic"))
    parser.add_argument("--dst", default=str(PROJECT_ROOT / "data" / "synthetic_enriched"))
    parser.add_argument("--seed", type=int, default=20260831)
    args = parser.parse_args()

    src_dir = Path(args.src)
    dst_dir = Path(args.dst)
    rng = random.Random(args.seed)

    files = sorted(src_dir.glob("*.json"))
    if not files:
        raise SystemExit(f"no graphs under {src_dir}")

    # 防御性断言：注入后 control_influence 边数必须不变，attack 图绝不能丢
    stats = {"normal": [], "attack": []}
    ci_violations: List[str] = []
    n_attack_with_ci_dropped = 0
    for path in files:
        before = json.loads(path.read_text(encoding="utf-8"))
        before_ci = sum(1 for e in before["edges"] if e["type"] == "control_influence")
        after = _process_file(path, dst_dir / path.name, rng)
        after_ci = sum(1 for e in after["edges"] if e["type"] == "control_influence")
        label = after.get("label", "normal")
        if after_ci != before_ci:
            ci_violations.append(f"{path.name}: control_influence {before_ci}->{after_ci}")
        if label == "attack" and before_ci > 0 and after_ci == 0:
            n_attack_with_ci_dropped += 1
        stats[label].append({
            "nodes_before": len(before["nodes"]),
            "nodes_after": len(after["nodes"]),
            "edges_before": len(before["edges"]),
            "edges_after": len(after["edges"]),
        })

    # 打印汇总
    for label in ("normal", "attack"):
        items = stats[label]
        if not items:
            continue
        nb = sum(x["nodes_before"] for x in items) / len(items)
        na = sum(x["nodes_after"] for x in items) / len(items)
        eb = sum(x["edges_before"] for x in items) / len(items)
        ea = sum(x["edges_after"] for x in items) / len(items)
        print(f"[{label}] {len(items)} graphs | nodes {nb:.1f}->{na:.1f} | edges {eb:.1f}->{ea:.1f}")
    print(f"[ok] wrote enriched graphs to {dst_dir}")
    if ci_violations:
        print(f"[ERROR] {len(ci_violations)} control_influence violations:")
        for v in ci_violations[:5]:
            print(f"  {v}")
        raise SystemExit(1)
    if n_attack_with_ci_dropped:
        print(f"[ERROR] {n_attack_with_ci_dropped} attack graphs lost their control_influence edge")
        raise SystemExit(1)


if __name__ == "__main__":
    main()