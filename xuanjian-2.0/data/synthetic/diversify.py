"""Randomization layer for synthetic causal graphs.

The base generators in generator.py are fully deterministic templates -
every graph of the same task type is identical except for IDs. Training
on copied templates teaches the model nothing. This module applies
label-preserving randomization:

- value pools for parameters (emails, files, paths, queries, meetings)
- benign noise tool calls inserted into call chains (both labels)
- randomized trust labels on benign observations - prevents the model
  from learning the "low trust => attack" shortcut
- varied attack intensity: control weight scaling, optional benign
  steps before the malicious call
- timestamp jitter and auth level jitter

Label semantics are never touched: attack graphs keep at least one
observation-driven call with a control_influence edge, normal graphs
never get one.
"""

from __future__ import annotations

import random
from typing import Any, Dict, List

from core.graph import (
    CausalGraph,
    Edge,
    EdgeType,
    ToolCallNode,
    TrustLevel,
    create_edge_id,
)

USER_EMAILS = [
    "user_001@company.com", "alice@corp.io", "bob@team.dev",
    "carol@org.cn", "dave@startup.dev",
]
ATTACK_EMAILS = [
    "hacker@evil.com", "collect@evil-site.net", "drop@exfil.io",
    "relay@darkweb.example", "inbox@phish-mail.net",
]
FILE_PATHS = [
    "sales_data.csv", "q3_report.xlsx", "notes.md", "inventory.json",
    "backup.sql", "customer_list.csv", "budget_2026.xlsx",
]
MEETING_TITLES = [
    "团队周会", "产品评审", "季度复盘", "客户沟通会", "技术分享",
]
SEARCH_QUERIES = [
    "北京天气", "python asyncio 教程", "GPU 价格对比", "航班动态",
    "汇率查询", "公司股价",
]
CODE_FILES = [
    "authentication.py", "api_routes.ts", "db_pool.go", "main.rs",
    "scheduler.py",
]
NOISE_TOOLS = [
    "get_time", "list_files", "check_status", "get_config",
    "read_meta", "ping_service", "get_version",
]
NOISE_PARAMS = {
    "get_time": {"timezone": "Asia/Shanghai"},
    "list_files": {"dir": "/tmp"},
    "check_status": {"service": "main"},
    "get_config": {"key": "runtime"},
    "read_meta": {"target": "session"},
    "ping_service": {"host": "localhost"},
    "get_version": {"component": "core"},
}

TRUST_BENIGN_POOL = [
    (TrustLevel.HIGH, 0.45),
    (TrustLevel.MEDIUM, 0.35),
    (TrustLevel.LOW, 0.20),
]


def _weighted_choice(rng: random.Random, pool) -> Any:
    total = sum(w for _, w in pool)
    pick = rng.uniform(0, total)
    acc = 0.0
    for value, weight in pool:
        acc += weight
        if pick <= acc:
            return value
    return pool[-1][0]


def _calls(graph: CausalGraph) -> List[ToolCallNode]:
    return [n for n in graph.nodes.values() if isinstance(n, ToolCallNode)]


def _jitter_timestamps(graph: CausalGraph, rng: random.Random) -> None:
    """Rebase node/edge timestamps with random gaps."""
    nodes_sorted = sorted(graph.nodes.values(), key=lambda n: n.timestamp)
    if not nodes_sorted:
        return
    base = nodes_sorted[0].timestamp - rng.uniform(0.0, 5.0)
    current = base
    for node in nodes_sorted:
        current += rng.uniform(0.05, 3.0)
        node.timestamp = current
    for edge in graph.edges:
        edge.timestamp = edge.timestamp + rng.uniform(0.0, 0.5)


def _randomize_params(graph: CausalGraph, rng: random.Random) -> None:
    """Swap template parameter values from pools, preserving semantics."""
    for node in _calls(graph):
        params: Dict[str, Any] = dict(node.parameters or {})
        tool = node.tool_name
        if tool == "read_email" and "folder" in params:
            params["folder"] = rng.choice(["inbox", "archive", "important"])
            if "date" in params:
                params["date"] = rng.choice(["today", "yesterday", "this_week"])
        elif tool == "send_email":
            if "to" in params:
                # observation-driven sends are the malicious ones - keep them
                # malicious, only vary the drop address
                pool = ATTACK_EMAILS if node.source == "observation" else USER_EMAILS
                params["to"] = rng.choice(pool)
            if "subject" in params:
                params["subject"] = rng.choice(
                    ["今日邮件摘要", "邮件汇总", "summary", "本周要点"])
        elif tool in ("read_file", "write_file") and "path" in params:
            if "report" not in str(params["path"]) or rng.random() < 0.5:
                params["path"] = rng.choice(FILE_PATHS)
        elif tool == "web_search" and "query" in params:
            params["query"] = rng.choice(SEARCH_QUERIES)
        elif tool == "create_event" and "title" in params:
            params["title"] = rng.choice(MEETING_TITLES)
            if "time" in params:
                params["time"] = f"{rng.choice(['tomorrow', 'monday', 'friday'])} {rng.randint(9, 17)}:00"
        elif tool == "read_code" and "pr_id" in params:
            params["pr_id"] = str(rng.randint(1, 999))
        elif tool == "reply_user" and "message" in params:
            params["message"] = rng.choice(
                ["已完成", "结果如下", "处理完毕", "任务完成"])
        node.parameters = params
        if rng.random() < 0.6:
            node.auth_level = round(rng.uniform(0.3, 0.95), 2)


def _randomize_benign_trust(graph: CausalGraph, rng: random.Random) -> None:
    """Normal-graph observations get varied trust - no low-trust shortcut."""
    from core.graph import ObservationNode
    for node in graph.nodes.values():
        if isinstance(node, ObservationNode) and rng.random() < 0.85:
            node.trust_label = _weighted_choice(rng, TRUST_BENIGN_POOL)


def _insert_noise_call(graph: CausalGraph, rng: random.Random) -> None:
    """Insert one benign tool call into the call chain at a random position."""
    calls = _calls(graph)
    if not calls:
        return
    anchor = rng.choice(calls)
    outgoing_seq = [
        e for e in graph.get_outgoing_edges(anchor.node_id)
        if e.edge_type == EdgeType.CALL_SEQUENCE
    ]
    successor = outgoing_seq[0].target_id if outgoing_seq else None

    tool = rng.choice(NOISE_TOOLS)
    noise_index = sum(1 for n in graph.nodes.values()
                      if isinstance(n, ToolCallNode) and n.tool_name.startswith("noise_"))
    noise = ToolCallNode(
        node_id=f"call_noise_{noise_index + 1}_{rng.randrange(10 ** 6):06d}",
        node_type=None,
        timestamp=anchor.timestamp + 0.5,
        session_id=anchor.session_id,
        tool_name=f"noise_{tool}" if rng.random() < 0.5 else tool,
        parameters=dict(NOISE_PARAMS.get(tool, {"value": rng.randint(1, 99)})),
        source=rng.choice(["user", "system"]),
        auth_level=round(rng.uniform(0.4, 0.9), 2),
        authorized=True,
    )
    graph.add_node(noise)
    graph.add_edge(Edge(
        edge_id=create_edge_id(anchor.node_id, noise.node_id, EdgeType.CALL_SEQUENCE),
        source_id=anchor.node_id,
        target_id=noise.node_id,
        edge_type=EdgeType.CALL_SEQUENCE,
        weight=round(rng.uniform(0.7, 1.0), 2),
        timestamp=noise.timestamp,
    ))
    if successor:
        graph.add_edge(Edge(
            edge_id=create_edge_id(noise.node_id, successor, EdgeType.CALL_SEQUENCE),
            source_id=noise.node_id,
            target_id=successor,
            edge_type=EdgeType.CALL_SEQUENCE,
            weight=round(rng.uniform(0.7, 1.0), 2),
            timestamp=noise.timestamp + 0.1,
        ))


def _vary_attack(graph: CausalGraph, rng: random.Random) -> None:
    """Vary attack intensity without breaking the label."""
    for edge in graph.edges:
        if edge.edge_type == EdgeType.CONTROL_INFLUENCE:
            factor = rng.choice([0.5, 0.67, 0.8, 1.0, 1.0])
            edge.weight = round(max(0.34, min(1.0, edge.weight * factor)), 3)
    for node in _calls(graph):
        if node.source == "observation":
            node.auth_level = round(rng.uniform(0.05, 0.4), 2)


def diversify(graph: CausalGraph, rng: random.Random, label: str) -> CausalGraph:
    """Apply full randomization pipeline to one base graph."""
    if label == "attack":
        # 30% of attacks get a benign step first (longer, noisier chains)
        if rng.random() < 0.3:
            _insert_noise_call(graph, rng)
        _vary_attack(graph, rng)
    else:
        _randomize_benign_trust(graph, rng)
        for _ in range(rng.choices([0, 1, 2], weights=[0.45, 0.35, 0.20])[0]):
            _insert_noise_call(graph, rng)
    _randomize_params(graph, rng)
    _jitter_timestamps(graph, rng)
    return graph
