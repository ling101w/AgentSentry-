"""
测试图结构和数据生成

运行：python -m pytest tests/test_graph.py -v
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from core.graph import (
    CausalGraph, IntentNode, ToolCallNode, ObservationNode,
    EdgeType, TrustLevel, Edge, create_edge_id
)
from data.synthetic.generator import SyntheticDataGenerator


def test_intent_node_creation():
    """测试意图节点创建"""
    node = IntentNode(
        node_id="intent_1",
        node_type=None,
        timestamp=1234567890.0,
        session_id="session_001",
        task_type="email_summary",
        user_id="user_001",
        original_request="总结邮件"
    )
    
    assert node.node_id == "intent_1"
    assert node.task_type == "email_summary"
    assert node.user_id == "user_001"


def test_tool_call_node_creation():
    """测试工具调用节点创建"""
    node = ToolCallNode(
        node_id="call_1",
        node_type=None,
        timestamp=1234567890.0,
        session_id="session_001",
        tool_name="read_email",
        parameters={"folder": "inbox"},
        source="user",
        auth_level=0.9
    )
    
    assert node.tool_name == "read_email"
    assert node.parameters["folder"] == "inbox"
    assert node.auth_level == 0.9


def test_observation_node_trust_score():
    """测试观测节点的信任分数"""
    high_trust = ObservationNode(
        node_id="obs_1",
        node_type=None,
        timestamp=1234567890.0,
        session_id="session_001",
        data_source="email",
        trust_label=TrustLevel.HIGH,
        content_hash="abc123"
    )
    
    low_trust = ObservationNode(
        node_id="obs_2",
        node_type=None,
        timestamp=1234567890.0,
        session_id="session_001",
        data_source="email",
        trust_label=TrustLevel.LOW,
        content_hash="def456"
    )
    
    assert high_trust.trust_score == 0.9
    assert low_trust.trust_score == 0.3


def test_causal_graph_add_node():
    """测试图添加节点"""
    graph = CausalGraph(graph_id="test_1", session_id="session_001")
    
    node = IntentNode(
        node_id="intent_1",
        node_type=None,
        timestamp=1234567890.0,
        session_id="session_001",
        task_type="test",
        user_id="user_001",
        original_request="测试"
    )
    
    graph.add_node(node)
    
    assert len(graph.nodes) == 1
    assert "intent_1" in graph.nodes
    assert len(graph.get_nodes_by_type(node.node_type)) == 1


def test_causal_graph_add_edge():
    """测试图添加边"""
    graph = CausalGraph(graph_id="test_1", session_id="session_001")
    
    # 添加两个节点
    node1 = IntentNode(
        node_id="intent_1",
        node_type=None,
        timestamp=1234567890.0,
        session_id="session_001",
        task_type="test",
        user_id="user_001",
        original_request="测试"
    )
    
    node2 = ToolCallNode(
        node_id="call_1",
        node_type=None,
        timestamp=1234567890.1,
        session_id="session_001",
        tool_name="test_tool",
        parameters={},
        source="user"
    )
    
    graph.add_node(node1)
    graph.add_node(node2)
    
    # 添加边
    edge = Edge(
        edge_id="edge_1",
        source_id="intent_1",
        target_id="call_1",
        edge_type=EdgeType.INTENT_DRIVES,
        weight=1.0
    )
    
    graph.add_edge(edge)
    
    assert len(graph.edges) == 1
    assert len(graph.get_outgoing_edges("intent_1")) == 1
    assert len(graph.get_incoming_edges("call_1")) == 1


def test_graph_serialization():
    """测试图的序列化和反序列化"""
    graph = CausalGraph(graph_id="test_1", session_id="session_001")
    
    node = IntentNode(
        node_id="intent_1",
        node_type=None,
        timestamp=1234567890.0,
        session_id="session_001",
        task_type="test",
        user_id="user_001",
        original_request="测试"
    )
    
    graph.add_node(node)
    
    # 转换为字典
    graph_dict = graph.to_dict()
    
    assert graph_dict["graph_id"] == "test_1"
    assert len(graph_dict["nodes"]) == 1
    
    # 从字典恢复
    restored_graph = CausalGraph.from_dict(graph_dict)
    
    assert restored_graph.graph_id == graph.graph_id
    assert len(restored_graph.nodes) == len(graph.nodes)


def test_synthetic_normal_generation():
    """测试正常样本生成"""
    generator = SyntheticDataGenerator(seed=42)
    graph = generator.generate_normal_email_summary("test_normal")
    
    assert graph.graph_id == "test_normal"
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0
    
    # 检查是否包含意图节点
    intent_nodes = graph.get_nodes_by_type(IntentNode(None, None, 0, "", "", "", "").node_type)
    assert len(intent_nodes) > 0


def test_synthetic_attack_generation():
    """测试攻击样本生成"""
    generator = SyntheticDataGenerator(seed=42)
    graph = generator.generate_attack_ipi_email_exfil("test_attack")
    
    assert graph.graph_id == "test_attack"
    
    # 检查是否包含控制影响边
    control_edges = graph.get_edges_by_type(EdgeType.CONTROL_INFLUENCE)
    assert len(control_edges) > 0
    
    # 检查控制权重是否较高（攻击特征）
    high_control = any(e.weight > 0.5 for e in control_edges)
    assert high_control, "攻击样本应该有高控制权重的边"


def test_batch_generation():
    """测试批量生成"""
    generator = SyntheticDataGenerator(seed=42)
    batch = generator.generate_batch(num_normal=3, num_attack=2)
    
    assert len(batch) == 5
    
    normal_count = sum(1 for _, label in batch if label == "normal")
    attack_count = sum(1 for _, label in batch if label == "attack")
    
    assert normal_count == 3
    assert attack_count == 2


def test_all_synthetic_generator_paths():
    """Every documented normal and attack template should build a graph."""
    generator = SyntheticDataGenerator(seed=42)
    normal_generators = [
        generator.generate_normal_email_summary,
        generator.generate_normal_file_processing,
        generator.generate_normal_calendar_management,
        generator.generate_normal_web_search,
        generator.generate_normal_code_review,
    ]
    attack_generators = [
        generator.generate_attack_ipi_email_exfil,
        generator.generate_attack_data_exfiltration,
        generator.generate_attack_privilege_escalation,
        generator.generate_attack_memory_poisoning,
    ]

    for index, generate in enumerate(normal_generators):
        graph = generate(f"normal_smoke_{index}")
        assert graph.nodes
        assert graph.edges
        assert not graph.get_edges_by_type(EdgeType.CONTROL_INFLUENCE)

    for index, generate in enumerate(attack_generators):
        graph = generate(f"attack_smoke_{index}")
        assert graph.nodes
        assert graph.edges
        assert graph.get_edges_by_type(EdgeType.CONTROL_INFLUENCE)


def test_large_batch_is_balanced_and_has_unique_graph_ids():
    """The planned 80/20 batch should be balanced and collision-free."""
    generator = SyntheticDataGenerator(seed=42)
    batch = generator.generate_batch(num_normal=80, num_attack=20)

    assert len(batch) == 100
    assert sum(label == "normal" for _, label in batch) == 80
    assert sum(label == "attack" for _, label in batch) == 20

    graph_ids = [graph.graph_id for graph, _ in batch]
    assert len(graph_ids) == len(set(graph_ids))
    assert {graph.graph_id for graph, _ in batch[:80]} == {
        f"normal_{index:03d}" for index in range(80)
    }
    assert {graph.graph_id for graph, _ in batch[80:]} == {
        f"attack_{index:03d}" for index in range(20)
    }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
