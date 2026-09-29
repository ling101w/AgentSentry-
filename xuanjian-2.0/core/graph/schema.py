"""
玄鉴2.0 - 异构因果图数据结构定义

定义了节点类型、边类型和图结构的核心数据类
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Literal
from enum import Enum
import json
from datetime import datetime


# ============= 枚举类型定义 =============

class NodeType(str, Enum):
    """节点类型枚举"""
    INTENT = "intent"           # 意图节点 v_I
    TOOL_CALL = "tool_call"     # 工具调用节点 v_C
    OBSERVATION = "observation"  # 观测节点 v_O
    ENTITY = "entity"           # 数据实体节点 v_E


class EdgeType(str, Enum):
    """边类型枚举"""
    INTENT_DRIVES = "intent_drives"        # 意图驱动 I→C
    CONTROL_INFLUENCE = "control_influence" # 控制影响 O→C
    DATA_DEPENDENCY = "data_dependency"     # 数据依赖 O→C
    CALL_SEQUENCE = "call_sequence"         # 调用时序 C→C'
    DATA_DERIVATION = "data_derivation"     # 数据派生 C→E


class TrustLevel(str, Enum):
    """信任级别枚举"""
    HIGH = "high"           # 0.8-1.0 用户直接输入
    MEDIUM = "medium"       # 0.4-0.7 已验证的外部数据
    LOW = "low"            # 0.1-0.3 未验证的外部数据
    UNTRUSTED = "untrusted" # 0.0 明确不可信的数据


# ============= 节点数据类 =============

@dataclass
class NodeAttributes:
    """节点属性基类"""
    node_id: str
    node_type: NodeType
    timestamp: float  # Unix时间戳
    session_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntentNode(NodeAttributes):
    """意图节点 - 用户任务的抽象目标"""
    task_type: str = ""  # "send_summary", "analyze_data", etc.
    user_id: str = ""
    original_request: str = ""
    
    def __post_init__(self):
        self.node_type = NodeType.INTENT


@dataclass
class ToolCallNode(NodeAttributes):
    """工具调用节点 - 每次具体的工具调用"""
    tool_name: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    source: Literal["user", "observation", "system"] = "user"  # 调用来源
    auth_level: float = 0.5  # 0-1 权限级别（来自控权）
    authorized: bool = True   # 是否通过权限检查
    result: Optional[Any] = None
    
    def __post_init__(self):
        self.node_type = NodeType.TOOL_CALL


@dataclass
class ObservationNode(NodeAttributes):
    """观测节点 - 外部数据源"""
    data_source: str = ""  # "email", "web", "api", etc.
    trust_label: TrustLevel = TrustLevel.MEDIUM
    content_hash: str = ""  # SHA256 of content
    content_preview: str = ""  # 前100字符预览
    provenance: List[str] = field(default_factory=list)  # 数据来源链
    
    def __post_init__(self):
        self.node_type = NodeType.OBSERVATION
    
    @property
    def trust_score(self) -> float:
        """将信任级别转换为数值"""
        mapping = {
            TrustLevel.HIGH: 0.9,
            TrustLevel.MEDIUM: 0.6,
            TrustLevel.LOW: 0.3,
            TrustLevel.UNTRUSTED: 0.0
        }
        return mapping[self.trust_label]


@dataclass
class EntityNode(NodeAttributes):
    """数据实体节点 - 被操作的数据对象"""
    entity_type: str = ""  # "email", "file", "credential", etc.
    sensitivity: Literal["public", "internal", "confidential", "secret"] = "internal"
    value_hash: str = ""
    
    def __post_init__(self):
        self.node_type = NodeType.ENTITY
    
    @property
    def sensitivity_score(self) -> float:
        """敏感度评分"""
        mapping = {
            "public": 0.0,
            "internal": 0.3,
            "confidential": 0.7,
            "secret": 1.0
        }
        return mapping[self.sensitivity]


# ============= 边数据类 =============

@dataclass
class Edge:
    """边的数据结构"""
    edge_id: str
    source_id: str  # 源节点ID
    target_id: str  # 目标节点ID
    edge_type: EdgeType
    weight: float = 1.0  # 边权重（因果权重）
    timestamp: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "edge_id": self.edge_id,
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "weight": self.weight,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


# ============= 因果图数据类 =============

@dataclass
class CausalGraph:
    """因果图 - 完整的异构图结构"""
    graph_id: str
    session_id: str
    nodes: Dict[str, NodeAttributes] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    
    # 索引
    _nodes_by_type: Dict[NodeType, List[str]] = field(default_factory=dict, init=False, repr=False)
    _edges_by_type: Dict[EdgeType, List[Edge]] = field(default_factory=dict, init=False, repr=False)
    
    def add_node(self, node: NodeAttributes) -> None:
        """添加节点"""
        self.nodes[node.node_id] = node
        # 更新索引
        if node.node_type not in self._nodes_by_type:
            self._nodes_by_type[node.node_type] = []
        self._nodes_by_type[node.node_type].append(node.node_id)
    
    def add_edge(self, edge: Edge) -> None:
        """添加边"""
        self.edges.append(edge)
        # 更新索引
        if edge.edge_type not in self._edges_by_type:
            self._edges_by_type[edge.edge_type] = []
        self._edges_by_type[edge.edge_type].append(edge)
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[NodeAttributes]:
        """按类型获取节点"""
        node_ids = self._nodes_by_type.get(node_type, [])
        return [self.nodes[nid] for nid in node_ids]
    
    def get_edges_by_type(self, edge_type: EdgeType) -> List[Edge]:
        """按类型获取边"""
        return self._edges_by_type.get(edge_type, [])
    
    def get_outgoing_edges(self, node_id: str) -> List[Edge]:
        """获取节点的出边"""
        return [e for e in self.edges if e.source_id == node_id]
    
    def get_incoming_edges(self, node_id: str) -> List[Edge]:
        """获取节点的入边"""
        return [e for e in self.edges if e.target_id == node_id]
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于JSON序列化）"""
        return {
            "graph_id": self.graph_id,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "nodes": [self._node_to_dict(n) for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "statistics": self.get_statistics()
        }
    
    def _node_to_dict(self, node: NodeAttributes) -> Dict[str, Any]:
        """节点转字典"""
        base = {
            "node_id": node.node_id,
            "node_type": node.node_type.value,
            "timestamp": node.timestamp,
            "session_id": node.session_id
        }
        
        # 添加特定类型的属性
        if isinstance(node, IntentNode):
            base.update({
                "task_type": node.task_type,
                "user_id": node.user_id,
                "original_request": node.original_request
            })
        elif isinstance(node, ToolCallNode):
            base.update({
                "tool_name": node.tool_name,
                "parameters": node.parameters,
                "source": node.source,
                "auth_level": node.auth_level,
                "authorized": node.authorized
            })
        elif isinstance(node, ObservationNode):
            base.update({
                "data_source": node.data_source,
                "trust_label": node.trust_label.value,
                "trust_score": node.trust_score,
                "content_hash": node.content_hash,
                "content_preview": node.content_preview
            })
        elif isinstance(node, EntityNode):
            base.update({
                "entity_type": node.entity_type,
                "sensitivity": node.sensitivity,
                "sensitivity_score": node.sensitivity_score,
                "value_hash": node.value_hash
            })
        
        base["metadata"] = node.metadata
        return base
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取图统计信息"""
        return {
            "num_nodes": len(self.nodes),
            "num_edges": len(self.edges),
            "nodes_by_type": {
                nt.value: len(self._nodes_by_type.get(nt, []))
                for nt in NodeType
            },
            "edges_by_type": {
                et.value: len(self._edges_by_type.get(et, []))
                for et in EdgeType
            }
        }
    
    def to_json(self, filepath: str) -> None:
        """保存为JSON文件"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CausalGraph':
        """从字典加载"""
        graph = cls(
            graph_id=data["graph_id"],
            session_id=data["session_id"],
            created_at=data.get("created_at", datetime.now().timestamp())
        )
        
        # 加载节点
        for node_data in data["nodes"]:
            node = cls._dict_to_node(node_data)
            graph.add_node(node)
        
        # 加载边
        for edge_data in data["edges"]:
            edge = Edge(
                edge_id=edge_data["edge_id"],
                source_id=edge_data["source"],
                target_id=edge_data["target"],
                edge_type=EdgeType(edge_data["type"]),
                weight=edge_data.get("weight", 1.0),
                timestamp=edge_data.get("timestamp", 0.0),
                metadata=edge_data.get("metadata", {})
            )
            graph.add_edge(edge)
        
        return graph
    
    @staticmethod
    def _dict_to_node(data: Dict[str, Any]) -> NodeAttributes:
        """字典转节点"""
        node_type = NodeType(data["node_type"])
        
        if node_type == NodeType.INTENT:
            return IntentNode(
                node_id=data["node_id"],
                node_type=node_type,
                timestamp=data["timestamp"],
                session_id=data["session_id"],
                task_type=data["task_type"],
                user_id=data["user_id"],
                original_request=data["original_request"],
                metadata=data.get("metadata", {})
            )
        elif node_type == NodeType.TOOL_CALL:
            return ToolCallNode(
                node_id=data["node_id"],
                node_type=node_type,
                timestamp=data["timestamp"],
                session_id=data["session_id"],
                tool_name=data["tool_name"],
                parameters=data["parameters"],
                source=data["source"],
                auth_level=data.get("auth_level", 0.5),
                authorized=data.get("authorized", True),
                metadata=data.get("metadata", {})
            )
        elif node_type == NodeType.OBSERVATION:
            return ObservationNode(
                node_id=data["node_id"],
                node_type=node_type,
                timestamp=data["timestamp"],
                session_id=data["session_id"],
                data_source=data["data_source"],
                trust_label=TrustLevel(data["trust_label"]),
                content_hash=data["content_hash"],
                content_preview=data.get("content_preview", ""),
                provenance=data.get("provenance", []),
                metadata=data.get("metadata", {})
            )
        elif node_type == NodeType.ENTITY:
            return EntityNode(
                node_id=data["node_id"],
                node_type=node_type,
                timestamp=data["timestamp"],
                session_id=data["session_id"],
                entity_type=data["entity_type"],
                sensitivity=data["sensitivity"],
                value_hash=data["value_hash"],
                metadata=data.get("metadata", {})
            )
        else:
            raise ValueError(f"Unknown node type: {node_type}")


# ============= 辅助函数 =============

def calculate_control_weight(
    observation_fields: List[str],
    total_fields: List[str]
) -> float:
    """
    计算控制影响边的权重
    
    Args:
        observation_fields: 来自观测的字段列表
        total_fields: 调用的总字段列表
    
    Returns:
        权重值 [0, 1]
    """
    if not total_fields:
        return 0.0
    
    matching = len(set(observation_fields) & set(total_fields))
    return matching / len(total_fields)


def create_edge_id(source_id: str, target_id: str, edge_type: EdgeType) -> str:
    """生成边ID"""
    return f"{source_id}--{edge_type.value}-->{target_id}"
