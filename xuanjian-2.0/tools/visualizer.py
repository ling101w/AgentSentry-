"""
因果图可视化工具

使用 networkx + matplotlib 可视化因果图
"""

import json
from typing import Optional
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.graph import CausalGraph, NodeType, EdgeType


def visualize_graph(graph: CausalGraph, output_path: Optional[str] = None, show: bool = True):
    """
    可视化因果图
    
    Args:
        graph: 因果图对象
        output_path: 保存路径（可选）
        show: 是否显示图形
    """
    try:
        import networkx as nx
        import matplotlib.pyplot as plt
        from matplotlib.patches import FancyBboxPatch
    except ImportError:
        print("需要安装 networkx 和 matplotlib:")
        print("pip install networkx matplotlib")
        return
    
    # 创建有向图
    G = nx.DiGraph()
    
    # 添加节点
    node_colors = {
        NodeType.INTENT: '#90EE90',      # 浅绿色
        NodeType.TOOL_CALL: '#87CEEB',   # 天蓝色
        NodeType.OBSERVATION: '#FFB6C1',  # 浅粉色
        NodeType.ENTITY: '#FFD700'        # 金色
    }
    
    node_labels = {}
    node_color_list = []
    
    for node_id, node in graph.nodes.items():
        G.add_node(node_id)
        
        # 生成标签
        if node.node_type == NodeType.INTENT:
            label = f"Intent:\n{node.task_type}"
        elif node.node_type == NodeType.TOOL_CALL:
            label = f"Call:\n{node.tool_name}"
        elif node.node_type == NodeType.OBSERVATION:
            label = f"Obs:\n{node.data_source}\n(trust={node.trust_score:.1f})"
        elif node.node_type == NodeType.ENTITY:
            label = f"Entity:\n{node.entity_type}"
        else:
            label = node_id
        
        node_labels[node_id] = label
        node_color_list.append(node_colors.get(node.node_type, '#CCCCCC'))
    
    # 添加边
    edge_colors = {
        EdgeType.INTENT_DRIVES: 'green',
        EdgeType.CONTROL_INFLUENCE: 'red',
        EdgeType.DATA_DEPENDENCY: 'blue',
        EdgeType.CALL_SEQUENCE: 'gray',
        EdgeType.DATA_DERIVATION: 'orange'
    }
    
    edge_styles = {
        EdgeType.INTENT_DRIVES: 'solid',
        EdgeType.CONTROL_INFLUENCE: 'solid',
        EdgeType.DATA_DEPENDENCY: 'dashed',
        EdgeType.CALL_SEQUENCE: 'solid',
        EdgeType.DATA_DERIVATION: 'dotted'
    }
    
    for edge in graph.edges:
        G.add_edge(
            edge.source_id,
            edge.target_id,
            weight=edge.weight,
            color=edge_colors.get(edge.edge_type, 'gray'),
            style=edge_styles.get(edge.edge_type, 'solid'),
            edge_type=edge.edge_type.value
        )
    
    # 布局
    try:
        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    except:
        pos = nx.spring_layout(G, seed=42)
    
    # 绘图
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # 绘制节点
    nx.draw_networkx_nodes(
        G, pos,
        node_color=node_color_list,
        node_size=3000,
        alpha=0.9,
        ax=ax
    )
    
    # 绘制节点标签
    nx.draw_networkx_labels(
        G, pos,
        labels=node_labels,
        font_size=8,
        font_weight='bold',
        ax=ax
    )
    
    # 按边类型分组绘制
    for edge_type in EdgeType:
        edges_of_type = [
            (e.source_id, e.target_id)
            for e in graph.edges
            if e.edge_type == edge_type
        ]
        
        if edges_of_type:
            nx.draw_networkx_edges(
                G, pos,
                edgelist=edges_of_type,
                edge_color=edge_colors.get(edge_type, 'gray'),
                style=edge_styles.get(edge_type, 'solid'),
                width=2.5,
                alpha=0.7,
                arrowsize=20,
                connectionstyle='arc3,rad=0.1',
                ax=ax
            )
    
    # 绘制边权重
    edge_labels = {
        (e.source_id, e.target_id): f"{e.weight:.2f}"
        for e in graph.edges
        if e.edge_type in [EdgeType.CONTROL_INFLUENCE, EdgeType.DATA_DEPENDENCY]
    }
    
    if edge_labels:
        nx.draw_networkx_edge_labels(
            G, pos,
            edge_labels=edge_labels,
            font_size=7,
            font_color='red',
            ax=ax
        )
    
    # 添加图例
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#90EE90', 
               markersize=10, label='Intent Node'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#87CEEB',
               markersize=10, label='Tool Call Node'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#FFB6C1',
               markersize=10, label='Observation Node'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#FFD700',
               markersize=10, label='Entity Node'),
        Line2D([0], [0], color='green', linewidth=2, label='Intent Drives'),
        Line2D([0], [0], color='red', linewidth=2, label='Control Influence'),
        Line2D([0], [0], color='blue', linewidth=2, linestyle='--', label='Data Dependency'),
        Line2D([0], [0], color='gray', linewidth=2, label='Call Sequence'),
    ]
    
    ax.legend(handles=legend_elements, loc='upper left', fontsize=9)
    
    # 标题
    stats = graph.get_statistics()
    title = f"Causal Graph: {graph.graph_id}\n"
    title += f"Nodes: {stats['num_nodes']} | Edges: {stats['num_edges']}"
    ax.set_title(title, fontsize=14, fontweight='bold')
    
    ax.axis('off')
    plt.tight_layout()
    
    # 保存
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"图像已保存到: {output_path}")
    
    # 显示
    if show:
        plt.show()
    
    plt.close()


def visualize_from_json(json_path: str, output_path: Optional[str] = None):
    """从JSON文件加载并可视化"""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    graph = CausalGraph.from_dict(data)
    
    if output_path is None:
        output_path = json_path.replace('.json', '.png')
    
    visualize_graph(graph, output_path, show=True)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python visualizer.py <graph.json> [output.png]")
        print("\n或者运行测试:")
        print("python visualizer.py test")
        sys.exit(1)
    
    if sys.argv[1] == "test":
        # 生成测试数据并可视化
        from data.synthetic.generator import SyntheticDataGenerator
        
        generator = SyntheticDataGenerator()
        
        # 正常样本
        print("生成正常样本...")
        normal_graph = generator.generate_normal_email_summary("test_normal")
        normal_graph.to_json("data/synthetic/test_normal.json")
        visualize_graph(normal_graph, "data/synthetic/test_normal.png", show=False)
        
        # 攻击样本
        print("生成攻击样本...")
        attack_graph = generator.generate_attack_ipi_email_exfil("test_attack")
        attack_graph.to_json("data/synthetic/test_attack.json")
        visualize_graph(attack_graph, "data/synthetic/test_attack.png", show=False)
        
        print("\n✓ 测试完成！生成的文件:")
        print("  - data/synthetic/test_normal.json")
        print("  - data/synthetic/test_normal.png")
        print("  - data/synthetic/test_attack.json")
        print("  - data/synthetic/test_attack.png")
    else:
        json_path = sys.argv[1]
        output_path = sys.argv[2] if len(sys.argv) > 2 else None
        visualize_from_json(json_path, output_path)
