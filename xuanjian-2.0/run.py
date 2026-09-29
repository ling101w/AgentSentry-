"""
快速启动脚本 - 设置Python路径并运行常用命令
"""

import sys
import os
import glob
import json

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def infer_attack_type(graph):
    """Infer the synthetic attack family from the graph's dangerous tool."""
    tool_names = {
        node.tool_name
        for node in graph.nodes.values()
        if getattr(node, "tool_name", None)
    }
    for tool_name, attack_type in (
        ("send_email", "IPI"),
        ("upload_file", "data_exfiltration"),
        ("delete_file", "privilege_escalation"),
        ("update_memory", "memory_poisoning"),
    ):
        if tool_name in tool_names:
            return attack_type
    return None


def write_dataset_record(graph, label, filepath):
    """Write a graph plus dataset labels used by training and statistics tools."""
    record = graph.to_dict()
    record["schema_version"] = "2.0"
    record["label"] = label
    record["attack_type"] = infer_attack_type(graph) if label == "attack" else None
    record["ground_truth_anomaly_nodes"] = (
        [
            edge.target_id
            for edge in graph.edges
            if getattr(edge.edge_type, "value", edge.edge_type) == "control_influence"
        ]
        if label == "attack"
        else []
    )
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="玄鉴2.0 快速启动工具")
    parser.add_argument("command", choices=["generate", "visualize", "test"], 
                       help="执行的命令")
    parser.add_argument("--num-normal", type=int, default=5, 
                       help="生成正常样本数量")
    parser.add_argument("--num-attack", type=int, default=2,
                       help="生成攻击样本数量")
    parser.add_argument("--input", type=str, 
                       help="输入文件路径（用于visualize）")
    parser.add_argument("--output-dir", type=str,
                       help="数据输出目录（默认：data/synthetic）")
    parser.add_argument("--clean", action="store_true",
                       help="生成前清理输出目录中的旧 normal_*/attack_* 数据")
    parser.add_argument("--seed", type=int, default=42,
                       help="数据生成随机种子")
    
    args = parser.parse_args()
    
    if args.command == "generate":
        from data.synthetic.generator import SyntheticDataGenerator

        if args.num_normal < 0 or args.num_attack < 0:
            parser.error("样本数量不能为负数")
        
        print(f"生成数据：{args.num_normal} 正常 + {args.num_attack} 攻击")
        generator = SyntheticDataGenerator(seed=args.seed)
        data = generator.generate_batch(
            num_normal=args.num_normal,
            num_attack=args.num_attack
        )
        
        output_dir = args.output_dir or os.path.join(PROJECT_ROOT, "data", "synthetic")
        os.makedirs(output_dir, exist_ok=True)

        if args.clean:
            old_files = [
                *glob.glob(os.path.join(output_dir, "normal_*.json")),
                *glob.glob(os.path.join(output_dir, "attack_*.json")),
            ]
            for old_file in old_files:
                os.remove(old_file)
            if old_files:
                print(f"已清理旧数据：{len(old_files)} 个文件")
        
        for i, (graph, label) in enumerate(data):
            label_index = i if label == "normal" else i - args.num_normal
            filename = os.path.join(output_dir, f"{label}_{label_index:03d}.json")
            write_dataset_record(graph, label, filename)
            print(f"[OK] {filename}")
        
        print(f"\n总计生成 {len(data)} 条数据")
    
    elif args.command == "visualize":
        from tools.visualizer import visualize_graph
        from data.synthetic.generator import SyntheticDataGenerator
        
        if args.input:
            # 可视化指定文件
            import json
            from core.graph import CausalGraph
            
            with open(args.input, 'r', encoding='utf-8') as f:
                data = json.load(f)
            graph = CausalGraph.from_dict(data)
            output_path = args.input.replace('.json', '.png')
            visualize_graph(graph, output_path, show=False)
            print(f"[OK] Saved to {output_path}")
        else:
            # 生成测试数据并可视化
            generator = SyntheticDataGenerator()
            
            print("生成并可视化测试数据...")
            
            # 正常样本
            normal_graph = generator.generate_normal_email_summary("test_normal")
            normal_graph.to_json("data/synthetic/test_normal.json")
            visualize_graph(normal_graph, "data/synthetic/test_normal.png", show=False)
            print("[OK] data/synthetic/test_normal.png")
            
            # 攻击样本
            attack_graph = generator.generate_attack_ipi_email_exfil("test_attack")
            attack_graph.to_json("data/synthetic/test_attack.json")
            visualize_graph(attack_graph, "data/synthetic/test_attack.png", show=False)
            print("[OK] data/synthetic/test_attack.png")
    
    elif args.command == "test":
        import pytest
        print("运行测试...")
        raise SystemExit(pytest.main([os.path.join(PROJECT_ROOT, "tests"), "-v"]))
