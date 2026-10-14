import json, sys, torch, glob
from pathlib import Path
sys.path.insert(0, 'E:/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0')

from models.temporal_gat.dataset import CausalGraphDataset, collate_graphs
import torch.utils.data as data

data_dir = Path('E:/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0/data/synthetic_enriched')
dataset = CausalGraphDataset(list(data_dir.glob('*.json')))
print(f'feature_dim={dataset.feature_dim}')

# Show raw graph structure for a few samples
attack_files = sorted(data_dir.glob('attack_*.json'))[:3]
normal_files = sorted(data_dir.glob('normal_*.json'))[:3]

for path in attack_files + normal_files:
    g = json.loads(path.read_text(encoding='utf-8'))
    label = g.get('label', '?')
    node_types = [n['node_type'] for n in g['nodes']]
    edge_types = [e['type'] for e in g['edges']]
    # which calls have source==observation?
    obs_driven = [(n['node_id'], n['tool_name'], n.get('source'))
                  for n in g['nodes'] if n['node_type'] == 'tool_call']
    ci_edges = [(e['source'], e['type'], e['target']) for e in g['edges'] if e['type'] == 'control_influence']
    print(f'\n[{label.upper()} {g["graph_id"]}] nodes={len(g["nodes"])} edges={len(g["edges"])}')
    print(f'  node_types: {node_types}')
    print(f'  edge_types: {edge_types}')
    print(f'  tool_calls: {obs_driven}')
    print(f'  control_influence edges: {ci_edges}')
