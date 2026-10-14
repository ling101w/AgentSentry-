"""Ablation test: does the model depend on the `source` field shortcut?

If AUC drops significantly when source is zeroed out, the model is using
source=observation as a shortcut (which won't exist in real attack data).
"""
import json, sys, torch, random
from pathlib import Path
sys.path.insert(0, 'E:/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0')

from models.temporal_gat.model import TemporalGAT, compute_loss
from models.temporal_gat.dataset import CausalGraphDataset, collate_graphs

def zero_source(batch, feat_dim=70):
    """Zero out source feature columns [8,9,10] in node_feat."""
    nf = batch['node_feat'].clone()
    nf[:, 8] = 0.0  # source == user
    nf[:, 9] = 0.0  # source == observation  <-- the key shortcut
    nf[:, 10] = 0.0  # source == system
    return {**batch, 'node_feat': nf}

def eval(model, loader, device):
    model.eval()
    graph_probs, graph_labels = [], []
    with torch.no_grad():
        for batch in loader:
            batch = {k: (v.to(device) if torch.is_tensor(v) else v) for k, v in batch.items()}
            # zero source
            batch = zero_source(batch)
            outputs = model(batch)
            graph_probs.extend(outputs['graph_prob'].cpu().numpy().tolist())
            graph_labels.extend(batch['graph_label'].cpu().numpy().tolist())
    import numpy as np
    from sklearn.metrics import roc_auc_score, f1_score
    y = np.array(graph_labels)
    p = np.array(graph_probs)
    auc = roc_auc_score(y, p)
    f1 = f1_score(y, (p >= 0.5).astype(int))
    return auc, f1

data_dir = Path('E:/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0/data/synthetic_enriched')
ckpt_path = Path('E:/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0/checkpoints/best_model.pth')
vocab_path = Path('E:/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0/checkpoints/vocab.json')

device = torch.device('cpu')
model = TemporalGAT(feature_dim=70, hidden_dim=64, num_layers=3).to(device)
model.load_state_dict(torch.load(ckpt_path, map_location=device))
vocab = json.load(open(vocab_path))

dataset = CausalGraphDataset(list(data_dir.glob('*.json')))
loader = torch.utils.data.DataLoader(dataset, batch_size=16, shuffle=False, collate_fn=collate_graphs)

print('=== With source features intact ===')
auc_full, f1_full = eval(model, loader, device)
print(f'AUC={auc_full:.4f} F1={f1_full:.4f}')

print('\n=== With source features ZEROED OUT ===')
auc_abl, f1_abl = eval(model, loader, device)
print(f'AUC={auc_abl:.4f} F1={f1_abl:.4f}')
print(f'\nAblation drop: AUC {auc_full:.4f} -> {auc_abl:.4f}  (delta={auc_abl-auc_full:.4f})')
