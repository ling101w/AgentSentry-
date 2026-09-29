import json
g = [json.loads(l) for l in open('data/replay/replay_graphs.jsonl', encoding='utf-8')]
print('total:', len(g))
print('attack_types:', sorted({x.get('attack_type') for x in g if x.get('label') == 'attack'}))
print('sources:', sorted({x.get('source') for x in g if x.get('label') == 'attack'}))
print('threat_primary:', sorted({x.get('threat_primary') for x in g if x.get('label') == 'attack'}))
print('replay_id samples:')
for x in [y for y in g if y.get('label') == 'attack'][:3]:
    print(' ', x.get('replay_id'), '->', x.get('attack_type'), '/', x.get('source'))
