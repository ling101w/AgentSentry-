"""Quick progress check for the running replay."""
import json
import os
import glob
import subprocess
from collections import Counter

# 1. Find the most recent run log
run_logs = sorted(glob.glob('data/replay/run_*.log'))
print(f'run logs found: {len(run_logs)}')
latest = run_logs[-1] if run_logs else None
if latest:
    size = os.path.getsize(latest)
    print(f'latest run log: {latest} ({size:,} bytes)')

# 2. Count progress in sessions.jsonl.log.jsonl
log_path = 'data/replay/sessions.jsonl.log.jsonl'
if not os.path.exists(log_path):
    print(f'{log_path}: MISSING')
else:
    statuses = Counter()
    ids = []
    with open(log_path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            statuses[entry.get('status', '?')] += 1
            ids.append(entry.get('replay_id', '?'))
    total = sum(statuses.values())
    print(f'progress: {total} done ({dict(statuses)})')
    if ids:
        print(f'last 5: {ids[-5:]}')
    # total manifest size
    with open('data/replay/manifest.jsonl', encoding='utf-8') as fh:
        manifest_total = sum(1 for l in fh if l.strip())
    print(f'manifest total: {manifest_total}, remaining: {manifest_total - total}')

# 3. Check if the nohup'd bash process is still alive
try:
    out = subprocess.check_output(['wsl', '-d', 'Ubuntu-22.04', '--', 'bash', '-lc',
                                   'ps -p $(cat /mnt/e/cslearn/AgentSentry/xuanjian/AgentSentry/xuanjian-2.0/data/replay/replay.pid 2>/dev/null) -o pid,etime,cmd 2>/dev/null || echo NOT_RUNNING'],
                                  text=True)
    print('process status:')
    print(out)
except Exception as e:
    print(f'process check failed: {e}')
