# Security Screen DAG Design QA

- source visual truth path: `.tmp/graph-v2-1920x1080.png` and `.tmp/graph-v2-1366x768.png`
- implementation URL: `http://127.0.0.1:8766/security-screen`
- implementation screenshot path: unavailable; the primary in-app Browser failed before capture because the shared automation runtime omitted its sandbox metadata
- viewport: intended checks at 1920x1080 and 1366x768
- state: causal graph view with a real attack trace; authorized and enforcement-bypass traces covered by projection tests
- full-view comparison evidence: blocked because a current implementation screenshot could not be captured
- focused region comparison evidence: an independent Chromium pass verified the live 1366x768 layout and interactions, but did not retain a screenshot artifact for source-to-implementation comparison

## Findings

- P1: A source-to-implementation visual comparison is not available. The HTML module parses, the live endpoint serves the new markup, and the 1366x768 live pass found no overflow or console errors, but a retained current screenshot is still required for formal comparison at both target viewports.

## Patches Made Since Previous QA

- Preserved the existing security-screen palette, panel layout, and Three.js topology.
- Replaced the causal view's serpentine coordinates with a topological rank layout.
- Added connected display-only collapse nodes for long paths.
- Added fit, zoom, pan, keyboard tabs, node/edge inspection, directed focus, stable alert selection, dynamic evidence legend, and partial-graph counters.
- Added attack, authorized, and enforcement-bypass trace presentations.
- Added a six-step causal story in both the graph header and evidence bar: authorization actor, authorization result, data field, tool chain, destination, and verdict.
- Made the first real graph open automatically while preserving a user's manual topology/causal view choice across polling refreshes.
- Verified the rebuilt `8766` endpoint serves the six-step markup and currently exposes 4 real causal graphs across 66 overview alerts.
- Bound authorization evidence to the final Sink action so an earlier authorized read cannot be presented as authorization for a later unapproved external send.
- Separated graph-path verdict from the final merged enforcement decision; the sixth step now follows the actual alert action.
- Added two frontend regression tests for those security invariants.
- Consolidated the three crowded left-column cards and the attack-chain card into one four-tab `态势侧舱`; hidden panes continue receiving live render updates.
- Converted the attack chain to a vertical side-panel sequence and expanded the bottom row from three cramped columns to two wider evidence panels.
- Replaced the generic competition-ready banner with `玄鉴已启动 · 全域戒备` and live protection-layer wording.
- Added keyboard tab navigation (`ArrowLeft`, `ArrowRight`, `Home`, `End`) and stable per-tab live summaries.

## Implementation Checklist

- Capture both target viewports from the current `8766` build.
- Check node and edge-label collisions with 6, 12, and 16 projected nodes.
- Verify node selection, edge selection, inspector close, wheel zoom, drag pan, reset, Tab, and arrow-key view switching.
- Compare the current screenshots against the two source screenshots in one combined visual input.
- Reconfirm all six story cells at 1920x1080 and retain both current screenshots for comparison.
- Capture the new four-tab side console at 1920x1080 and 1366x768; verify every tab, focus state, vertical attack-chain layout, and two-column bottom row without overlap.

final result: blocked
