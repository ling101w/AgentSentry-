# Semantic Action Graph Design QA

- source visual truth path: `E:\weix\xwechat_files\wxid_qb9bpbg86nc222_5bd3\temp\RWTemp\2026-08\0aded3c3359cb22b61fecbb3abf4660c.png`
- implementation URL: `http://127.0.0.1:8766/`
- implementation screenshot path: `artifacts/design-qa/implementation-1680x944-final.png`
- primary viewport: `1680x944`
- responsive evidence: `artifacts/design-qa/implementation-1366x768-final.png`, `artifacts/design-qa/implementation-390x844-final.png`
- state: deny session selected, attack-path focus enabled, `edge-cap-email` selected, rich evidence inspector open, timeline at LIVE
- browser-rendered evidence: `artifacts/design-qa/comparison-reference-left-implementation-right-final.png`
- focused evidence: `artifacts/design-qa/comparison-focused-context-final.png`, `artifacts/design-qa/comparison-focused-graph-final.png`, `artifacts/design-qa/comparison-focused-inspector-final.png`
- primary interactions tested: all 9 edge labels, all 10 semantic nodes, node dragging with connected-edge redraw, layout persistence after reload, all 7 timeline ticks, summary metrics, allow/ask/deny session switching, path focus, inspector close/reopen, and LIVE return
- console errors checked: 0 errors, 0 warnings

## Full-view Comparison Evidence

- The final comparison places the supplied source on the left and the same-state implementation on the right at `1680x944`.
- The implementation preserves the source's five-region hierarchy: navigation/header, request context, causal graph, evidence inspector, and summary/timeline footer.
- The prominent product identity is now `玄鉴`; session-specific records, timestamps, decisions, tools, policies, and evidence remain sourced from the dashboard APIs.
- No actionable P0, P1, or P2 full-view mismatch remains.

## Focused Region Comparison Evidence

- Request context: `comparison-focused-context-final.png` confirms the numbered input/tool/evidence blocks, status colors, and compact card rhythm.
- Causal graph: `comparison-focused-graph-final.png` confirms semantic node density, attack-path emphasis, readable relation labels, selected-edge highlight, and the green 玄鉴 boundary.
- Evidence inspector: `comparison-focused-inspector-final.png` confirms the richer selection-specific hierarchy: what happened, current relation/node facts, observations, and downstream context.

## Required Fidelity Surfaces

- Fonts and typography: Segoe UI / Microsoft YaHei UI keeps Chinese headings, metadata, monospace IDs, and graph labels readable at desktop and narrow desktop widths; no negative letter spacing or clipped primary labels is present.
- Spacing and layout rhythm: desktop columns remain approximately `410 / 657 / 435px`; the graph/context panels, evidence-flow strip, and footer timeline retain the source's compact rhythm.
- Colors and visual tokens: blue normal nodes, amber intermediate nodes, red causal path, and green 玄鉴 boundary remain isolated to their semantic roles on the dark neutral canvas.
- Image and icon fidelity: the existing shield asset is reused and interface symbols use the vendored Lucide bundle; no placeholder imagery, emoji, handcrafted SVG, or CSS illustration was introduced.
- Copy and content: fixed hierarchy follows the source while live content is truthful. Edge inspector endpoints disambiguate same-named nodes as `未授权能力 · 发送邮件` and `工具动作 · 发送邮件`.
- Interaction and accessibility: semantic buttons, labels, focus states, selected-node/edge highlighting, draggable nodes, keyboard edge activation, reduced-motion support, and no page-level horizontal overflow at `1680x944`, `1366x768`, or `390x844`.

## Comparison History

1. The initial shell comparison found composition drift from the supplied incident-detail screen. Fixed by making the semantic action graph homepage the primary screen.
2. The first rendered comparison found request-card sizing, semantic status colors, graph spacing, and wrapped decision text drift. Fixed with measured panel tracks, attached flow spacing, and responsive text constraints.
3. The focused graph comparison found role placement drift. Fixed with role-aware positions for intent, capability, action, taint, secret, guard, decision, and sink nodes.
4. Interaction QA found that the graph refreshed every five seconds and detached active elements. Fixed with render-signature DOM reuse and selection restoration from live session IDs.
5. Edge QA found label pointer events being captured by canvas panning. Fixed by reserving edge pointer events and preserving selected edge IDs through refresh.
6. Edge QA then found labels hidden below nodes. Fixed with curve-aware label placement that avoids node and label collisions, so all relation labels have independent hit areas.
7. Inspector QA found same-named capability/action endpoints ambiguous. Fixed with semantic endpoint labels and Chinese relation/state labels.
8. Final responsive QA confirmed no page-level horizontal overflow or overlapping primary controls at desktop, narrow desktop, and mobile viewports.

## Findings

No actionable P0, P1, or P2 findings remain.

## Follow-up Polish

- P3: the source includes a slightly denser dotted graph texture; the implementation keeps a quieter grid so live edge labels and evidence remain legible.
- P3: the implementation graph includes additional guard/decision projection nodes because it exposes the backend's enforcement chain rather than flattening it into a single block card.

final result: passed
