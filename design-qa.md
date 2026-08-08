# Semantic Action Graph Design QA

- source visual truth path: `E:\weix\xwechat_files\wxid_qb9bpbg86nc222_5bd3\temp\RWTemp\2026-08\0aded3c3359cb22b61fecbb3abf4660c.png`
- implementation URL: `http://127.0.0.1:8766/`
- implementation screenshot path: `artifacts/design-qa/implementation-1680x944-final-20260808.jpg`
- responsive evidence: `artifacts/design-qa/implementation-1366x768-final-20260808.jpg`, `artifacts/design-qa/implementation-390x844-final-20260808.jpg`
- full-view comparison: `artifacts/design-qa/comparison-reference-left-implementation-right-final-20260808.jpg`
- focused comparisons: `artifacts/design-qa/comparison-focused-context-final-20260808.jpg`, `artifacts/design-qa/comparison-focused-graph-final-20260808.jpg`, `artifacts/design-qa/comparison-focused-inspector-final-20260808.jpg`
- primary viewport: `1680x944`
- state: deny session selected, attack primary path visible, decision node selected, timeline at LIVE
- browser-rendered evidence: Chrome local preview connected to the real dashboard endpoints
- primary interactions tested: node and edge selection, all timeline ticks, event-result shortcuts, full-graph toggle, draggable nodes with connected-edge redraw, layout persistence after reload, allow/ask/deny session switching, replay controls, more-actions menu, and allowlist confirmation dialog
- console errors checked: 0 errors, 0 warnings

## Full-view Comparison Evidence

The source and current implementation were opened together in the full-view comparison artifact. The implementation preserves the source hierarchy of navigation, request context, causal graph, evidence inspector, and event timeline while applying the requested product changes:

- A dynamic core-conclusion bar is now the first content layer.
- Request context is compressed and Prompt Injection evidence is promoted.
- Red is limited to confirmed attack content; amber marks suspicious behavior, blue/gray marks normal behavior, and green marks successful enforcement.
- The default graph is the attack primary path; the complete dependency graph is opt-in.
- Event summary and timeline are merged into one dynamic incident story.

No actionable P0, P1, or P2 full-view mismatch remains.

## Focused Region Comparison Evidence

- Request context: the focused comparison confirms the four large source cards were intentionally compressed into user request, model input, compact tool tags, and a stronger detection card. Long content wraps and the panel scrolls at short desktop heights.
- Causal graph: the focused comparison confirms semantic node types, labeled relations, primary-path emphasis, and a green enforcement outcome. The calmer palette preserves red for the Prompt Injection branch.
- Evidence inspector: the focused comparison confirms the new layered hierarchy of current selection, what happened, local facts, and collapsed technical details. Normal nodes and relations do not inherit irrelevant attack-wide fields.

## Required Fidelity Surfaces

- Fonts and typography: Segoe UI / Microsoft YaHei UI and Cascadia Code fallbacks keep Chinese labels, metadata, policy codes, and graph labels readable. Letter spacing is zero and primary labels do not clip.
- Spacing and layout rhythm: the 1680 view uses compact three-column investigation tracks plus a 220px result rail. At 1366, context and inspector remain independently scrollable. At 390, the conclusion and graph lead the vertical flow with no page-level horizontal overflow.
- Colors and visual tokens: blue/gray represent normal behavior, amber represents suspicious behavior, red represents confirmed attack content, and green represents effective safety control. The page no longer reads as a single red alarm state.
- Image and icon fidelity: the supplied shield asset and vendored Lucide icon set are used. No placeholder imagery, emoji, handcrafted SVG, or CSS illustration was introduced.
- Copy and content: visible incident IDs, timestamps, tools, targets, decisions, evidence, policies, and timeline events come from `/api/security/overview`, `/api/records`, and `/api/settings/enforcement`. Visible branding is `玄鉴`.
- Interaction and accessibility: graph nodes and edge hit areas are keyboard-focusable, selected items have visible emphasis, nodes are draggable, timeline ticks are buttons, summary results are buttons, dialogs are labeled, and reduced-motion behavior is supported. Compact metadata now uses contrast ratios above 4.5:1, and visible timeline/alert labels are included in their accessible names.

## Comparison History

1. Replaced the dashboard-first composition with the supplied incident-detail structure.
2. Added real backend projection for session, graph, inspector, request context, and timeline data.
3. Added selection-specific node and edge evidence instead of a static attack-wide JSON panel.
4. Added timeline-to-graph synchronization, result-summary shortcuts, draggable nodes, and persisted per-view layouts.
5. Added the dynamic core conclusion, compressed context, detection card, primary-path mode, layered inspector, and merged result rail.
6. Corrected the preview tool call from `graph_builder` to `send_email` and mapped that timeline step to `action-email`.
7. Corrected review-event detection time to prefer the matching audit record's full `created_at` value.
8. Removed narrow-screen graph-confidence clipping by hiding secondary graph metadata below 1480px.
9. Corrected the more-actions menu direction so the allowlist entry is visible and its confirmation dialog is reachable.
10. Raised compact metadata contrast and aligned brand, alert, and timeline accessible names with their visible labels.

## Findings

No actionable P0, P1, or P2 findings remain.

## Follow-up Polish

- P3: at 1366x768, request context and Inspector use internal scrolling to protect the graph and result rail; a future density preference could trade footer height for more vertical investigation space.
- P3: the default primary-path graph uses a deliberately quiet background compared with the source so relation labels remain legible during replay.

final result: passed

## Operations Workspace QA (2026-08-08)

- implementation URL: `http://127.0.0.1:8767`
- routes verified: `/overview`, `/agents`, `/policies`, `/tools`, `/alerts`, `/audit`, `/settings`
- desktop evidence: `artifacts/design-qa/workspace-*-1680.png`
- mobile evidence: `artifacts/design-qa/workspace-*-390.png`
- data contracts verified: security overview, records, stats, policy config, tool manifests, alerts, health, enforcement, and checkpoints
- browser state: every route reached `LIVE` and rendered backend fixture data without a synchronization error
- interaction checks: tool detail and revoke-confirmation dialog, tool filtering, policy dirty state, alert detail, audit filtering and detail, agent detail, mode inventory, and security-stack inventory
- navigation check: overview and agent session links select the requested attack-monitor session through `?session=...`
- branding check: dynamic backend labels display `玄鉴`; internal API field names remain unchanged
- runtime errors observed during the interaction pass: 0

The workspace reuses the attack-monitor shell, density, color semantics, navigation, and responsive behavior. The QA pass corrected native button backgrounds in alert and identity-risk rows, removed danger color from zero-value attack metrics, and constrained long section metadata on mobile.

No actionable P0, P1, or P2 workspace finding remains.
