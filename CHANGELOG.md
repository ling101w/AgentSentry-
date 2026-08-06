# Changelog

## 0.2.0 - 2026-07-10

- Added TaskSpec V2 explicit capabilities with evidence, target constraints, expiry, quotation/negation handling, and the Non-Authoritative Memory Principle.
- Added field-level provenance IDs and precise taint-to-sink propagation.
- Added SHA-256 digest-pinned Tool Security Manifests and conservative unknown-tool handling.
- Isolated LLM-Judge evidence in a data-only JSON envelope and made decision merging monotonic.
- Added observe, balanced, competition, and high-security profiles.
- Replaced synthetic IsolationForest training with an explainable online statistical behavior baseline.
- Added label-isolated evaluation protocol, sealed holdout workflow, credible metrics, and explicit native AgentDojo `not_run` status.
- Added strict TypeScript checks, ESLint, Vitest, fuzz tests, coverage thresholds, Python regression tests, CI, SBOM generation, and security policy.

## 0.1.0

- Initial AgentSentry/OpenClaw competition prototype.
