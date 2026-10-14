# Audit persistence behavior

The writer bounds all pending events, including the active batch, to 5,000 events and 8 MiB of serialized UTF-8 content by default. Twenty percent is reserved for warning/danger records; critical events are also rejected when the total limit is reached. Only one batch writes at a time and concurrent flush calls share the same drain operation.

`GET /api/audit/persistence` exposes current backlog, byte limits, active batches, drops by severity, write failures, lost-event counts, the last successful append and the last error. These are process-lifetime counters. Hash-chain integrity and durable delivery are separate properties: records visible in memory are not necessarily persisted.

Failed batches are counted and discarded; there is no unbounded retry buffer. Background errors remain observable through status, and explicit flush/compact/prune operations reject on failure. A later successful write restores the current I/O state but does not clear loss counters.

Audit persistence remains best-effort: enforcement continues during a write failure. It does not claim durable-before-execution guarantees. Operators requiring mandatory durable audit must treat failed persistence as a deployment fault and stop the agent externally. JSONL retention still uses compaction, now by default once per retention-sized batch (at least 200 events), rather than rewriting the whole file every 200 events on large deployments. Segmented logs and cross-process coordination remain future work.
