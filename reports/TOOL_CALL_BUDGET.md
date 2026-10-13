# Tool-call latency contract

The production OpenClaw before-tool hook skips semantic calls when the preliminary decision is a deterministic deny. Otherwise tool-risk, memory-risk and ambiguous-authorization Judge routes share one deadline derived from `semantic.timeoutMs`, capped at 2,000 ms. Retry attempts and response-body reads consume that same deadline. A timeout leaves the deterministic result in force; a late model response cannot mutate the returned decision or populate the ambiguous-action cache with a timeout result.

Graph shadow scoring is asynchronous, with at most 32 pending requests. Tool-decision records retain the graph input and a scheduled/disabled/backpressured status. Completed scores are separate `graph_shadow_score` records correlated by toolCallId. Sidecar errors and scores arriving after shutdown do not affect enforcement or append to a closed store.

The deadline bounds model I/O, not synchronous policy parsing, graph projection, filesystem checkpoints or the event loop under saturation. It applies to the production OpenClaw hook; command-lab/evaluator orchestration has separate timeouts. Existing P50/P95/P99 hook metrics remain available. Controlled local tests verify scheduling and timeout behavior; real model cost, production P95/P99, and task Utility still need native evaluation on a frozen clean commit.
