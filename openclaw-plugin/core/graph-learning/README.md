# Graph Learning Data Contract

`production-graph-v1` is the label-free, pre-enforcement input contract for graph-learning experiments.

The projection contains only bounded categorical and structural features. It deliberately excludes raw task text, tool arguments, data paths, content fingerprints, final decisions, lifecycle status, attack-path verdicts, rule scores, findings, and Semantic Judge output.

Each `tool_decision` audit record stores:

```text
payload.graph_learning = {
  schema_version: "graph-training-envelope-v1",
  sample_id,
  captured_at,
  input: { schema_version: "production-graph-v1", ... }
}
```

The input is captured from preliminary policy effects before Semantic Judge results are merged. The final policy outcome stays outside `input` and is added only by the offline exporter as a weak label.

```powershell
npm run export:graph-training -- --input C:\path\to\records.jsonl --output C:\path\to\graph-training.jsonl
```

Policy outcomes are not independent attack ground truth. Replace or join these weak labels with evaluator-owned labels before reporting model quality.
