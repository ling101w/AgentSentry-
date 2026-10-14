process.stdout.write(JSON.stringify({ ready: true, model_version: "fixture-v1" }) + "\n");
process.stdin.setEncoding("utf8");
let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newline = buffer.indexOf("\n");
  while (newline >= 0) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    newline = buffer.indexOf("\n");
    if (!line.trim()) continue;
    const request = JSON.parse(line);
    process.stdout.write(JSON.stringify({
      id: request.id,
      ok: true,
      model_version: "fixture-v1",
      graph_probability: 0.82,
      threshold: 0.6,
      ood_score: 0.2,
      ood_threshold: 0.7,
      route: "shadow_review",
    }) + "\n");
  }
});
