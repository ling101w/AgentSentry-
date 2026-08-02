import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 10_000,
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      include: [
        "config.ts",
        "index.ts",
        "core/**/*.ts"
      ],
      // These modules are exercised by the isolated security/property harnesses.
      // V8 coverage cannot merge coverage from their separate Node processes.
      exclude: [
        "core/adapters/**",
        "core/authorization/**",
        "core/behavior/**",
        "core/policy/decision.ts",
        "core/policy/deterministic.ts",
        "core/policy/risk.ts",
        "core/policy/types.ts",
        "core/session-registry.ts",
        "core/ssrf-http.ts",
        "core/taint/graph.ts",
        "core/taint/propagation.ts"
      ],
      thresholds: {
        statements: 82,
        branches: 74,
        functions: 90,
        lines: 87
      }
    }
  }
});
