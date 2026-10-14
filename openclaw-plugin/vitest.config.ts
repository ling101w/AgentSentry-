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
        "core/**/*.ts",
        "server/**/*.ts"
      ],
      exclude: [
        "core/ssrf-http.ts",
      ],
      thresholds: {
        // Keep the established core gate while reporting server coverage separately.
        "{config.ts,index.ts,core/**}": {
          statements: 83,
          branches: 73,
          functions: 88,
          lines: 87,
        },
        "server/**": {
          statements: 55,
          branches: 45,
          functions: 60,
          lines: 60,
        },
        "server/{policy-sessions,sidecar-service,policy-test-service}.ts": {
          statements: 85,
          branches: 65,
          functions: 90,
          lines: 90,
        },
      }
    }
  }
});
