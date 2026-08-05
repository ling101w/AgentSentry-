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
      exclude: [
        "core/ssrf-http.ts",
      ],
      thresholds: {
        statements: 83,
        branches: 73,
        functions: 88,
        lines: 87
      }
    }
  }
});
