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
      thresholds: {
        statements: 82,
        branches: 74,
        functions: 90,
        lines: 87
      }
    }
  }
});
