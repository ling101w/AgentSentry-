import { describe, expect, it } from "vitest";
import { clampText, redactObject } from "../../core/redact.ts";

describe("telemetry redaction", () => {
  it("does not expose secret-key fields or token-shaped values", () => {
    expect(redactObject({ apiKey: "sk-super-secret-value", nested: { authorization: "Bearer abcdefghijklmnop" } }, 100)).toEqual({
      apiKey: "[redacted]",
      nested: { authorization: "[redacted]" },
    });
    expect(clampText("token sk-abcdefghijklmnop", 100)).not.toContain("sk-abcdefghijklmnop");
    expect(clampText('{"token":"opaqueCredentialValue123456789"}', 200)).toBe('{"token":"[redacted]"}');
  });

  it("honors small preview limits", () => {
    expect(clampText("abcdef", 3)).toBe("...");
    expect(clampText("abcdef", 5)).toBe("ab...");
  });
});
