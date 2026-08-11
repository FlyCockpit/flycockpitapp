import { describe, expect, it } from "vitest";
import {
  assertSafeForState,
  containsForbiddenSentinel,
  FORBIDDEN_SENTINELS,
  isHostPathString,
  isProviderUrlString,
  isRawWorkflowJson,
  isRedactableValue,
  isSignedQueryString,
  redactForbiddenValues,
  redactString,
  scanForForbiddenSentinels,
} from "./image-generation-redaction";

describe("image generation redaction", () => {
  it("forbidden sentinels include secret, signed url, raw workflow, quarantine, host path", () => {
    const lower = FORBIDDEN_SENTINELS.map((s) => s.toLowerCase());
    expect(lower).toContain("api_key");
    expect(lower).toContain("secret");
    expect(lower).toContain("password");
    expect(lower).toContain("access_token");
    expect(lower).toContain("provider_body");
    expect(lower).toContain("quarantine");
    expect(lower).toContain("host_path");
    expect(lower).toContain("local_path");
    expect(lower).toContain("raw_workflow_json");
    expect(lower).toContain("signed_url");
  });

  it("scanForForbiddenSentinels finds keys recursively", () => {
    const value = {
      api_key: "leak",
      nested: { secret: "leak" },
      list: [{ password: "leak" }],
      safe: "ok",
    };
    const found = scanForForbiddenSentinels(value);
    expect(found).toContain("api_key");
    expect(found).toContain("secret");
    expect(found).toContain("password");
    expect(found).not.toContain("safe");
    // Sorted and deduped.
    expect(found).toEqual([...new Set(found)].sort());
  });

  it("containsForbiddenSentinel returns a boolean", () => {
    expect(containsForbiddenSentinel({ api_key: "x" })).toBe(true);
    expect(containsForbiddenSentinel({ artifact_id: "x" })).toBe(false);
  });

  it("detects host path, provider URL, signed query, and raw workflow strings", () => {
    expect(isHostPathString("/var/lib/output.png")).toBe(true);
    expect(isHostPathString("file:///sandbox/x.png")).toBe(true);
    expect(isHostPathString("C:\\Users\\x.png")).toBe(true);
    expect(isHostPathString("not-a-path")).toBe(false);

    expect(isProviderUrlString("https://openai.com/image.png")).toBe(true);
    expect(isProviderUrlString("not-a-url")).toBe(false);

    expect(isSignedQueryString("https://x?sig=abc")).toBe(true);
    expect(isSignedQueryString("https://x?signature=abc")).toBe(true);
    expect(isSignedQueryString("https://x")).toBe(false);

    expect(isRawWorkflowJson('{"class_type":"Load"}')).toBe(true);
    expect(isRawWorkflowJson("plain text")).toBe(false);
  });

  it("isRedactableValue detects any redactable string", () => {
    expect(isRedactableValue("/var/lib/output.png")).toBe(true);
    expect(isRedactableValue("https://openai.com/x.png")).toBe(true);
    expect(isRedactableValue("https://x?sig=abc")).toBe(true);
    expect(isRedactableValue('{"class_type":"Load"}')).toBe(true);
    expect(isRedactableValue("safe value")).toBe(false);
  });

  it("redactString masks the content", () => {
    expect(redactString("secret")).toBe("•".repeat(6));
    expect(redactString("")).toBe("");
    expect(redactString("a-very-long-secret-value")).toHaveLength(8);
  });

  it("redactForbiddenValues deep-clones and redacts redactable strings", () => {
    const value = {
      url: "https://openai.com/x.png",
      path: "/var/lib/output.png",
      safe: "ok",
      nested: { signed: "https://x?sig=abc" },
    };
    const redacted = redactForbiddenValues(value);
    expect(redacted.url).toBe("•".repeat(8));
    expect(redacted.path).toBe("•".repeat(8));
    expect(redacted.safe).toBe("ok");
    expect(redacted.nested.signed).toBe("•".repeat(8));
    // Original unchanged.
    expect(value.url).toBe("https://openai.com/x.png");
  });

  it("assertSafeForState throws on forbidden sentinel keys", () => {
    expect(() => assertSafeForState({ api_key: "x" }, "test")).toThrow();
    expect(() => assertSafeForState({ artifact_id: "x" }, "test")).not.toThrow();
  });
});
