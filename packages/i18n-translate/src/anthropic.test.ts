import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock the @anthropic-ai/sdk default export. The provider only uses
// `client.messages.create`, so we expose a single shared spy and assert on it.
// ---------------------------------------------------------------------------

const messagesCreate = vi.fn();
class MockAnthropic {
  messages = { create: messagesCreate };
}

vi.mock("@anthropic-ai/sdk", () => ({
  default: MockAnthropic,
}));

vi.mock("@flycockpit/env/shared", () => ({
  env: {
    TRANSLATION_PROVIDER: "anthropic",
    OPENROUTER_API_KEY: undefined,
    ANTHROPIC_API_KEY: "anthropic-test-key",
    TRANSLATION_MODEL: undefined,
  },
}));

const { AnthropicDirectProvider } = await import("./anthropic.js");

describe("AnthropicDirectProvider", () => {
  beforeEach(() => {
    messagesCreate.mockReset();
  });

  it("translates plaintext into es-MX with deterministic temperature and the default model", async () => {
    messagesCreate.mockResolvedValue({
      content: [{ type: "text", text: "Hola" }],
      model: "claude-haiku-4-5",
    });

    const provider = new AnthropicDirectProvider("anthropic-test-key");
    const result = await provider.translate({
      source: "Hello",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
    });

    expect(result).toEqual({ text: "Hola", model: "claude-haiku-4-5" });
    expect(messagesCreate).toHaveBeenCalledOnce();

    const call = messagesCreate.mock.calls[0]?.[0] as {
      model: string;
      temperature: number;
      max_tokens: number;
      system: string;
      messages: { role: string; content: string }[];
    };
    expect(call.model).toBe("claude-haiku-4-5");
    expect(call.temperature).toBe(0);
    expect(call.max_tokens).toBeGreaterThan(0);
    expect(call.system).toMatch(/Mexican Spanish/);
    expect(call.messages[0]?.role).toBe("user");
    expect(call.messages[0]?.content).toBe("<source>\nHello\n</source>");
  });

  it("forwards a per-call model override to the SDK", async () => {
    messagesCreate.mockResolvedValue({
      content: [{ type: "text", text: "Hola" }],
      model: "claude-opus-4-5",
    });

    const provider = new AnthropicDirectProvider("anthropic-test-key");
    await provider.translate({
      source: "Hello",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
      model: "claude-opus-4-5",
    });

    const call = messagesCreate.mock.calls[0]?.[0] as { model: string };
    expect(call.model).toBe("claude-opus-4-5");
  });

  it("concatenates multiple text blocks into a single output string", async () => {
    messagesCreate.mockResolvedValue({
      content: [
        { type: "text", text: "Hola " },
        { type: "text", text: "mundo" },
      ],
      model: "claude-haiku-4-5",
    });

    const provider = new AnthropicDirectProvider("anthropic-test-key");
    const result = await provider.translate({
      source: "Hello world",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
    });

    expect(result.text).toBe("Hola mundo");
  });

  it("throws when the response contains no text blocks", async () => {
    messagesCreate.mockResolvedValue({
      content: [],
      model: "claude-haiku-4-5",
    });

    const provider = new AnthropicDirectProvider("anthropic-test-key");
    await expect(
      provider.translate({
        source: "Hello",
        sourceLocale: "en-US",
        targetLocale: "es-MX",
        contentKind: "plaintext",
      }),
    ).rejects.toThrow(/empty completion/);
  });

  it("throws when Anthropic reports max_tokens truncation", async () => {
    messagesCreate.mockResolvedValue({
      content: [{ type: "text", text: "Truncated output" }],
      model: "claude-haiku-4-5",
      stop_reason: "max_tokens",
    });

    const provider = new AnthropicDirectProvider("anthropic-test-key");
    await expect(
      provider.translate({
        source: "Hello",
        sourceLocale: "en-US",
        targetLocale: "es-MX",
        contentKind: "plaintext",
      }),
    ).rejects.toThrow(/truncated/i);
  });

  it("propagates SDK errors to the caller", async () => {
    messagesCreate.mockRejectedValue(new Error("Anthropic 503"));

    const provider = new AnthropicDirectProvider("anthropic-test-key");
    await expect(
      provider.translate({
        source: "Hello",
        sourceLocale: "en-US",
        targetLocale: "es-MX",
        contentKind: "plaintext",
      }),
    ).rejects.toThrow("Anthropic 503");
  });
});
