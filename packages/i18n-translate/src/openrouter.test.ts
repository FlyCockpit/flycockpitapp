import type { MockInstance } from "vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// Mock the openai SDK so the provider never opens a real HTTP client. The
// shared `chatCompletionsCreate` spy is asserted against in each test.
// `OpenAI` is invoked as `new OpenAI(...)` so the mock must be constructable —
// a `class` works where a `vi.fn(() => ...)` factory does not.
const chatCompletionsCreate = vi.fn();
class MockOpenAI {
  chat = { completions: { create: chatCompletionsCreate } };
}

vi.mock("openai", () => ({
  default: MockOpenAI,
}));

// Mock @flycockpit/env/shared (the worker-safe env the translation providers
// import) because the provider reads TRANSLATION_MODEL/PROVIDER from it at
// module load. The OpenRouter HTTP-Referer now comes off process.env directly,
// not validated env, so BETTER_AUTH_URL is no longer mocked here. Default to a
// minimal env; tests that need different values use `vi.doMock` after
// `vi.resetModules()`.
vi.mock("@flycockpit/env/shared", () => ({
  env: {
    TRANSLATION_PROVIDER: "openrouter",
    OPENROUTER_API_KEY: "test-key",
    ANTHROPIC_API_KEY: undefined,
    TRANSLATION_MODEL: undefined,
  },
}));

// Re-import the mocked module + the SUT.
const { OpenRouterProvider } = await import("./openrouter.js");

describe("OpenRouterProvider", () => {
  beforeEach(() => {
    chatCompletionsCreate.mockReset();
  });

  it("translates plaintext into es-MX with deterministic temperature and the default model", async () => {
    chatCompletionsCreate.mockResolvedValue({
      choices: [{ message: { content: "Hola" } }],
      model: "anthropic/claude-haiku-4-5",
    });

    const provider = new OpenRouterProvider("test-key");
    const result = await provider.translate({
      source: "Hello",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
    });

    expect(result).toEqual({ text: "Hola", model: "anthropic/claude-haiku-4-5" });
    expect(chatCompletionsCreate).toHaveBeenCalledOnce();

    const call = chatCompletionsCreate.mock.calls[0]?.[0] as {
      model: string;
      temperature: number;
      max_tokens: number;
      messages: { role: string; content: string }[];
    };
    expect(call.model).toBe("anthropic/claude-haiku-4-5");
    expect(call.temperature).toBe(0);
    expect(call.max_tokens).toBe(8192);
    const system = call.messages.find((m) => m.role === "system")?.content ?? "";
    expect(system).toMatch(/Mexican Spanish/);
    const user = call.messages.find((m) => m.role === "user")?.content;
    expect(user).toBe("<source>\nHello\n</source>");
  });

  it("forwards a per-call model override to the SDK", async () => {
    chatCompletionsCreate.mockResolvedValue({
      choices: [{ message: { content: "Hola" } }],
      model: "openai/gpt-4o-mini",
    });

    const provider = new OpenRouterProvider("test-key");
    await provider.translate({
      source: "Hello",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
      model: "openai/gpt-4o-mini",
    });

    const call = chatCompletionsCreate.mock.calls[0]?.[0] as { model: string };
    expect(call.model).toBe("openai/gpt-4o-mini");
  });

  it("emits markdown-preservation guidance when contentKind is markdown", async () => {
    chatCompletionsCreate.mockResolvedValue({
      choices: [{ message: { content: "# Hola" } }],
      model: "anthropic/claude-haiku-4-5",
    });

    const provider = new OpenRouterProvider("test-key");
    await provider.translate({
      source: "# Hello",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "markdown",
    });

    const call = chatCompletionsCreate.mock.calls[0]?.[0] as {
      messages: { role: string; content: string }[];
    };
    const system = call.messages.find((m) => m.role === "system")?.content ?? "";
    expect(system).toMatch(/Markdown/i);
    expect(system).toMatch(/asset:/);
  });

  it("emits JSON-only guidance when contentKind is json", async () => {
    chatCompletionsCreate.mockResolvedValue({
      choices: [{ message: { content: '{"title":"Hola"}' } }],
      model: "anthropic/claude-haiku-4-5",
    });

    const provider = new OpenRouterProvider("test-key");
    await provider.translate({
      source: '{"title":"Hello"}',
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "json",
    });

    const call = chatCompletionsCreate.mock.calls[0]?.[0] as {
      messages: { role: string; content: string }[];
    };
    const system = call.messages.find((m) => m.role === "system")?.content ?? "";
    expect(system).toMatch(/ONLY the JSON/);
  });

  it("propagates SDK errors to the caller", async () => {
    chatCompletionsCreate.mockRejectedValue(new Error("Upstream 502"));

    const provider = new OpenRouterProvider("test-key");
    await expect(
      provider.translate({
        source: "Hello",
        sourceLocale: "en-US",
        targetLocale: "es-MX",
        contentKind: "plaintext",
      }),
    ).rejects.toThrow("Upstream 502");
  });

  it("throws an actionable error when the SDK returns an empty completion", async () => {
    chatCompletionsCreate.mockResolvedValue({
      choices: [{ message: { content: "" } }],
      model: "anthropic/claude-haiku-4-5",
    });

    const provider = new OpenRouterProvider("test-key");
    await expect(
      provider.translate({
        source: "Hello",
        sourceLocale: "en-US",
        targetLocale: "es-MX",
        contentKind: "plaintext",
      }),
    ).rejects.toThrow(/empty completion/);
  });

  it("throws when OpenRouter reports length truncation", async () => {
    chatCompletionsCreate.mockResolvedValue({
      choices: [{ finish_reason: "length", message: { content: "Truncated output" } }],
      model: "anthropic/claude-haiku-4-5",
    });

    const provider = new OpenRouterProvider("test-key");
    await expect(
      provider.translate({
        source: "Hello",
        sourceLocale: "en-US",
        targetLocale: "es-MX",
        contentKind: "plaintext",
      }),
    ).rejects.toThrow(/truncated/i);
  });
});

// ---------------------------------------------------------------------------
// getTranslationProvider() — env-key gating
// ---------------------------------------------------------------------------

describe("getTranslationProvider", () => {
  // We re-import factory + env mocks fresh per test so we can flip env values.
  let _resetTranslationProviderCache: () => void;

  beforeEach(async () => {
    vi.resetModules();
    // Reset the openai mock for the fresh module graph.
    vi.doMock("openai", () => ({ default: MockOpenAI }));
  });

  afterEach(() => {
    _resetTranslationProviderCache?.();
  });

  it("throws an actionable error when TRANSLATION_PROVIDER=openrouter and OPENROUTER_API_KEY is missing", async () => {
    vi.doMock("@flycockpit/env/shared", () => ({
      env: {
        TRANSLATION_PROVIDER: "openrouter",
        OPENROUTER_API_KEY: undefined,
        ANTHROPIC_API_KEY: undefined,
        TRANSLATION_MODEL: undefined,
      },
    }));

    const mod = await import("./factory.js");
    _resetTranslationProviderCache = mod._resetTranslationProviderCache;

    expect(() => mod.getTranslationProvider()).toThrow(/OPENROUTER_API_KEY/);
  });

  it("throws an actionable error when TRANSLATION_PROVIDER=anthropic and ANTHROPIC_API_KEY is missing", async () => {
    vi.doMock("@flycockpit/env/shared", () => ({
      env: {
        TRANSLATION_PROVIDER: "anthropic",
        OPENROUTER_API_KEY: undefined,
        ANTHROPIC_API_KEY: undefined,
        TRANSLATION_MODEL: undefined,
      },
    }));

    const mod = await import("./factory.js");
    _resetTranslationProviderCache = mod._resetTranslationProviderCache;

    expect(() => mod.getTranslationProvider()).toThrow(/ANTHROPIC_API_KEY/);
  });
});

// Suppress an unused-binding lint when the only references are inside vi.mock
// calls evaluated above.
void (chatCompletionsCreate as unknown as MockInstance);
void MockOpenAI;
