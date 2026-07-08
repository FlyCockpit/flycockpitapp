import { env } from "@flycockpit/env/shared";
import { AnthropicDirectProvider } from "./anthropic.js";
import { OpenRouterProvider } from "./openrouter.js";
import type { TranslationProvider } from "./types.js";

let cached: TranslationProvider | null = null;
let cachedKey: string | null = null;

/**
 * Returns the configured translation provider.
 *
 * The instance is cached after first call so we don't churn HTTP clients on
 * every job. The cache key includes the provider id so a test that mutates
 * env mid-run (rare) sees the new provider on the next call.
 *
 * Throws if the chosen provider's API key is missing — surfacing a clear
 * actionable error at first job execution rather than swallowing the misconfig.
 */
export function getTranslationProvider(): TranslationProvider {
  const provider = env.TRANSLATION_PROVIDER;

  if (cached && cachedKey === provider) return cached;

  if (provider === "openrouter") {
    if (!env.OPENROUTER_API_KEY) {
      throw new Error(
        "[i18n-translate] TRANSLATION_PROVIDER=openrouter but OPENROUTER_API_KEY is not set. " +
          "Set OPENROUTER_API_KEY in your .env, or change TRANSLATION_PROVIDER to 'anthropic'.",
      );
    }
    cached = new OpenRouterProvider(env.OPENROUTER_API_KEY);
    cachedKey = provider;
    return cached;
  }

  if (provider === "anthropic") {
    if (!env.ANTHROPIC_API_KEY) {
      throw new Error(
        "[i18n-translate] TRANSLATION_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set. " +
          "Set ANTHROPIC_API_KEY in your .env, or change TRANSLATION_PROVIDER to 'openrouter'.",
      );
    }
    cached = new AnthropicDirectProvider(env.ANTHROPIC_API_KEY);
    cachedKey = provider;
    return cached;
  }

  // Exhaustiveness check — z.enum should make this unreachable.
  throw new Error(`[i18n-translate] Unknown TRANSLATION_PROVIDER: ${String(provider)}`);
}

/** Test-only: drop the cached provider so the next call rebuilds from env. */
export function _resetTranslationProviderCache(): void {
  cached = null;
  cachedKey = null;
}
