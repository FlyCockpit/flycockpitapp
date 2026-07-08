import { env } from "@flycockpit/env/shared";
import OpenAI from "openai";
import { buildTranslationPrompt } from "./prompt.js";
import type { TranslateInput, TranslateResult, TranslationProvider } from "./types.js";

const DEFAULT_MODEL = "anthropic/claude-haiku-4-5";
const MAX_OUTPUT_TOKENS = 8192;

export class OpenRouterProvider implements TranslationProvider {
  private readonly client: OpenAI;

  constructor(apiKey: string) {
    const defaultHeaders: Record<string, string> = {
      "X-Title": "Flycockpit Translation",
    };
    // OpenRouter uses HTTP-Referer purely to attribute traffic on its
    // leaderboard — it is optional metadata, not functional. PUBLIC_APP_URL is
    // the stable public origin; fall back to the raw BETTER_AUTH_URL from
    // process.env (set in the server process, absent in the worker — the
    // header is simply omitted there). Both are read off process.env directly
    // so this provider stays in the worker-safe env graph and never forces a
    // worker deployment to set BETTER_AUTH_URL.
    const referer = env.PUBLIC_APP_URL ?? process.env.BETTER_AUTH_URL;
    if (referer) defaultHeaders["HTTP-Referer"] = referer;

    this.client = new OpenAI({
      apiKey,
      baseURL: "https://openrouter.ai/api/v1",
      defaultHeaders,
    });
  }

  async translate(input: TranslateInput): Promise<TranslateResult> {
    const model = input.model ?? env.TRANSLATION_MODEL ?? DEFAULT_MODEL;
    const { system, user } = buildTranslationPrompt({
      source: input.source,
      sourceLocale: input.sourceLocale,
      targetLocale: input.targetLocale,
      contentKind: input.contentKind,
    });

    const completion = await this.client.chat.completions.create({
      model,
      // Deterministic translations — re-running the worker for the same source
      // should produce the same target, otherwise diff review becomes useless.
      temperature: 0,
      max_tokens: MAX_OUTPUT_TOKENS,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
    });

    const choice = completion.choices[0];
    if (choice?.finish_reason === "length") {
      throw new Error(
        `[i18n-translate] OpenRouter truncated the translation at the output limit (model=${completion.model ?? model})`,
      );
    }

    const text = choice?.message?.content;
    if (typeof text !== "string" || text.length === 0) {
      throw new Error(`[i18n-translate] OpenRouter returned an empty completion (model=${model})`);
    }

    return {
      text,
      // OpenRouter echoes the resolved model id in `completion.model`. Pass it
      // through unchanged — it is what gets persisted as `translatedByModel`
      // and surfaced in the "translated by" UI banner.
      model: completion.model ?? model,
    };
  }
}
