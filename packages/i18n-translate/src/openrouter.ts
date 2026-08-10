import { env } from "@flycockpit/env/shared";
import OpenAI from "openai";
import { buildTranslationPrompt } from "./prompt.js";
import type { TranslateInput, TranslateResult, TranslationProvider } from "./types.js";

const DEFAULT_MODEL = "anthropic/claude-haiku-4-5";
const MAX_OUTPUT_TOKENS = 8192;

export interface OpenRouterAttributionOptions {
  httpReferer?: string | null;
  title?: string | null;
}

export function openRouterAttributionHeaders(
  options: OpenRouterAttributionOptions = {},
): Record<string, string> {
  const headers: Record<string, string> = {};
  const title = options.title === undefined ? "FlyCockpit Translation" : options.title;
  if (title) headers["X-OpenRouter-Title"] = title;

  let referer: string | null | undefined;
  if (options.httpReferer !== undefined) {
    referer = options.httpReferer;
  } else if (env.PUBLIC_APP_URL !== undefined) {
    referer = env.PUBLIC_APP_URL;
  } else if (Object.hasOwn(process.env, "BETTER_AUTH_URL")) {
    referer = process.env.BETTER_AUTH_URL;
  } else {
    referer = "https://flycockpit.dev";
  }
  if (referer) headers["HTTP-Referer"] = referer;
  return headers;
}

export class OpenRouterProvider implements TranslationProvider {
  private readonly client: OpenAI;

  constructor(apiKey: string, attribution: OpenRouterAttributionOptions = {}) {
    this.client = new OpenAI({
      apiKey,
      baseURL: "https://openrouter.ai/api/v1",
      defaultHeaders: openRouterAttributionHeaders(attribution),
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
