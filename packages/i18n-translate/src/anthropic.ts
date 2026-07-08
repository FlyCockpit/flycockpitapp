import Anthropic from "@anthropic-ai/sdk";
import { env } from "@flycockpit/env/shared";
import { buildTranslationPrompt } from "./prompt.js";
import type { TranslateInput, TranslateResult, TranslationProvider } from "./types.js";

const DEFAULT_MODEL = "claude-haiku-4-5";

const MAX_OUTPUT_TOKENS = 8192;

export class AnthropicDirectProvider implements TranslationProvider {
  private readonly client: Anthropic;

  constructor(apiKey: string) {
    this.client = new Anthropic({ apiKey });
  }

  async translate(input: TranslateInput): Promise<TranslateResult> {
    const model = input.model ?? env.TRANSLATION_MODEL ?? DEFAULT_MODEL;
    const { system, user } = buildTranslationPrompt({
      source: input.source,
      sourceLocale: input.sourceLocale,
      targetLocale: input.targetLocale,
      contentKind: input.contentKind,
    });

    const response = await this.client.messages.create({
      model,
      max_tokens: MAX_OUTPUT_TOKENS,
      temperature: 0,
      system,
      messages: [{ role: "user", content: user }],
    });

    if (response.stop_reason === "max_tokens") {
      throw new Error(
        `[i18n-translate] Anthropic truncated the translation at max_tokens (model=${response.model ?? model})`,
      );
    }

    const text = response.content
      .filter((block): block is Anthropic.TextBlock => block.type === "text")
      .map((block) => block.text)
      .join("");

    if (text.length === 0) {
      throw new Error(`[i18n-translate] Anthropic returned an empty completion (model=${model})`);
    }

    return {
      text,
      model: response.model ?? model,
    };
  }
}
