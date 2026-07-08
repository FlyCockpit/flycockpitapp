export interface TranslateInput {
  /** Markdown / plaintext / JSON-stringified content to translate. */
  source: string;
  /** Source locale, BCP 47 (e.g. "en-US"). */
  sourceLocale: string;
  /** Target locale, BCP 47 (e.g. "es-MX"). */
  targetLocale: string;
  /** Hint that controls preservation rules baked into the system prompt. */
  contentKind: "markdown" | "plaintext" | "json";
  /** Per-call model override; otherwise the provider falls back to env / default. */
  model?: string;
}

export interface TranslateResult {
  /** Translated text exactly as the model returned it (already stripped of any wrapping). */
  text: string;
  /** Resolved model id used for the call, e.g. "anthropic/claude-haiku-4-5". */
  model: string;
}

export interface TranslationProvider {
  translate(input: TranslateInput): Promise<TranslateResult>;
}
