import { describe, expect, it } from "vitest";

import { buildTranslationPrompt } from "./prompt.js";

describe("buildTranslationPrompt", () => {
  it("emits Mexican-Spanish + no-vosotros guidance when targetLocale is es-MX", () => {
    const { system } = buildTranslationPrompt({
      source: "Hello",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
    });
    expect(system).toMatch(/Mexican Spanish/);
    expect(system).toMatch(/vosotros/);
  });

  it("does not emit the Mexican-Spanish rule for non-es-MX targets", () => {
    const { system } = buildTranslationPrompt({
      source: "Hello",
      sourceLocale: "en-US",
      targetLocale: "fr-FR",
      contentKind: "plaintext",
    });
    expect(system).not.toMatch(/Mexican Spanish/);
    expect(system).not.toMatch(/vosotros/);
  });

  it("warns about preserving {{placeholder}} syntax for plaintext", () => {
    const { system } = buildTranslationPrompt({
      source: "Hello {{name}}",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
    });
    expect(system).toMatch(/\{\{name\}\}|placeholder|braces/i);
  });

  it("warns about preserving asset: URLs and Markdown syntax for markdown", () => {
    const { system } = buildTranslationPrompt({
      source: "# Heading",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "markdown",
    });
    expect(system).toMatch(/Markdown/);
    expect(system).toMatch(/asset:/);
  });

  it("instructs the model to output ONLY the JSON when contentKind is json", () => {
    const { system } = buildTranslationPrompt({
      source: '{"a":"b"}',
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "json",
    });
    expect(system).toMatch(/ONLY the JSON/);
  });

  it("wraps the source in explicit data delimiters in the user message", () => {
    const { system, user } = buildTranslationPrompt({
      source: "Hello world",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
    });
    expect(system).toMatch(/untrusted user-authored data/i);
    expect(user).toBe("<source>\nHello world\n</source>");
  });

  it("names both the source and target locale in the system message", () => {
    const { system } = buildTranslationPrompt({
      source: "Hello",
      sourceLocale: "en-US",
      targetLocale: "es-MX",
      contentKind: "plaintext",
    });
    expect(system).toMatch(/en-US/);
    expect(system).toMatch(/es-MX/);
  });
});
