import { createInstance } from "i18next";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";

import enValidation from "../locales/en-US/validation.json";
import esValidation from "../locales/es-MX/validation.json";
import { installZodErrorMap } from "./zod";

/**
 * Smoke test for the locale-aware Zod error map. Verifies:
 *   1. A bare `z.string().email()` failure renders the en-US copy when the
 *      active language is `en-US`.
 *   2. Switching the i18n instance to `es-MX` causes the next parse to render
 *      the Spanish copy without any per-form change.
 *   3. The `tooSmall.string` branch interpolates `{{minimum}}` correctly.
 */
describe("installZodErrorMap", () => {
  const i18n = createInstance();

  beforeAll(async () => {
    await i18n.init({
      lng: "en-US",
      fallbackLng: "en-US",
      ns: ["validation"],
      defaultNS: "validation",
      resources: {
        "en-US": { validation: enValidation },
        "es-MX": { validation: esValidation },
      },
      interpolation: { escapeValue: false },
    });
    installZodErrorMap(i18n);
  });

  afterEach(async () => {
    // Reset to en-US between tests so case order doesn't matter.
    await i18n.changeLanguage("en-US");
  });

  it("renders the en-US email message when the language is en-US", () => {
    const result = z.string().email().safeParse("not-an-email");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe(enValidation.invalidString.email);
    }
  });

  it("re-renders in es-MX after changeLanguage", async () => {
    await i18n.changeLanguage("es-MX");
    const result = z.string().email().safeParse("not-an-email");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe(esValidation.invalidString.email);
    }
  });

  it("interpolates {{minimum}} into tooSmall.string in en-US", () => {
    const result = z.string().min(8).safeParse("abc");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe("Must be at least 8 characters.");
    }
  });

  it("interpolates {{minimum}} into tooSmall.string in es-MX", async () => {
    await i18n.changeLanguage("es-MX");
    const result = z.string().min(8).safeParse("abc");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe("Debe tener al menos 8 caracteres.");
    }
  });

  it("treats undefined input as required", () => {
    const result = z.object({ name: z.string() }).safeParse({});
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe(enValidation.required);
    }
  });
});
