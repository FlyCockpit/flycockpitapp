import { describe, expect, it } from "vitest";

import { renderVerifyEmail } from "./verify-email";

describe("renderVerifyEmail", () => {
  it("returns en-US subject + en-US strings + lang='en-US' for the default locale", () => {
    const { subject, html } = renderVerifyEmail({
      url: "https://example.com/verify?token=abc",
      locale: "en-US",
    });

    expect(subject).toBe("Verify your email");
    expect(html).toContain('<html lang="en-US">');
    expect(html).toContain("Verify your email");
    expect(html).toContain(
      "Click the button below to verify your email address and activate your account.",
    );
    expect(html).toContain("https://example.com/verify?token=abc");
  });

  it("returns the Spanish bundle + lang='es-MX' for the es-MX locale", () => {
    const { subject, html } = renderVerifyEmail({
      url: "https://example.com/verify?token=abc",
      locale: "es-MX",
    });

    // The Spanish bundle is populated by `pnpm i18n:translate:mailer`. The
    // assertion is on the *shape* of the response, not the exact translation,
    // so the test doesn't break if the Spanish copy is reworded.
    expect(subject).not.toBe("");
    expect(html).toContain('<html lang="es-MX">');
    // Some marker we can confidently expect: the URL we passed in survives.
    expect(html).toContain("https://example.com/verify?token=abc");
    // None of the en-US literals leak into the Spanish render (they would
    // indicate per-key fallback to en-US, i.e. an unpopulated bundle).
    expect(html).not.toContain(
      "Click the button below to verify your email address and activate your account.",
    );
  });

  it("falls back to en-US when an unsupported locale is passed", () => {
    const { subject, html } = renderVerifyEmail({
      url: "https://example.com/verify?token=abc",
      locale: "fr-FR",
    });

    expect(subject).toBe("Verify your email");
    expect(html).toContain('<html lang="en-US">');
    expect(html).toContain(
      "Click the button below to verify your email address and activate your account.",
    );
  });

  it("escapes href attribute values", () => {
    const { html } = renderVerifyEmail({
      url: "https://example.com/verify?token=abc&next=https%3A%2F%2Fapp.example%2F",
      locale: "en-US",
    });

    expect(html).toContain(
      'href="https://example.com/verify?token=abc&amp;next=https%3A%2F%2Fapp.example%2F"',
    );
  });

  it("rejects non-http verification URLs", () => {
    expect(() =>
      renderVerifyEmail({
        url: "javascript:alert(1)",
        locale: "en-US",
      }),
    ).toThrow("Email link must use HTTP or HTTPS.");
  });
});
