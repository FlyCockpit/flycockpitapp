import { describe, expect, it } from "vitest";

import { renderTwoFactorOtp } from "./two-factor-otp";

describe("renderTwoFactorOtp", () => {
  it("returns en-US subject + en-US strings + lang='en-US' for the default locale", () => {
    const { subject, html } = renderTwoFactorOtp({
      otp: "123456",
      locale: "en-US",
    });

    expect(subject).toBe("Your verification code");
    expect(html).toContain('<html lang="en-US">');
    expect(html).toContain("Your verification code");
    expect(html).toContain("Use the code below to finish signing in.");
    // The OTP itself is rendered into the body.
    expect(html).toContain("123456");
  });

  it("returns the Spanish bundle + lang='es-MX' for the es-MX locale", () => {
    const { subject, html } = renderTwoFactorOtp({
      otp: "654321",
      locale: "es-MX",
    });

    // Assert on the shape, not the exact translation, so the test doesn't break
    // if the Spanish copy is reworded.
    expect(subject).not.toBe("");
    expect(html).toContain('<html lang="es-MX">');
    // The OTP survives into the Spanish render.
    expect(html).toContain("654321");
    // None of the en-US literals leak into the Spanish render (they would
    // indicate per-key fallback to en-US, i.e. an unpopulated bundle).
    expect(html).not.toContain("Use the code below to finish signing in.");
  });

  it("falls back to en-US when an unsupported locale is passed", () => {
    const { subject, html } = renderTwoFactorOtp({
      otp: "111222",
      locale: "fr-FR",
    });

    expect(subject).toBe("Your verification code");
    expect(html).toContain('<html lang="en-US">');
    expect(html).toContain("Use the code below to finish signing in.");
  });

  it("HTML-escapes the OTP value before interpolating it into the body", () => {
    const { html } = renderTwoFactorOtp({
      otp: "<b>&\"'",
      locale: "en-US",
    });

    expect(html).toContain("&lt;b&gt;&amp;&quot;&#39;");
    expect(html).not.toContain("<b>&\"'");
  });
});
