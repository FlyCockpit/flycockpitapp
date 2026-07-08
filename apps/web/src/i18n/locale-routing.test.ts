import { describe, expect, it } from "vitest";

import { decideLocaleRedirect } from "./redirect-to-default";

/**
 * Phase 2 added the `/$lang/...` URL prefix and a redirect at the root. The
 * `decideLocaleRedirect` helper is the pure decision boundary the route's
 * `beforeLoad` calls — we exercise it directly here so the tests don't have
 * to mount TanStack Router or import React-only modules.
 */
describe("decideLocaleRedirect", () => {
  it("redirects an unsupported locale (fr-FR) to the default locale + the rest of the path", () => {
    const result = decideLocaleRedirect({
      params: { lang: "fr-FR" },
      location: { pathname: "/fr-FR/dashboard", searchStr: "", hash: "" },
    });

    expect(result).not.toBeNull();
    expect(result?.href).toBe("/en-US/dashboard");
    expect(result?.replace).toBe(true);
  });

  it("treats a non-locale segment as part of the path and prepends the default locale", () => {
    const result = decideLocaleRedirect({
      params: { lang: "dashboard" },
      location: { pathname: "/dashboard", searchStr: "", hash: "" },
    });

    expect(result).not.toBeNull();
    expect(result?.href).toBe("/en-US/dashboard");
  });

  it("preserves search string and hash through the redirect", () => {
    const result = decideLocaleRedirect({
      params: { lang: "fr-FR" },
      location: { pathname: "/fr-FR/posts/foo", searchStr: "?ref=email", hash: "section-2" },
    });

    expect(result?.href).toBe("/en-US/posts/foo?ref=email#section-2");
  });

  it("returns null when the lang param is a supported locale (no redirect)", () => {
    const result = decideLocaleRedirect({
      params: { lang: "es-MX" },
      location: { pathname: "/es-MX/dashboard", searchStr: "", hash: "" },
    });

    expect(result).toBeNull();
  });

  it("returns null when lang is the default locale", () => {
    const result = decideLocaleRedirect({
      params: { lang: "en-US" },
      location: { pathname: "/en-US/", searchStr: "", hash: "" },
    });

    expect(result).toBeNull();
  });

  it("redirects an empty trailing path to /en-US (no double slash)", () => {
    const result = decideLocaleRedirect({
      params: { lang: "fr-FR" },
      location: { pathname: "/fr-FR", searchStr: "", hash: "" },
    });

    expect(result?.href).toBe("/en-US");
  });
});
