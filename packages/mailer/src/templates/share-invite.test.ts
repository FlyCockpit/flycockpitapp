import { describe, expect, it } from "vitest";
import { renderShareInvite } from "./share-invite";

const baseArgs = {
  ownerName: "Ada Admin",
  instanceName: "Devbox",
  scopes: ["Agent access", "Project files"],
  acceptUrl: "https://app.example.test/en-US/instances",
  expiresAt: new Date("2026-01-08T12:00:00Z"),
  existingUser: true,
  locale: "en-US",
};

describe("renderShareInvite", () => {
  it("renders the English invitation", () => {
    const { subject, html } = renderShareInvite(baseArgs);
    expect(subject).toContain("invited");
    expect(html).toContain("Ada Admin");
    expect(html).toContain("Devbox");
    expect(html).toContain("Agent access");
    expect(html).toContain("Review invitation");
  });

  it("renders the Spanish invitation", () => {
    const { subject, html } = renderShareInvite({
      ...baseArgs,
      existingUser: false,
      locale: "es-MX",
    });
    expect(subject).toContain("invitaron");
    expect(html).toContain("Crear cuenta");
  });

  it("falls back to English for unsupported locales", () => {
    const { html } = renderShareInvite({ ...baseArgs, locale: "fr-FR" });
    expect(html).toContain('lang="en-US"');
  });

  it("escapes user-provided content", () => {
    const { html } = renderShareInvite({
      ...baseArgs,
      ownerName: '<script>alert("x")</script>',
      instanceName: "<img src=x onerror=alert(1)>",
    });
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;");
  });
});
