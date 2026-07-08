import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "https://app.example.com",
  },
}));

const { registerSeoRoutes } = await import("./seo.js");

const protectedRouteFragments = ["/admin", "/dashboard", "/settings", "/portal"];

describe("SEO routes", () => {
  it("uses the configured canonical origin instead of request host headers", async () => {
    const app = new Hono();
    registerSeoRoutes(app);

    const sitemap = await app.request("/sitemap.xml", {
      headers: {
        host: "evil.example",
        "x-forwarded-host": "evil.example",
        "x-forwarded-proto": "http",
      },
    });

    expect(sitemap.status).toBe(200);
    const sitemapBody = await sitemap.text();
    expect(sitemapBody).toContain("https://app.example.com/en-US");
    expect(sitemapBody).not.toContain("evil.example");
    for (const protectedPath of protectedRouteFragments) {
      expect(sitemapBody).not.toContain(protectedPath);
    }

    const robots = await app.request("/robots.txt", {
      headers: { host: "evil.example", "x-forwarded-host": "evil.example" },
    });
    expect(await robots.text()).toContain("Sitemap: https://app.example.com/sitemap.xml");
  });

  it("keeps protected routes out of llms.txt", async () => {
    const app = new Hono();
    registerSeoRoutes(app);

    const llms = await app.request("/llms.txt");

    expect(llms.status).toBe(200);
    const llmsBody = await llms.text();
    for (const protectedPath of protectedRouteFragments) {
      expect(llmsBody).not.toContain(protectedPath);
    }
  });
});
