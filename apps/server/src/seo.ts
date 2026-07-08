import { DEFAULT_LOCALE, SUPPORTED_LOCALES } from "@flycockpit/config/locales";
import { env } from "@flycockpit/env/server";
import type { Env, Hono } from "hono";

/**
 * SEO / discoverability endpoints: `/robots.txt`, `/sitemap.xml`, `/llms.txt`.
 *
 * Why these live as explicit Hono routes (not static files in apps/web/public):
 *   - They must win over BOTH the static-asset `serveStatic` and the SSR
 *     catch-all (`app.all("/*")`). Registered before those, Hono's
 *     first-match-wins ordering guarantees `/$lang/...` never swallows them and
 *     returns the SPA HTML shell (the bug in analysis/10 finding 3).
 *   - The base URL is the configured canonical app origin, so public cached
 *     responses never reflect spoofed Host / X-Forwarded-* headers.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ MAINTENANCE: `PUBLIC_PATHS` is the single source of truth for the public, │
 * │ indexable surface of the app. Update it (and sitemap.md) whenever you add │
 * │ or remove a public page — see the "SEO discoverability files" rule in     │
 * │ AGENTS.md. Auth-gated and admin routes are intentionally excluded.        │
 * └─────────────────────────────────────────────────────────────────────────┘
 */

type PublicPath = {
  /** Path WITHOUT the `/$lang` prefix; "" is the locale root. Starts with "/". */
  path: string;
  /** Human label used in llms.txt. */
  title: string;
  /** sitemap.xml <changefreq> hint. */
  changefreq: "daily" | "weekly" | "monthly";
  /** sitemap.xml <priority> 0.0–1.0. */
  priority: number;
};

// Public, indexable content pages only. Authenticated pages, admin routes,
// utility auth/device routes, demos, and other non-indexable surfaces stay out
// of sitemap.xml/llms.txt even if they are technically reachable.
const PUBLIC_PATHS: PublicPath[] = [
  { path: "", title: "Home", changefreq: "weekly", priority: 1.0 },
  { path: "/about", title: "About", changefreq: "monthly", priority: 0.7 },
  // The cookie-policy page ships with the consent system. If you rip out consent
  // (the consent module notes), remove this entry too.
  { path: "/cookie-policy", title: "Cookie policy", changefreq: "monthly", priority: 0.3 },
];

const APP_NAME = process.env.VITE_APP_NAME || "App";

/** Absolute canonical origin for public cached SEO files. */
function baseUrl(): string {
  return new URL(env.BETTER_AUTH_URL).origin;
}

function localizedUrl(base: string, locale: string, path: string): string {
  return `${base}/${locale}${path}`;
}

function renderRobots(base: string): string {
  return [
    "User-agent: *",
    "Allow: /",
    // The admin tree is 404-hidden, but spell it out so crawlers never probe it.
    "Disallow: /*/admin",
    `Sitemap: ${base}/sitemap.xml`,
    "",
  ].join("\n");
}

function renderSitemap(base: string): string {
  const urls = PUBLIC_PATHS.flatMap((p) =>
    SUPPORTED_LOCALES.map((locale) => {
      const loc = localizedUrl(base, locale, p.path);
      // hreflang alternates: tell crawlers each locale is a translation of the
      // others, with x-default pointing at the default locale.
      const alternates = [
        ...SUPPORTED_LOCALES.map(
          (alt) =>
            `    <xhtml:link rel="alternate" hreflang="${alt}" href="${localizedUrl(base, alt, p.path)}" />`,
        ),
        `    <xhtml:link rel="alternate" hreflang="x-default" href="${localizedUrl(base, DEFAULT_LOCALE, p.path)}" />`,
      ].join("\n");
      return [
        "  <url>",
        `    <loc>${loc}</loc>`,
        alternates,
        `    <changefreq>${p.changefreq}</changefreq>`,
        `    <priority>${p.priority.toFixed(1)}</priority>`,
        "  </url>",
      ].join("\n");
    }),
  ).join("\n");

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
    urls,
    "</urlset>",
    "",
  ].join("\n");
}

function renderLlms(base: string): string {
  const links = PUBLIC_PATHS.map(
    (p) => `- [${p.title}](${localizedUrl(base, DEFAULT_LOCALE, p.path)})`,
  ).join("\n");
  return [
    `# ${APP_NAME}`,
    "",
    `> ${APP_NAME} is a mobile-first PWA. Every URL is prefixed with a locale segment (e.g. \`/${DEFAULT_LOCALE}/...\`); supported locales: ${SUPPORTED_LOCALES.join(", ")}. Most of the app sits behind authentication; the pages below are the public surface.`,
    "",
    "## Pages",
    "",
    links,
    "",
    "## Notes",
    "",
    "- Authenticated and admin areas are not listed here and are not crawlable.",
    `- The canonical sitemap is at ${base}/sitemap.xml.`,
    "",
  ].join("\n");
}

/**
 * Register the SEO routes. Call this BEFORE the static-asset middleware and the
 * SSR catch-all in apps/server/src/index.ts.
 */
export function registerSeoRoutes<E extends Env>(app: Hono<E>): Hono<E> {
  app.get("/robots.txt", (c) =>
    c.text(renderRobots(baseUrl()), 200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    }),
  );

  app.get("/sitemap.xml", (c) =>
    c.body(renderSitemap(baseUrl()), 200, {
      "Content-Type": "application/xml; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    }),
  );

  app.get("/llms.txt", (c) =>
    c.text(renderLlms(baseUrl()), 200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    }),
  );

  return app;
}
