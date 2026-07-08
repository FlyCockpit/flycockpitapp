import { env } from "@flycockpit/env/server";
import type { Context } from "hono";

const allowedOrigins = new Set(
  [env.BETTER_AUTH_URL, env.CORS_ORIGIN]
    .filter((value): value is string => typeof value === "string" && value.length > 0)
    .map((value) => new URL(value).origin),
);

export function validateSameSiteJsonRequest(c: Context): Response | null {
  const contentType = c.req.header("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return c.json({ error: "Request must be JSON." }, 415);
  }

  const secFetchSite = c.req.header("sec-fetch-site")?.toLowerCase();
  if (secFetchSite && !["same-origin", "same-site", "none"].includes(secFetchSite)) {
    return c.json({ error: "Cross-site requests are not allowed." }, 403);
  }

  const origin = c.req.header("origin");
  if (origin && !allowedOrigins.has(origin)) {
    return c.json({ error: "Cross-site requests are not allowed." }, 403);
  }

  return null;
}
