import type { ConsentTag } from "./types";

/**
 * ── The only file a non-technical integrator edits ──────────────────────────
 *
 * List the third-party tags your site uses. Each entry is gated behind the
 * named consent `category`; the matching built-in `adapter` knows how to load
 * (and best-effort unload) it. Nothing here loads until the visitor opts the
 * category in — that guarantee lives in the engine, not in this list, so you
 * cannot get it wrong by editing this file.
 *
 * Uncomment and fill in the IDs for the services you actually use. An empty
 * registry is a valid, fully-compliant no-op (the banner won't even show if
 * there are no non-essential cookies — see `<ConsentManager>`).
 *
 * Adapters:
 *   • "gtag"      — Google Analytics 4 / Google Ads. `params.measurementId`
 *                   required. `params.mode` defaults to "block" (strictest:
 *                   gtag.js is not loaded at all until consent). Set
 *                   `mode: "consent-mode"` to instead use Google Consent
 *                   Mode v2 (loads gtag.js with all signals defaulted to
 *                   denied, then flips on consent — preserves modeled
 *                   conversions but the script itself loads pre-consent).
 *   • "metaPixel" — Facebook/Meta Pixel. `params.pixelId` required. The pixel
 *                   has no clean consent-default, so it is never injected
 *                   until `marketing` is granted. This is the only compliant
 *                   pattern for Meta.
 *   • "script"    — any deferred <script src>. `params.src` required; any
 *                   other string params become attributes (e.g. Plausible's
 *                   `"data-domain"`). For first-party-friendly analytics.
 *   • "callback"  — escape hatch for cookies the app sets itself. Provide
 *                   `onGrant` / `onRevoke` directly on the entry.
 *
 * After adding a host (googletagmanager.com, connect.facebook.net, …) you
 * must also allow it in the server CSP `script-src` — see
 * the consent module notes § CSP.
 */
export const consentRegistry: ConsentTag[] = [
  // {
  //   id: "ga4",
  //   category: "analytics",
  //   adapter: "gtag",
  //   params: { measurementId: "G-XXXXXXXXXX" /*, mode: "consent-mode" */ },
  // },
  // {
  //   id: "meta-pixel",
  //   category: "marketing",
  //   adapter: "metaPixel",
  //   params: { pixelId: "0000000000000000" },
  // },
  // {
  //   id: "plausible",
  //   category: "analytics",
  //   adapter: "script",
  //   params: { src: "https://plausible.io/js/script.js", "data-domain": "example.com" },
  // },
];
