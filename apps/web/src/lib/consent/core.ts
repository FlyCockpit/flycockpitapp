/**
 * Framework-agnostic consent state. No React, no UI — just the cookie, the
 * policy-version gate, and a subscribe/notify channel. This is the legally
 * load-bearing layer: when there is no current decision, every optional
 * category reads `false`, so the adapters never fire and nothing
 * non-essential loads. The UI and the React hook are thin wrappers over this.
 *
 * SSR-safe: every `document` access is guarded so the module can be imported
 * on the server (the SSR article routes) without throwing.
 */

import { CONSENT_COOKIE_MAX_AGE_DAYS, CONSENT_COOKIE_NAME, CONSENT_POLICY_VERSION } from "./policy";
import type { ConsentCookie, ConsentState } from "./types";
import { OPTIONAL_CATEGORIES } from "./types";

/** Stable reference returned whenever there is no valid current decision. */
const NO_CONSENT: ConsentState = Object.freeze({
  functional: false,
  analytics: false,
  marketing: false,
});

type Listener = () => void;
const listeners = new Set<Listener>();

function isBrowser(): boolean {
  return typeof document !== "undefined";
}

function readCookieRaw(name: string): string | null {
  if (!isBrowser()) return null;
  const prefix = `${name}=`;
  for (const part of document.cookie ? document.cookie.split("; ") : []) {
    if (part.startsWith(prefix)) return decodeURIComponent(part.slice(prefix.length));
  }
  return null;
}

function writeCookie(name: string, value: string, maxAgeDays: number): void {
  if (!isBrowser()) return;
  const maxAge = Math.floor(maxAgeDays * 24 * 60 * 60);
  const isHttps = typeof window !== "undefined" && window.location?.protocol === "https:";
  const secure = isHttps ? "; Secure" : "";
  // biome-ignore lint/suspicious/noDocumentCookie: consent must be read/written synchronously before any non-essential script runs; the async Cookie Store API cannot gate a synchronous pre-consent check.
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure}`;
}

function randomId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `c_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}

function parseCookie(raw: string | null): ConsentCookie | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const p = parsed as Record<string, unknown>;
  if (
    typeof p.v !== "number" ||
    typeof p.ts !== "number" ||
    typeof p.id !== "string" ||
    typeof p.cats !== "object" ||
    p.cats === null
  ) {
    return null;
  }
  // A decision made under an older policy version is treated as "no decision"
  // so the banner re-appears and the visitor re-consents under the new policy.
  if (p.v !== CONSENT_POLICY_VERSION) return null;

  const rawCats = p.cats as Record<string, unknown>;
  const cats: ConsentState = { functional: false, analytics: false, marketing: false };
  for (const c of OPTIONAL_CATEGORIES) {
    cats[c] = rawCats[c] === true;
  }
  return { v: p.v, ts: p.ts, id: p.id, cats };
}

// Parse the cookie once and reuse the object reference. `useSyncExternalStore`
// requires a stable snapshot between renders; recomputing on every read would
// return a fresh object and loop. The cache is invalidated only by
// `setConsent` (this tab) and `__resetConsentCache` (tests).
let cached: ConsentCookie | null | undefined;

function current(): ConsentCookie | null {
  if (cached === undefined) cached = parseCookie(readCookieRaw(CONSENT_COOKIE_NAME));
  return cached;
}

/** True once the visitor has made (and not outgrown) an explicit choice. */
export function hasConsentDecision(): boolean {
  return current() !== null;
}

/** The active per-category decision, or all-`false` when undecided. */
export function getConsent(): ConsentState {
  return current()?.cats ?? NO_CONSENT;
}

/** The full stored record (version, timestamp, anon id) or `null` if undecided. */
export function getConsentRecord(): ConsentCookie | null {
  return current();
}

/** Stable anonymous id for correlating the client decision with the server log. */
export function getConsentAnonId(): string | null {
  return current()?.id ?? null;
}

/** Persist a decision, refresh the cache, and notify subscribers. */
export function setConsent(cats: ConsentState): ConsentCookie {
  const record: ConsentCookie = {
    v: CONSENT_POLICY_VERSION,
    ts: Date.now(),
    // Keep a stable anon id across re-decisions so the server log can thread
    // a visitor's consent history without any account or PII.
    id: current()?.id ?? randomId(),
    cats: { ...cats },
  };
  writeCookie(CONSENT_COOKIE_NAME, JSON.stringify(record), CONSENT_COOKIE_MAX_AGE_DAYS);
  cached = record;
  for (const l of [...listeners]) l();
  return record;
}

export function acceptAll(): ConsentCookie {
  return setConsent({ functional: true, analytics: true, marketing: true });
}

export function rejectAll(): ConsentCookie {
  return setConsent({ functional: false, analytics: false, marketing: false });
}

/** Subscribe to decision changes. Returns an unsubscribe fn. */
export function subscribeConsent(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Test-only: drop the in-memory cache so a freshly written cookie is re-read. */
export function __resetConsentCache(): void {
  cached = undefined;
}
