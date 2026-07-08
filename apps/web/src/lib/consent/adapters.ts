/**
 * Built-in adapters: the *only* place that knows how to load a third-party
 * tag. A non-technical integrator never touches this file — they list tags in
 * `registry.ts` and the engine routes each to the adapter named here.
 *
 * Honest limitation: revoking consent stops *future* loads and best-effort
 * removes the injected <script>, but JavaScript that already executed on this
 * page-view cannot be truly unloaded. Withdrawal takes full effect on the
 * next navigation. This is standard for client-side consent and is documented
 * for the user in the consent module notes.
 *
 * No inline <script> is ever injected (only `<script src>`), so this stays
 * compatible with the app's strict CSP (no 'unsafe-eval', no inline).
 */

import type { AdapterName, ConsentState, ConsentTag } from "./types";

type GtagFn = (...args: unknown[]) => void;
type FbqFn = ((...args: unknown[]) => void) & {
  callMethod?: (...args: unknown[]) => void;
  queue: unknown[][];
  loaded: boolean;
  version: string;
};
type ConsentWindow = Window & {
  dataLayer?: unknown[];
  gtag?: GtagFn;
  fbq?: FbqFn;
  _fbq?: FbqFn;
} & Record<string, unknown>;

type Adapter = {
  grant: (tag: ConsentTag) => void;
  revoke?: (tag: ConsentTag) => void;
};

const injected = new Set<string>();

function canTouchDom(): boolean {
  return typeof document !== "undefined" && typeof window !== "undefined";
}

function injectScript(key: string, src: string, attrs: Record<string, string> = {}): void {
  if (!canTouchDom() || injected.has(key)) return;
  const el = document.createElement("script");
  el.async = true;
  el.src = src;
  el.dataset.consentTag = key;
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  document.head.appendChild(el);
  injected.add(key);
}

function removeScript(key: string): void {
  if (!canTouchDom()) return;
  for (const el of document.querySelectorAll(`script[data-consent-tag="${CSS.escape(key)}"]`)) {
    el.remove();
  }
  injected.delete(key);
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// ── script ──────────────────────────────────────────────────────────────────
const scriptAdapter: Adapter = {
  grant(tag) {
    const src = str(tag.params?.src);
    if (!src) return;
    const attrs: Record<string, string> = {};
    for (const [k, v] of Object.entries(tag.params ?? {})) {
      if (k !== "src" && typeof v === "string") attrs[k] = v;
    }
    injectScript(tag.id, src, attrs);
  },
  revoke(tag) {
    removeScript(tag.id);
  },
};

// ── gtag (GA4 / Google Ads) ─────────────────────────────────────────────────
function ensureGtag(w: ConsentWindow): GtagFn {
  w.dataLayer = w.dataLayer || [];
  if (!w.gtag) {
    const dataLayer = w.dataLayer;
    w.gtag = (...args: unknown[]) => {
      dataLayer.push(args);
    };
  }
  return w.gtag;
}

const gtagAdapter: Adapter = {
  grant(tag) {
    if (!canTouchDom()) return;
    const id = str(tag.params?.measurementId);
    if (!id) return;
    const consentMode = tag.params?.mode === "consent-mode";
    const w = window as unknown as ConsentWindow;
    const gtag = ensureGtag(w);
    delete w[`ga-disable-${id}`];
    injectScript(`gtag:${id}`, `https://www.googletagmanager.com/gtag/js?id=${id}`);
    gtag("js", new Date());
    if (consentMode) {
      const grantAds = tag.category === "marketing";
      gtag("consent", "update", {
        analytics_storage: tag.category === "analytics" ? "granted" : "denied",
        ad_storage: grantAds ? "granted" : "denied",
        ad_user_data: grantAds ? "granted" : "denied",
        ad_personalization: grantAds ? "granted" : "denied",
      });
    }
    gtag("config", id);
  },
  revoke(tag) {
    if (!canTouchDom()) return;
    const id = str(tag.params?.measurementId);
    if (!id) return;
    const w = window as unknown as ConsentWindow;
    // The GA4 opt-out flag halts any further hits even if gtag.js is cached.
    w[`ga-disable-${id}`] = true;
    if (tag.params?.mode === "consent-mode" && w.gtag) {
      w.gtag("consent", "update", {
        analytics_storage: "denied",
        ad_storage: "denied",
        ad_user_data: "denied",
        ad_personalization: "denied",
      });
    }
    removeScript(`gtag:${id}`);
  },
};

// ── metaPixel (Facebook) ────────────────────────────────────────────────────
function ensureFbq(w: ConsentWindow): FbqFn {
  if (w.fbq) return w.fbq;
  const fbq = ((...args: unknown[]) => {
    if (fbq.callMethod) fbq.callMethod(...args);
    else fbq.queue.push(args);
  }) as FbqFn;
  fbq.queue = [];
  fbq.loaded = true;
  fbq.version = "2.0";
  w.fbq = fbq;
  w._fbq = w._fbq ?? fbq;
  return fbq;
}

const metaPixelAdapter: Adapter = {
  grant(tag) {
    if (!canTouchDom()) return;
    const pixelId = str(tag.params?.pixelId);
    if (!pixelId) return;
    const w = window as unknown as ConsentWindow;
    const fbq = ensureFbq(w);
    injectScript(`meta:${pixelId}`, "https://connect.facebook.net/en_US/fbevents.js");
    fbq("consent", "grant");
    fbq("init", pixelId);
    fbq("track", "PageView");
  },
  revoke(tag) {
    if (!canTouchDom()) return;
    const pixelId = str(tag.params?.pixelId);
    const w = window as unknown as ConsentWindow;
    if (w.fbq) w.fbq("consent", "revoke");
    if (pixelId) removeScript(`meta:${pixelId}`);
  },
};

// ── callback (first-party escape hatch) ─────────────────────────────────────
const callbackAdapter: Adapter = {
  grant(tag) {
    tag.onGrant?.();
  },
  revoke(tag) {
    tag.onRevoke?.();
  },
};

const ADAPTERS: Record<AdapterName, Adapter> = {
  script: scriptAdapter,
  gtag: gtagAdapter,
  metaPixel: metaPixelAdapter,
  callback: callbackAdapter,
};

// Tracks which tags are currently live so grant/revoke fire exactly once per
// transition (no double-injection, no revoke without a prior grant).
const live = new Set<string>();

/**
 * Reconcile the live tags with a consent decision. Idempotent: calling it
 * repeatedly with the same state is a no-op.
 */
export function applyConsent(state: ConsentState, registry: ConsentTag[]): void {
  for (const tag of registry) {
    const adapter = ADAPTERS[tag.adapter];
    if (!adapter) continue;
    const allowed = state[tag.category] === true;
    if (allowed && !live.has(tag.id)) {
      adapter.grant(tag);
      live.add(tag.id);
    } else if (!allowed && live.has(tag.id)) {
      adapter.revoke?.(tag);
      live.delete(tag.id);
    }
  }
}

/** Test-only: forget which tags are live and which scripts were injected. */
export function __resetAdapterState(): void {
  live.clear();
  injected.clear();
}
