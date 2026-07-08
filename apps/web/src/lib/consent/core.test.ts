import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  __resetConsentCache,
  acceptAll,
  getConsent,
  getConsentAnonId,
  hasConsentDecision,
  rejectAll,
  setConsent,
  subscribeConsent,
} from "./core";
import { CONSENT_COOKIE_NAME, CONSENT_POLICY_VERSION } from "./policy";

/**
 * The consent core is the legally load-bearing layer: with no current
 * decision every optional category must read `false` so the adapters never
 * fire. These tests pin that invariant plus the policy-version gate.
 */

/**
 * The web test env is `node` (no jsdom — component tests are out of scope per
 * the testing rule). The consent core only needs `document.cookie`, so we
 * stand up a minimal in-memory cookie jar with just enough of the browser's
 * get/set semantics (concatenated read, `Max-Age=0` deletes).
 *
 * The fake `document` owns the production read/write codepath (the core's
 * own `document.cookie` access still runs through it); the test helpers seed
 * state by mutating the jar directly, so test code never assigns
 * `document.cookie` and needs no lint suppression.
 */
const jar = new Map<string, string>();

function installCookieJar() {
  jar.clear();
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      get cookie() {
        return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
      },
      set cookie(input: string) {
        const [pair, ...attrs] = input.split("; ");
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq);
        const value = pair.slice(eq + 1);
        const expired = attrs.some((a) => /^max-age=0$/i.test(a) || /^expires=/i.test(a));
        if (expired) jar.delete(name);
        else jar.set(name, value);
      },
    },
  });
}

function uninstallCookieJar() {
  Reflect.deleteProperty(globalThis, "document");
}

function clearConsentCookie() {
  jar.delete(CONSENT_COOKIE_NAME);
  __resetConsentCache();
}

function writeRawCookie(value: string) {
  // Seed the jar exactly as the browser would store it (the core encodes on
  // write and decodes on read), without the test touching `document.cookie`.
  jar.set(CONSENT_COOKIE_NAME, encodeURIComponent(value));
  __resetConsentCache();
}

describe("consent core", () => {
  beforeEach(() => {
    installCookieJar();
    clearConsentCookie();
  });

  afterEach(() => {
    uninstallCookieJar();
  });

  it("defaults to no decision and all-false categories", () => {
    expect(hasConsentDecision()).toBe(false);
    expect(getConsent()).toEqual({ functional: false, analytics: false, marketing: false });
    expect(getConsentAnonId()).toBeNull();
  });

  it("persists a decision and reflects it on the next read", () => {
    setConsent({ functional: true, analytics: false, marketing: true });
    __resetConsentCache(); // force a real cookie round-trip

    expect(hasConsentDecision()).toBe(true);
    expect(getConsent()).toEqual({ functional: true, analytics: false, marketing: true });
    expect(getConsentAnonId()).toMatch(/.+/);
  });

  it("acceptAll / rejectAll set every optional category", () => {
    acceptAll();
    expect(getConsent()).toEqual({ functional: true, analytics: true, marketing: true });
    rejectAll();
    expect(getConsent()).toEqual({ functional: false, analytics: false, marketing: false });
  });

  it("keeps a stable anon id across re-decisions", () => {
    rejectAll();
    const first = getConsentAnonId();
    acceptAll();
    expect(getConsentAnonId()).toBe(first);
  });

  it("treats a decision from an older policy version as no decision", () => {
    writeRawCookie(
      JSON.stringify({
        v: CONSENT_POLICY_VERSION - 1,
        ts: Date.now(),
        id: "old",
        cats: { functional: true, analytics: true, marketing: true },
      }),
    );
    expect(hasConsentDecision()).toBe(false);
    expect(getConsent()).toEqual({ functional: false, analytics: false, marketing: false });
  });

  it("treats a malformed cookie as no decision", () => {
    writeRawCookie("not json {");
    expect(hasConsentDecision()).toBe(false);
    expect(getConsent().marketing).toBe(false);
  });

  it("notifies subscribers on change and stops after unsubscribe", () => {
    const listener = vi.fn();
    const unsubscribe = subscribeConsent(listener);

    acceptAll();
    expect(listener).toHaveBeenCalledTimes(1);

    unsubscribe();
    rejectAll();
    expect(listener).toHaveBeenCalledTimes(1);
  });
});
