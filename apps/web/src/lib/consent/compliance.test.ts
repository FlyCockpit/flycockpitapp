import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { __resetAdapterState, applyConsent } from "./adapters";
import { __resetConsentCache, acceptAll, getConsent, rejectAll, setConsent } from "./core";
import type { ConsentTag } from "./types";

/**
 * The compliance gate. This is the legally load-bearing assertion: with a
 * tag configured, **nothing non-essential is injected before the visitor
 * opts in**, it loads only after the matching category is granted, and
 * withdrawal removes it.
 *
 * The plan called for an agent-browser/docker end-to-end check, but the repo
 * testing rule forbids E2E and CI has no browser, so this proves the same
 * invariant deterministically at the injection boundary (the thing that
 * *causes* the network request) instead of sniffing real traffic. The
 * agent-browser walkthrough remains documented in
 * the consent module notes as an optional manual verification.
 */

type ScriptNode = {
  async: boolean;
  src: string;
  dataset: { consentTag?: string };
  setAttribute: (k: string, v: string) => void;
  remove: () => void;
};

let headScripts: ScriptNode[] = [];

function installDom() {
  headScripts = [];
  const fakeDocument = {
    createElement(): ScriptNode {
      const node: ScriptNode = {
        async: false,
        src: "",
        dataset: {},
        setAttribute() {},
        remove() {
          headScripts = headScripts.filter((s) => s !== node);
        },
      };
      return node;
    },
    head: {
      appendChild(node: ScriptNode) {
        headScripts.push(node);
      },
    },
    querySelectorAll(selector: string): ScriptNode[] {
      const match = /data-consent-tag="([^"]+)"/.exec(selector);
      const key = match?.[1];
      return headScripts.filter((s) => s.dataset.consentTag === key);
    },
    cookie: "",
  };
  const jar = new Map<string, string>();
  Object.defineProperty(fakeDocument, "cookie", {
    get: () => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; "),
    set: (input: string) => {
      const [pair, ...attrs] = input.split("; ");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      if (attrs.some((a) => /^max-age=0$/i.test(a))) jar.delete(name);
      else jar.set(name, pair.slice(eq + 1));
    },
  });
  Object.defineProperty(globalThis, "document", { configurable: true, value: fakeDocument });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { location: { protocol: "https:" } },
  });
  Object.defineProperty(globalThis, "CSS", {
    configurable: true,
    value: { escape: (s: string) => s },
  });
}

function uninstallDom() {
  Reflect.deleteProperty(globalThis, "document");
  Reflect.deleteProperty(globalThis, "window");
  Reflect.deleteProperty(globalThis, "CSS");
}

const registry: ConsentTag[] = [
  {
    id: "analytics-probe",
    category: "analytics",
    adapter: "script",
    params: { src: "https://probe.example/a.js" },
  },
  { id: "ga4", category: "analytics", adapter: "gtag", params: { measurementId: "G-TEST" } },
  { id: "meta", category: "marketing", adapter: "metaPixel", params: { pixelId: "1234567890" } },
];

const srcs = () => headScripts.map((s) => s.src);

describe("consent compliance — no non-essential load before opt-in", () => {
  beforeEach(() => {
    installDom(); // fresh empty cookie jar + clean DOM each test
    __resetConsentCache();
    __resetAdapterState();
  });

  afterEach(() => {
    uninstallDom();
  });

  it("injects NOTHING before a decision is made", () => {
    expect(getConsent()).toEqual({ functional: false, analytics: false, marketing: false });
    applyConsent(getConsent(), registry);
    expect(headScripts).toHaveLength(0);
  });

  it("loads analytics + marketing tags only after Accept all", () => {
    applyConsent(getConsent(), registry); // pre-consent: still nothing
    expect(headScripts).toHaveLength(0);

    acceptAll();
    applyConsent(getConsent(), registry);

    expect(srcs()).toContain("https://probe.example/a.js");
    expect(srcs().some((s) => s.includes("googletagmanager.com/gtag/js?id=G-TEST"))).toBe(true);
    expect(srcs().some((s) => s.includes("connect.facebook.net"))).toBe(true);
  });

  it("keeps marketing OFF when only analytics is granted", () => {
    setConsent({ functional: false, analytics: true, marketing: false });
    applyConsent(getConsent(), registry);

    expect(srcs()).toContain("https://probe.example/a.js");
    expect(srcs().some((s) => s.includes("connect.facebook.net"))).toBe(false);
  });

  it("removes the injected script when consent is withdrawn", () => {
    acceptAll();
    applyConsent(getConsent(), registry);
    expect(headScripts.length).toBeGreaterThan(0);

    rejectAll();
    applyConsent(getConsent(), registry);

    expect(srcs()).not.toContain("https://probe.example/a.js");
  });
});
