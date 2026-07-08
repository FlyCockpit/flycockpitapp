/**
 * Public surface of the consent system. Import from here, not the internal
 * modules.
 *
 *   • Layer 1 (core)     — cookie + policy gate + subscribe. Legally
 *                          load-bearing; with no decision everything is off.
 *   • Layer 2 (adapters) — the only code that loads third-party tags.
 *   • registry.ts        — the one file an integrator edits.
 *
 * `startConsentEngine()` wires the registry to the live decision. Call it once
 * on mount (see `<ConsentManager>`); it is idempotent and safe under
 * React StrictMode double-invoke.
 */

import { applyConsent } from "./adapters";
import { getConsent, subscribeConsent } from "./core";
import { consentRegistry } from "./registry";

export {
  acceptAll,
  getConsentRecord,
  rejectAll,
  setConsent,
  subscribeConsent,
} from "./core";
export {
  type ConsentState,
  OPTIONAL_CATEGORIES,
  type OptionalCategory,
} from "./types";

let subscribed = false;

/**
 * Reconcile the registry with the current decision and keep it reconciled.
 * Returns an unsubscribe fn. Calling it again only re-reconciles (the
 * subscription is installed once) so it's safe to call from an effect that
 * may run twice.
 */
export function startConsentEngine(): () => void {
  // Reconcile immediately — this is what loads tags for a returning visitor
  // whose prior decision is already in the cookie.
  applyConsent(getConsent(), consentRegistry);
  if (subscribed) return () => {};
  subscribed = true;
  return subscribeConsent(() => applyConsent(getConsent(), consentRegistry));
}
