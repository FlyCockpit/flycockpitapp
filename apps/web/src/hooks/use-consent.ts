import { useSyncExternalStore } from "react";

import {
  acceptAll,
  type ConsentState,
  getConsentRecord,
  rejectAll,
  setConsent,
  subscribeConsent,
} from "@/lib/consent";

/**
 * React binding for the consent core. Uses `useSyncExternalStore` (the same
 * pattern as `use-session-flag.ts`) so the component participates in
 * concurrent rendering instead of mirroring external state through a banned
 * `useEffect`.
 *
 * The snapshot is the cached `ConsentCookie` reference, which only changes
 * when `setConsent` runs — so it is stable across renders and safe for the
 * store contract. SSR returns `null` (undecided): the banner is client-only
 * and never server-rendered, so there is no hydration mismatch.
 */
export function useConsent() {
  const record = useSyncExternalStore(subscribeConsent, getConsentRecord, () => null);

  return {
    /** True once the visitor has made (and not outgrown) an explicit choice. */
    hasDecision: record !== null,
    /** Active per-category decision; all-false when undecided. */
    consent: record?.cats ?? { functional: false, analytics: false, marketing: false },
    record,
    setConsent: (cats: ConsentState) => setConsent(cats),
    acceptAll,
    rejectAll,
  };
}
