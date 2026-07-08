import { lazy, Suspense, useRef } from "react";

import { useConsent } from "@/hooks/use-consent";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { startConsentEngine } from "@/lib/consent";
import { consentRegistry } from "@/lib/consent/registry";
import { useConsentUi } from "@/stores/consent-ui";

// The consent UI is the only thing pulling the overlay machinery onto the eager
// path: ConsentPreferences → ResponsiveDialog → base-ui Dialog + vaul Drawer,
// and ConsentBanner → Button/Link. None of it is needed at first paint — the
// gating engine below (cheap, dependency-free) is what actually blocks
// non-essential scripts. Split both into their own chunks so vaul + the dialog
// only load when a banner shows or the user opens preferences.
const ConsentBanner = lazy(() =>
  import("./consent-banner").then((m) => ({ default: m.ConsentBanner })),
);
const ConsentPreferences = lazy(() =>
  import("./consent-preferences").then((m) => ({ default: m.ConsentPreferences })),
);

/**
 * Single mount point for the consent system. Started once from the root
 * layout. It:
 *   1. boots the gating engine (reconciles tags with the stored decision and
 *      keeps them reconciled),
 *   2. shows the first-visit banner only when there is something to consent
 *      to AND no current decision,
 *   3. hosts the preferences modal (re-openable from anywhere via the store).
 *
 * If the tag registry is empty there are no non-essential cookies, so no
 * banner is shown — an empty registry is a fully compliant no-op.
 */
export function ConsentManager() {
  // `startConsentEngine` returns its own unsubscribe, which doubles as the
  // effect cleanup. This is the sanctioned one-time external-sync escape hatch.
  useMountEffect(() => startConsentEngine());

  const { hasDecision } = useConsent();
  const { preferencesOpen, setPreferencesOpen, openPreferences } = useConsentUi();

  const hasOptionalTags = consentRegistry.length > 0;
  const showBanner = hasOptionalTags && !hasDecision && !preferencesOpen;

  // Keep the preferences modal unmounted until it's first opened (so its chunk
  // — and vaul + the dialog — never loads on a visit that never opens it), then
  // keep it mounted so its close animation can play out on subsequent toggles.
  // `open={preferencesOpen}` drives the actual open/close once mounted. Mutating
  // the ref during render is idempotent and safe (lazy-init pattern).
  const everOpenedRef = useRef(false);
  if (preferencesOpen) everOpenedRef.current = true;

  return (
    <>
      {showBanner ? (
        <Suspense fallback={null}>
          <ConsentBanner onCustomize={openPreferences} />
        </Suspense>
      ) : null}
      {everOpenedRef.current ? (
        <Suspense fallback={null}>
          <ConsentPreferences open={preferencesOpen} onOpenChange={setPreferencesOpen} />
        </Suspense>
      ) : null}
    </>
  );
}
