import { getConsentRecord } from "@/lib/consent";
import { client } from "@/utils/orpc";

/**
 * Best-effort server proof-of-consent. Read the decision the core just wrote
 * to the cookie and POST it for the GDPR accountability log. This is glue
 * between the framework-agnostic consent core and the app's oRPC client, so
 * it lives in the app layer (not in `lib/consent/`, which stays dependency-
 * free and unit-testable).
 *
 * Fire-and-forget by design: the cookie is the source of truth for gating, so
 * a failed/blocked request must never block the UI or change behaviour.
 */
type ConsentAction = "accept_all" | "reject_all" | "custom";

export function recordConsentToServer(action: ConsentAction): void {
  const record = getConsentRecord();
  if (!record) return;
  void client.consent
    .record({
      anonId: record.id,
      policyVersion: record.v,
      categories: record.cats,
      action,
      userAgent: typeof navigator !== "undefined" ? navigator.userAgent.slice(0, 512) : undefined,
    })
    .catch(() => {
      // Swallowed on purpose — accountability logging is best-effort.
    });
}
