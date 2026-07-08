/**
 * Consent policy knobs. These three constants are the deliberate levers; the
 * rest of the engine derives its behaviour from them.
 */

/**
 * Bump this whenever you materially change *which* trackers the app uses or
 * *what* a category covers. Every stored decision made under an older version
 * is treated as "no decision", so the banner re-appears and every visitor
 * re-consents under the new policy. This is the only sanctioned way to force
 * re-consent — do not bump it for cosmetic copy changes.
 */
export const CONSENT_POLICY_VERSION = 1;

/**
 * First-party cookie holding the visitor's decision. Intentionally NOT
 * HttpOnly — the gating engine must read it in the browser before any
 * non-essential script runs. It carries no PII (an opaque random id only).
 */
export const CONSENT_COOKIE_NAME = "cookie_consent";

/**
 * 12 months — the conventional ceiling for consent validity under the GDPR /
 * ePrivacy guidance. After this the cookie expires and the banner returns.
 */
export const CONSENT_COOKIE_MAX_AGE_DAYS = 365;
