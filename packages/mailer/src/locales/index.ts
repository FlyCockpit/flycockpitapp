/**
 * Locales the mailer package ships translation bundles for.
 *
 * Kept in sync MANUALLY with `@flycockpit/config/locales` `SUPPORTED_LOCALES`. The
 * mailer can't import from that package at runtime in every consumer (it's a
 * leaf workspace), so we duplicate the small list here. When you add a locale
 * to the central `SUPPORTED_LOCALES`, add it here AND drop matching JSON
 * bundles into
 * `packages/mailer/src/locales/<tag>/{verify-email,invite-user,two-factor-otp}.json`.
 *
 * If a caller passes an unsupported locale, the renderers fall back to en-US.
 */
export const MAILER_LOCALES = ["en-US", "es-MX"] as const;

export type MailerLocale = (typeof MAILER_LOCALES)[number];

export const DEFAULT_MAILER_LOCALE: MailerLocale = "en-US";

export function isMailerLocale(value: unknown): value is MailerLocale {
  return typeof value === "string" && (MAILER_LOCALES as readonly string[]).includes(value);
}

/**
 * Narrow an arbitrary string into a supported MailerLocale, falling back to
 * en-US for anything we don't ship a bundle for. Use this at the boundary —
 * Better-Auth's `user.locale` field is typed as `string`, not the strict
 * union, so callers receive `string | undefined` and must narrow before
 * passing to `renderVerifyEmail` / `renderInviteUser`.
 */
export function resolveMailerLocale(value: unknown): MailerLocale {
  return isMailerLocale(value) ? value : DEFAULT_MAILER_LOCALE;
}
