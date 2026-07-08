/**
 * Renders the email-verification message.
 *
 * Layout (table-based inline-CSS HTML) is identical across locales — only the
 * visible strings come from the JSON bundles. The `<html lang="...">`
 * attribute reflects the recipient's locale so screen readers and RTL email
 * clients route through the right pipeline.
 */
import enBundle from "../locales/en-US/verify-email.json";
import esBundle from "../locales/es-MX/verify-email.json";
import { type MailerLocale, resolveMailerLocale } from "../locales/index.js";
import { safeHref } from "./html.js";

interface VerifyEmailBundle {
  subject: string;
  heading: string;
  body: string;
  cta: string;
  ignoreFooter: string;
}

const BUNDLES: Record<MailerLocale, VerifyEmailBundle> = {
  "en-US": enBundle as VerifyEmailBundle,
  "es-MX": esBundle as VerifyEmailBundle,
};

function pickBundle(locale: MailerLocale): VerifyEmailBundle {
  // Defensive fallback: if a locale was added to MAILER_LOCALES but its JSON
  // bundle hasn't been dropped in yet, render with en-US copy rather than
  // crashing. Strings being missing entirely is also handled per-key below.
  const candidate = BUNDLES[locale];
  return candidate ?? BUNDLES["en-US"];
}

function fallbackString(value: string | undefined, fallback: string): string {
  return value && value.length > 0 ? value : fallback;
}

export interface RenderVerifyEmailArgs {
  url: string;
  locale: string;
}

export interface RenderVerifyEmailResult {
  subject: string;
  html: string;
}

export function renderVerifyEmail(args: RenderVerifyEmailArgs): RenderVerifyEmailResult {
  const locale = resolveMailerLocale(args.locale);
  const bundle = pickBundle(locale);
  const en = BUNDLES["en-US"];

  // Per-key fallback to en-US so a partially-translated bundle never ships an
  // empty subject line or a blank CTA button.
  const subject = fallbackString(bundle.subject, en.subject);
  const heading = fallbackString(bundle.heading, en.heading);
  const body = fallbackString(bundle.body, en.body);
  const cta = fallbackString(bundle.cta, en.cta);
  const ignoreFooter = fallbackString(bundle.ignoreFooter, en.ignoreFooter);
  const href = safeHref(args.url);

  const html = `<!DOCTYPE html>
<html lang="${locale}">
<head><meta charset="utf-8" /></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 0">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;padding:40px;max-width:480px">
        <tr><td style="text-align:center">
          <h1 style="margin:0 0 16px;font-size:22px;color:#18181b">${heading}</h1>
          <p style="margin:0 0 24px;font-size:15px;color:#52525b;line-height:1.5">
            ${body}
          </p>
          <a href="${href}" style="display:inline-block;padding:12px 32px;background:#18181b;color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;border-radius:6px">
            ${cta}
          </a>
          <p style="margin:24px 0 0;font-size:13px;color:#a1a1aa;line-height:1.5">
            ${ignoreFooter}
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  return { subject, html };
}
