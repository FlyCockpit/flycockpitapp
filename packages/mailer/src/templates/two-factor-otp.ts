/**
 * Renders the two-factor one-time-code (email OTP) message.
 *
 * Layout (table-based inline-CSS HTML) is identical across locales — only the
 * visible strings come from the JSON bundles. The `<html lang="...">`
 * attribute reflects the recipient's locale so screen readers and RTL email
 * clients route through the right pipeline.
 *
 * Unlike verify-email, there is no clickable CTA: the body prominently renders
 * the OTP code itself, which the user types back into the login challenge.
 */
import enBundle from "../locales/en-US/two-factor-otp.json";
import esBundle from "../locales/es-MX/two-factor-otp.json";
import { type MailerLocale, resolveMailerLocale } from "../locales/index.js";

interface TwoFactorOtpBundle {
  subject: string;
  heading: string;
  body: string;
  ignoreFooter: string;
}

const BUNDLES: Record<MailerLocale, TwoFactorOtpBundle> = {
  "en-US": enBundle as TwoFactorOtpBundle,
  "es-MX": esBundle as TwoFactorOtpBundle,
};

function pickBundle(locale: MailerLocale): TwoFactorOtpBundle {
  // Defensive fallback: if a locale was added to MAILER_LOCALES but its JSON
  // bundle hasn't been dropped in yet, render with en-US copy rather than
  // crashing. Strings being missing entirely is also handled per-key below.
  const candidate = BUNDLES[locale];
  return candidate ?? BUNDLES["en-US"];
}

function fallbackString(value: string | undefined, fallback: string): string {
  return value && value.length > 0 ? value : fallback;
}

/**
 * Escape the OTP for safe interpolation into the HTML body. The code comes from
 * Better-Auth (digits only), but escaping keeps the renderer robust if the
 * digit set ever changes and follows defense-in-depth for templated email.
 */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export interface RenderTwoFactorOtpArgs {
  otp: string;
  locale: string;
}

export interface RenderTwoFactorOtpResult {
  subject: string;
  html: string;
}

export function renderTwoFactorOtp(args: RenderTwoFactorOtpArgs): RenderTwoFactorOtpResult {
  const locale = resolveMailerLocale(args.locale);
  const bundle = pickBundle(locale);
  const en = BUNDLES["en-US"];

  // Per-key fallback to en-US so a partially-translated bundle never ships an
  // empty subject line or a blank heading.
  const subject = fallbackString(bundle.subject, en.subject);
  const heading = fallbackString(bundle.heading, en.heading);
  const body = fallbackString(bundle.body, en.body);
  const ignoreFooter = fallbackString(bundle.ignoreFooter, en.ignoreFooter);
  const otp = escapeHtml(args.otp);

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
          <div style="display:inline-block;padding:12px 32px;background:#f4f4f5;color:#18181b;font-size:28px;font-weight:700;letter-spacing:8px;border-radius:6px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace">
            ${otp}
          </div>
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
