/** Renders a user-to-user instance sharing invitation. */
import enBundle from "../locales/en-US/share-invite.json";
import esBundle from "../locales/es-MX/share-invite.json";
import { type MailerLocale, resolveMailerLocale } from "../locales/index.js";
import { escapeHtml, safeHref } from "./html.js";

interface ShareInviteBundle {
  subject: string;
  heading: string;
  body: string;
  scopesLabel: string;
  expiresLabel: string;
  neverExpires: string;
  ctaExisting: string;
  ctaNew: string;
  ignoreFooter: string;
}

const BUNDLES: Record<MailerLocale, ShareInviteBundle> = {
  "en-US": enBundle as ShareInviteBundle,
  "es-MX": esBundle as ShareInviteBundle,
};

function pickBundle(locale: MailerLocale): ShareInviteBundle {
  return BUNDLES[locale] ?? BUNDLES["en-US"];
}

function fallbackString(value: string | undefined, fallback: string): string {
  return value && value.length > 0 ? value : fallback;
}

function interpolate(template: string, vars: Record<string, string>): string {
  return template.replace(/{{s*([a-zA-Z0-9_]+)s*}}/g, (_, key) => {
    return Object.hasOwn(vars, key) ? vars[key]! : `{{${key}}}`;
  });
}

export interface RenderShareInviteArgs {
  ownerName: string;
  instanceName: string;
  scopes: string[];
  acceptUrl: string;
  expiresAt?: Date | string | null;
  existingUser: boolean;
  locale: string;
}

export interface RenderShareInviteResult {
  subject: string;
  html: string;
}

export function renderShareInvite(args: RenderShareInviteArgs): RenderShareInviteResult {
  const locale = resolveMailerLocale(args.locale);
  const bundle = pickBundle(locale);
  const en = BUNDLES["en-US"];
  const subject = fallbackString(bundle.subject, en.subject);
  const heading = fallbackString(bundle.heading, en.heading);
  const bodyTemplate = fallbackString(bundle.body, en.body);
  const scopesLabel = fallbackString(bundle.scopesLabel, en.scopesLabel);
  const expiresLabel = fallbackString(bundle.expiresLabel, en.expiresLabel);
  const neverExpires = fallbackString(bundle.neverExpires, en.neverExpires);
  const cta = fallbackString(
    args.existingUser ? bundle.ctaExisting : bundle.ctaNew,
    args.existingUser ? en.ctaExisting : en.ctaNew,
  );
  const ignoreFooter = fallbackString(bundle.ignoreFooter, en.ignoreFooter);
  const safeOwnerName = escapeHtml(args.ownerName);
  const safeInstanceName = escapeHtml(args.instanceName);
  const body = interpolate(bodyTemplate, {
    ownerName: safeOwnerName,
    instanceName: safeInstanceName,
  });
  const scopeList = args.scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("");
  const expires = args.expiresAt
    ? escapeHtml(new Date(args.expiresAt).toLocaleString(locale))
    : neverExpires;
  const href = safeHref(args.acceptUrl);

  const html = `<!DOCTYPE html>
<html lang="${locale}">
<head><meta charset="utf-8" /></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 0">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;padding:40px;max-width:520px">
        <tr><td>
          <h1 style="margin:0 0 16px;font-size:22px;color:#18181b">${heading}</h1>
          <p style="margin:0 0 16px;font-size:15px;color:#52525b;line-height:1.5">${body}</p>
          <p style="margin:0 0 8px;font-size:13px;color:#71717a">${scopesLabel}</p>
          <ul style="margin:0 0 16px;padding-left:20px;font-size:15px;color:#18181b;line-height:1.5">${scopeList}</ul>
          <p style="margin:0 0 8px;font-size:13px;color:#71717a">${expiresLabel}</p>
          <p style="margin:0 0 24px;font-size:15px;color:#18181b">${expires}</p>
          <p style="margin:0 0 24px;text-align:center">
            <a href="${href}" style="display:inline-block;padding:12px 32px;background:#18181b;color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;border-radius:6px">${cta}</a>
          </p>
          <p style="margin:0;font-size:13px;color:#a1a1aa;line-height:1.5">${ignoreFooter}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  return { subject, html };
}
