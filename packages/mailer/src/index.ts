import { env } from "@flycockpit/env/shared";
import type { Transporter } from "nodemailer";
import nodemailer from "nodemailer";

interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
}

let transporter: Transporter | null = null;

function getTransporter(): Transporter {
  if (transporter) return transporter;

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = env;

  if (!SMTP_HOST) {
    throw new Error(
      "SMTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, and SMTP_FROM in your .env file. " +
        "For local dev, run: docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit",
    );
  }

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT ?? 587,
    ...(SMTP_USER && SMTP_PASS ? { auth: { user: SMTP_USER, pass: SMTP_PASS } } : {}),
  });

  return transporter;
}

/**
 * Send an email using the SMTP transport configured via env vars.
 *
 * The nodemailer transport is created lazily on the first call so the
 * application boots cleanly even when SMTP is not configured.
 */
export async function sendEmail({ to, subject, html }: SendEmailOptions): Promise<void> {
  const transport = getTransporter();
  const from = env.SMTP_FROM ?? "noreply@example.com";

  let lastError: unknown;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await transport.sendMail({ from, to, subject, html });
      return;
    } catch (err) {
      lastError = err;
      if (attempt < 3) {
        await new Promise((resolve) => setTimeout(resolve, attempt * 500));
      }
    }
  }
  throw lastError;
}

/**
 * Whether SMTP is configured at all (env-level check, no network I/O). Drives
 * the `emailEnabled` app-config flag that gates email-dependent UI.
 */
export function isEmailConfigured(): boolean {
  return Boolean(env.SMTP_HOST);
}

/**
 * Best-effort SMTP reachability check (connect + auth handshake via nodemailer's
 * `verify()`). Returns a boolean and NEVER throws: `false` when SMTP is
 * unconfigured or the handshake fails, `true` otherwise.
 *
 * Used as a delivery-aware preflight: Better-Auth's email-OTP `send-otp`
 * endpoint swallows `sendOTP` failures and always returns success, so callers
 * verify the transport is actually reachable before telling a user a code is on
 * the way. This catches the common breakage (wrong host/port/credentials, server
 * down); it cannot guarantee a specific recipient won't bounce after a good
 * handshake — that is inherent to asynchronous email delivery.
 */
export async function verifyTransport(): Promise<boolean> {
  if (!env.SMTP_HOST) return false;
  try {
    return await getTransporter().verify();
  } catch {
    return false;
  }
}

// Locale machinery + per-template renderers. The mailer owns email rendering
// (subject + HTML) so callers don't have to think about i18n bundles, just
// pass the recipient's locale and the template-specific data.
export {
  DEFAULT_MAILER_LOCALE,
  isMailerLocale,
  MAILER_LOCALES,
  type MailerLocale,
  resolveMailerLocale,
} from "./locales/index.js";
export {
  type RenderInviteUserArgs,
  type RenderInviteUserResult,
  renderInviteUser,
} from "./templates/invite-user.js";
export {
  type RenderShareInviteArgs,
  type RenderShareInviteResult,
  renderShareInvite,
} from "./templates/share-invite.js";
export {
  type RenderTwoFactorOtpArgs,
  type RenderTwoFactorOtpResult,
  renderTwoFactorOtp,
} from "./templates/two-factor-otp.js";
export {
  type RenderVerifyEmailArgs,
  type RenderVerifyEmailResult,
  renderVerifyEmail,
} from "./templates/verify-email.js";
