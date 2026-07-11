import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { authRouter, passwordCapabilities } from "./auth";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {},
  ADMIN_EMAILS: new Set<string>(),
  FORCE_SSO: false,
}));

// authRouter imports verifyTransport for the email-OTP delivery preflight.
const verifyTransportMock = vi.fn<() => Promise<boolean>>();
vi.mock("@flycockpit/mailer", () => ({
  verifyTransport: () => verifyTransportMock(),
}));

const { default: prisma } = await import("@flycockpit/db");

const db = prisma as unknown as {
  account: { findFirst: MockInstance };
  user: { update: MockInstance };
};

function buildContext(
  sessionOverride?: Partial<{
    user: Partial<Session["user"]>;
    session: Partial<Session["session"]>;
  }> | null,
): Context {
  if (sessionOverride === null) return { session: null };
  return {
    session: {
      user: {
        id: "test-user-id",
        email: "test@example.com",
        name: "Test User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.user,
      },
      session: {
        id: "test-session-id",
        userId: sessionOverride?.user?.id ?? "test-user-id",
        token: "test-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.session,
      },
    } as Session,
  };
}

describe("passwordCapabilities helper", () => {
  it("hides password changes when forced SSO is enabled", () => {
    expect(passwordCapabilities({ forceSso: true, hasPasswordCredential: true })).toEqual({
      canChangePassword: false,
      reason: "force-sso",
    });
  });

  it("hides password changes without a password credential", () => {
    expect(passwordCapabilities({ forceSso: false, hasPasswordCredential: false })).toEqual({
      canChangePassword: false,
      reason: "no-password",
    });
  });
});

describe("authRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.account.findFirst.mockResolvedValue(null);
  });

  describe("passwordCapabilities", () => {
    it("requires authentication", async () => {
      const client = createRouterClient(authRouter, { context: buildContext(null) });

      await expect(client.passwordCapabilities()).rejects.toSatisfy((err: ORPCError) => {
        expect(err).toBeInstanceOf(ORPCError);
        expect(err.code).toBe("UNAUTHORIZED");
        return true;
      });
      expect(db.account.findFirst).not.toHaveBeenCalled();
    });

    it("allows password changes when the user has a password credential", async () => {
      db.account.findFirst.mockResolvedValue({ id: "account-id" });
      const client = createRouterClient(authRouter, { context: buildContext() });

      await expect(client.passwordCapabilities()).resolves.toEqual({
        canChangePassword: true,
        reason: null,
      });
      expect(db.account.findFirst).toHaveBeenCalledWith({
        where: {
          userId: "test-user-id",
          providerId: "credential",
          password: { not: null },
        },
        select: { id: true },
      });
    });

    it("reports no-password when the account has no password credential", async () => {
      const client = createRouterClient(authRouter, { context: buildContext() });

      await expect(client.passwordCapabilities()).resolves.toEqual({
        canChangePassword: false,
        reason: "no-password",
      });
    });
  });

  describe("updateLocale", () => {
    it("requires authentication (unauthenticated → UNAUTHORIZED)", async () => {
      const ctx = buildContext(null);
      const client = createRouterClient(authRouter, { context: ctx });

      await expect(client.updateLocale({ locale: "es-MX" })).rejects.toSatisfy((err: ORPCError) => {
        expect(err).toBeInstanceOf(ORPCError);
        expect(err.code).toBe("UNAUTHORIZED");
        return true;
      });
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it("updates the calling user's locale on a valid input", async () => {
      db.user.update.mockResolvedValue({});

      const ctx = buildContext();
      const client = createRouterClient(authRouter, { context: ctx });

      const result = await client.updateLocale({ locale: "es-MX" });

      expect(result).toEqual({ success: true });
      expect(db.user.update).toHaveBeenCalledWith({
        where: { id: "test-user-id" },
        data: { locale: "es-MX" },
      });
    });

    it("rejects an unsupported locale at Zod input validation (no Prisma write)", async () => {
      const ctx = buildContext();
      const client = createRouterClient(authRouter, { context: ctx });

      await expect(
        // @ts-expect-error — exercising input validation against an unsupported locale.
        client.updateLocale({ locale: "fr-FR" }),
      ).rejects.toBeInstanceOf(Error);
      expect(db.user.update).not.toHaveBeenCalled();
    });
  });

  describe("verifyEmailTransport", () => {
    it("is public — callable without a session", async () => {
      verifyTransportMock.mockResolvedValue(true);
      const client = createRouterClient(authRouter, { context: buildContext(null) });

      const result = await client.verifyEmailTransport();

      expect(result).toEqual({ ok: true });
    });

    it("reports ok=false when the SMTP transport is unreachable", async () => {
      verifyTransportMock.mockResolvedValue(false);
      const client = createRouterClient(authRouter, { context: buildContext(null) });

      const result = await client.verifyEmailTransport();

      expect(result).toEqual({ ok: false });
      expect(verifyTransportMock).toHaveBeenCalledOnce();
    });
  });
});
