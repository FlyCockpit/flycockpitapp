import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { authRouter } from "./auth";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {},
  ADMIN_EMAILS: new Set<string>(),
}));

// authRouter imports verifyTransport for the email-OTP delivery preflight.
const verifyTransportMock = vi.fn<() => Promise<boolean>>();
vi.mock("@flycockpit/mailer", () => ({
  verifyTransport: () => verifyTransportMock(),
}));

const { default: prisma } = await import("@flycockpit/db");

const db = prisma as unknown as {
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

describe("authRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
