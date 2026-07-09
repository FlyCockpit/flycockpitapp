import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { pushRouter } from "./push";

// Mock @flycockpit/db before importing the module
vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

// Mock @flycockpit/env/server to provide VAPID_PUBLIC_KEY
vi.mock("@flycockpit/env/server", () => ({
  env: { VAPID_PUBLIC_KEY: "test-vapid-key" },
}));

const { default: prisma } = await import("@flycockpit/db");

const db = prisma as unknown as {
  pushSubscription: {
    create: MockInstance;
    deleteMany: MockInstance;
    findMany: MockInstance;
    findUnique: MockInstance;
    update: MockInstance;
  };
  nativePushToken: {
    create: MockInstance;
    findUnique: MockInstance;
    update: MockInstance;
    updateMany: MockInstance;
  };
};

/** Build a minimal oRPC context for testing. */
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

describe("push router — auth gates", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ─── Protected procedure: vapidPublicKey ───────────────────────

  describe("subscribe (protectedProcedure)", () => {
    const validInput = {
      endpoint: "https://fcm.googleapis.com/fcm/send/test-token",
      keys: { p256dh: "p256dh", auth: "auth" },
    };

    it("stores new HTTPS browser push-service endpoints", async () => {
      db.pushSubscription.findUnique.mockResolvedValue(null);
      db.pushSubscription.create.mockResolvedValue({});
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      const result = await client.subscribe(validInput);

      expect(result).toEqual({ success: true });
      expect(db.pushSubscription.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            endpoint: validInput.endpoint,
            userId: "test-user-id",
          }),
        }),
      );
    });

    it("refreshes keys when the endpoint already belongs to the same user", async () => {
      db.pushSubscription.findUnique.mockResolvedValue({ userId: "test-user-id" });
      db.pushSubscription.update.mockResolvedValue({});
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      const result = await client.subscribe(validInput);

      expect(result).toEqual({ success: true });
      expect(db.pushSubscription.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { endpoint: validInput.endpoint },
          data: {
            p256dh: validInput.keys.p256dh,
            auth: validInput.keys.auth,
          },
        }),
      );
      expect(db.pushSubscription.create).not.toHaveBeenCalled();
    });

    it("rejects endpoints already registered to another user", async () => {
      db.pushSubscription.findUnique.mockResolvedValue({ userId: "other-user-id" });
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(client.subscribe(validInput)).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("CONFLICT");
        return true;
      });

      expect(db.pushSubscription.update).not.toHaveBeenCalled();
      expect(db.pushSubscription.create).not.toHaveBeenCalled();
    });

    it("registers and refreshes Expo native push tokens", async () => {
      const token = "ExponentPushToken[aaaaaaaaaaaaaaaaaaaaaaaa]";
      db.nativePushToken.findUnique.mockResolvedValue(null);
      db.nativePushToken.create.mockResolvedValue({});
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(
        client.registerNative({ token, platform: "ios", deviceId: "ios-device" }),
      ).resolves.toEqual({ success: true });

      expect(db.nativePushToken.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            token,
            platform: "ios",
            deviceId: "ios-device",
            enabled: true,
            userId: "test-user-id",
          }),
        }),
      );

      db.nativePushToken.findUnique.mockResolvedValue({ userId: "test-user-id" });
      db.nativePushToken.update.mockResolvedValue({});
      await expect(
        client.registerNative({ token, platform: "ios", deviceId: "ios-device-2" }),
      ).resolves.toEqual({ success: true });
      expect(db.nativePushToken.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { token },
          data: { platform: "ios", deviceId: "ios-device-2", enabled: true },
        }),
      );
    });

    it("rejects loose native push token prefixes", async () => {
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(
        client.registerNative({ token: "ExpoPushToken-loose-prefix", platform: "ios" }),
      ).rejects.toThrow();
      await expect(
        client.registerNative({ token: "ExpoPushToken[has space]", platform: "ios" }),
      ).rejects.toThrow();

      expect(db.nativePushToken.findUnique).not.toHaveBeenCalled();
      expect(db.nativePushToken.create).not.toHaveBeenCalled();
    });

    it("rejects native push tokens already registered to another user", async () => {
      db.nativePushToken.findUnique.mockResolvedValue({ userId: "other-user-id" });
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(
        client.registerNative({
          token: "ExponentPushToken[aaaaaaaaaaaaaaaaaaaaaaaa]",
          platform: "android",
        }),
      ).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("CONFLICT");
        return true;
      });

      expect(db.nativePushToken.create).not.toHaveBeenCalled();
    });

    it("disables native push tokens on unregister", async () => {
      db.nativePushToken.updateMany.mockResolvedValue({ count: 1 });
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });
      const token = "ExponentPushToken[aaaaaaaaaaaaaaaaaaaaaaaa]";

      await expect(client.unregisterNative({ token })).resolves.toEqual({ success: true });

      expect(db.nativePushToken.updateMany).toHaveBeenCalledWith({
        where: { token, userId: "test-user-id" },
        data: { enabled: false },
      });
    });

    it("rejects non-HTTPS or non-push-service endpoints", async () => {
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(
        client.subscribe({
          ...validInput,
          endpoint: "http://127.0.0.1:8080/push",
        }),
      ).rejects.toThrow();

      await expect(
        client.subscribe({
          ...validInput,
          endpoint: "https://example.com/push",
        }),
      ).rejects.toThrow();

      expect(db.pushSubscription.findUnique).not.toHaveBeenCalled();
      expect(db.pushSubscription.create).not.toHaveBeenCalled();
      expect(db.pushSubscription.update).not.toHaveBeenCalled();
    });
  });

  describe("vapidPublicKey (protectedProcedure)", () => {
    it("throws UNAUTHORIZED when no session is provided", async () => {
      const ctx = buildContext(null);
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(client.vapidPublicKey()).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("UNAUTHORIZED");
        return true;
      });
    });

    it("succeeds for an authenticated user (any role)", async () => {
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      const result = await client.vapidPublicKey();

      expect(result).toEqual({ key: "test-vapid-key" });
    });
  });

  // ─── Admin-or-404 procedure: send ──────────────────────────────

  describe("send (adminOr404Procedure)", () => {
    const validInput = {
      title: "Test",
      body: "Hello",
    };

    it("throws NOT_FOUND when no session is provided", async () => {
      const ctx = buildContext(null);
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(client.send(validInput)).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("throws NOT_FOUND when user has role 'user' instead of 'admin'", async () => {
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(client.send(validInput)).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("throws NOT_FOUND when user email is not verified", async () => {
      const ctx = buildContext({ user: { role: "admin", emailVerified: false } });
      const client = createRouterClient(pushRouter, { context: ctx });

      await expect(client.send(validInput)).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("NOT_FOUND");
        return true;
      });
    });
  });
});
