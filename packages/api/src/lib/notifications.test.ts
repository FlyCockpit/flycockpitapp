import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/db", () => ({
  default: {
    cockpitInstance: { findUnique: vi.fn() },
    notification: { findUnique: vi.fn(), findFirst: vi.fn(), create: vi.fn() },
    notificationInstanceSetting: { findUnique: vi.fn() },
    nativePushToken: { findMany: vi.fn(), update: vi.fn() },
    pushSubscription: { findMany: vi.fn(), delete: vi.fn() },
    user: { findMany: vi.fn() },
    userPresenceLease: { count: vi.fn(), upsert: vi.fn(), deleteMany: vi.fn() },
  },
}));

vi.mock("@flycockpit/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "https://app.example.test",
    COCKPIT_RELAY_URL: "wss://relay.example.test/ws",
    RELAY_CONTROL_SECRET: "x".repeat(32),
  },
}));

vi.mock("./web-push", () => ({
  sendPushNotification: vi.fn(),
}));

const { default: prisma } = await import("@flycockpit/db");
const { sendPushNotification } = await import("./web-push");
const {
  decideNotificationDelivery,
  ingestAttentionNotification,
  normalizeAttentionPayload,
  parseRelayAttentionIngest,
  publishToast,
} = await import("./notifications");
const { resetRelayControlConfig, setRelayControlConfig } = await import("./relay-config");

const db = prisma as unknown as {
  cockpitInstance: { findUnique: ReturnType<typeof vi.fn> };
  notification: {
    findUnique: ReturnType<typeof vi.fn>;
    findFirst: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
  };
  notificationInstanceSetting: { findUnique: ReturnType<typeof vi.fn> };
  nativePushToken: { findMany: ReturnType<typeof vi.fn>; update: ReturnType<typeof vi.fn> };
  pushSubscription: { findMany: ReturnType<typeof vi.fn>; delete: ReturnType<typeof vi.fn> };
  user: { findMany: ReturnType<typeof vi.fn> };
};

const push = sendPushNotification as unknown as ReturnType<typeof vi.fn>;

const basePayload = {
  eventId: "evt-1",
  sessionId: "session-1",
  projectRoot: "/repo",
  eventType: "APPROVAL_NEEDED",
  fixedStringTitle: "Approval needed",
  fixedStringBody: "Open the session to review the request.",
  ts: "2026-07-06T00:00:00.000Z",
};

function seedBaseDb(overrides?: {
  targetUserId?: string;
  ownerCopies?: boolean;
  muted?: boolean;
  typeEnabled?: boolean;
  masterEnabled?: boolean;
}) {
  db.cockpitInstance.findUnique.mockResolvedValue({
    id: "instance-1",
    userId: "owner-1",
    displayName: "Workstation",
  });
  db.notificationInstanceSetting.findUnique.mockResolvedValue(
    overrides?.ownerCopies ? { ownerReceivesSharedSessions: true } : null,
  );
  db.user.findMany.mockImplementation(async ({ where }: { where: { id: { in: string[] } } }) =>
    where.id.in.map((id) => ({
      id,
      locale: "en-US",
      notificationAlerts: overrides?.masterEnabled ?? true,
      NotificationPreferences: [
        { type: "APPROVAL_NEEDED", enabled: overrides?.typeEnabled ?? true },
      ],
      NotificationInstanceSettings: [
        {
          muted: overrides?.muted ?? false,
          ownerReceivesSharedSessions: overrides?.ownerCopies ?? false,
        },
      ],
    })),
  );
  db.notification.findUnique.mockResolvedValue(null);
  db.notification.findFirst.mockResolvedValue(null);
  db.notification.create.mockImplementation(
    async ({ data }: { data: Record<string, unknown> }) => ({
      id: "notification-" + data.userId,
      createdAt: new Date("2026-07-06T00:00:01.000Z"),
      ...data,
    }),
  );
  db.pushSubscription.findMany.mockResolvedValue([]);
  db.pushSubscription.delete.mockResolvedValue({});
  db.nativePushToken.findMany.mockResolvedValue([]);
  db.nativePushToken.update.mockResolvedValue({});
  push.mockResolvedValue({});
}

describe("notification delivery decision", () => {
  it.each([
    { activelyPresent: true, expected: { channel: "toast", deliveredVia: "TOAST" } },
    { activelyPresent: false, expected: { channel: "webpush", deliveredVia: "PUSH" } },
  ])("routes by visibility: $activelyPresent", ({ activelyPresent, expected }) => {
    expect(
      decideNotificationDelivery({
        activelyPresent,
        masterEnabled: true,
        typeEnabled: true,
        instanceMuted: false,
        duplicateInWindow: false,
      }),
    ).toEqual(expected);
  });

  it("suppresses disabled, muted, and duplicate events", () => {
    expect(
      decideNotificationDelivery({
        activelyPresent: false,
        masterEnabled: false,
        typeEnabled: true,
        instanceMuted: false,
        duplicateInWindow: false,
      }).deliveredVia,
    ).toBeNull();
    expect(
      decideNotificationDelivery({
        activelyPresent: false,
        masterEnabled: true,
        typeEnabled: true,
        instanceMuted: true,
        duplicateInWindow: false,
      }).deliveredVia,
    ).toBeNull();
    expect(
      decideNotificationDelivery({
        activelyPresent: false,
        masterEnabled: true,
        typeEnabled: true,
        instanceMuted: false,
        duplicateInWindow: true,
      }),
    ).toEqual({ channel: "none", deliveredVia: "SUPPRESSED_DUPLICATE" });
  });
});

describe("relay attention ingest parsing", () => {
  it("threads relayId through presence and attention payloads", () => {
    expect(
      parseRelayAttentionIngest({
        relayId: "relay-1",
        event: "user_presence",
        userId: "user-1",
        payload: { clientId: "client-1", visible: true },
      }),
    ).toMatchObject({ kind: "presence", relayId: "relay-1" });

    expect(
      parseRelayAttentionIngest({
        relayId: "relay-1",
        instanceId: "instance-1",
        event: "APPROVAL_NEEDED",
        payload: basePayload,
      }),
    ).toMatchObject({ kind: "attention", relayId: "relay-1" });
  });
});

describe("publishToast", () => {
  beforeEach(() => {
    resetRelayControlConfig();
  });

  it("logs and returns false when relay control config is missing", async () => {
    setRelayControlConfig(null);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    await expect(
      publishToast({
        type: "notify_user",
        userId: "user-1",
        notification: {
          id: "notification-1",
          type: "APPROVAL_NEEDED",
          title: "Approval needed",
          body: "Open the session to review the request.",
          url: "/en-US/instances",
          instanceId: "instance-1",
          sessionRef: "session-1",
          createdAt: "2026-07-06T00:00:01.000Z",
        },
      }),
    ).resolves.toBe(false);

    expect(warn).toHaveBeenCalledWith(expect.stringContaining("RELAY_CONTROL_SECRET"));
    warn.mockRestore();
  });

  it("logs the response status when relay control returns non-2xx", async () => {
    setRelayControlConfig({
      relayId: "relay-1",
      controlSecret: "x".repeat(32),
      controlUrl: "https://relay.example.test/control",
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ error: "nope" }), { status: 503 }));

    await expect(
      publishToast({
        type: "disconnect_user",
        userId: "user-1",
        reason: "test",
      }),
    ).resolves.toBe(false);

    expect(fetchMock).toHaveBeenCalledWith(
      "https://relay.example.test/control",
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: `Bearer ${"x".repeat(32)}` }),
      }),
    );
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("status=503"));
    fetchMock.mockRestore();
    warn.mockRestore();
  });
});

describe("attention notification ingestion", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetRelayControlConfig();
    seedBaseDb();
  });

  it("writes a toast ledger row and does not push when the user is visible", async () => {
    const publishToast = vi.fn().mockResolvedValue(true);
    const sendWebPushToUser = vi.fn();

    const result = await ingestAttentionNotification({
      instanceId: "instance-1",
      payload: basePayload,
      deps: {
        isActivelyPresent: vi.fn().mockResolvedValue(true),
        publishToast,
        sendWebPushToUser,
      },
    });

    expect(result.recipients).toEqual([
      { userId: "owner-1", channel: "toast", deliveredVia: "TOAST" },
    ]);
    expect(db.notification.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ deliveredVia: "TOAST" }) }),
    );
    expect(publishToast).toHaveBeenCalledOnce();
    expect(sendWebPushToUser).not.toHaveBeenCalled();
  });

  it("writes a push ledger row and sends VAPID push when the user is absent", async () => {
    const publishToast = vi.fn();
    const sendWebPushToUser = vi.fn().mockResolvedValue({ sent: 1, total: 1 });

    await ingestAttentionNotification({
      instanceId: "instance-1",
      payload: basePayload,
      deps: {
        isActivelyPresent: vi.fn().mockResolvedValue(false),
        publishToast,
        sendWebPushToUser,
      },
    });

    expect(db.notification.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ deliveredVia: "PUSH" }) }),
    );
    expect(sendWebPushToUser).toHaveBeenCalledOnce();
    expect(publishToast).not.toHaveBeenCalled();
  });

  it("records a suppressed duplicate inside the coalescing window", async () => {
    db.notification.findFirst.mockResolvedValue({ id: "recent" });
    const sendWebPushToUser = vi.fn();

    await ingestAttentionNotification({
      instanceId: "instance-1",
      payload: basePayload,
      deps: {
        isActivelyPresent: vi.fn().mockResolvedValue(false),
        sendWebPushToUser,
        publishToast: vi.fn(),
      },
    });

    expect(db.notification.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ deliveredVia: "SUPPRESSED_DUPLICATE" }),
      }),
    );
    expect(sendWebPushToUser).not.toHaveBeenCalled();
  });

  it("resolves grantee recipients and only copies the owner when enabled", async () => {
    await ingestAttentionNotification({
      instanceId: "instance-1",
      payload: { ...basePayload, eventId: "evt-grantee", targetPrincipal: { userId: "grantee-1" } },
      deps: { isActivelyPresent: vi.fn().mockResolvedValue(true), publishToast: vi.fn() },
    });
    expect(db.user.findMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        where: { id: { in: ["grantee-1"] } },
      }),
    );

    vi.clearAllMocks();
    seedBaseDb({ ownerCopies: true });
    await ingestAttentionNotification({
      instanceId: "instance-1",
      payload: {
        ...basePayload,
        eventId: "evt-owner-copy",
        targetPrincipal: { userId: "grantee-1" },
      },
      deps: { isActivelyPresent: vi.fn().mockResolvedValue(true), publishToast: vi.fn() },
    });
    expect(db.user.findMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        where: { id: { in: ["grantee-1", "owner-1"] } },
      }),
    );
  });

  it("respects disabled preferences without writing a ledger row", async () => {
    seedBaseDb({ typeEnabled: false });

    const result = await ingestAttentionNotification({
      instanceId: "instance-1",
      payload: basePayload,
      deps: { isActivelyPresent: vi.fn().mockResolvedValue(false) },
    });

    expect(result.recipients).toEqual([
      { userId: "owner-1", channel: "none", reason: "preference" },
    ]);
    expect(db.notification.create).not.toHaveBeenCalled();
  });

  it("prunes expired push subscriptions on 404 or 410 push failures", async () => {
    db.pushSubscription.findMany.mockResolvedValue([
      { id: "sub-1", endpoint: "https://fcm.googleapis.com/fcm/send/a", p256dh: "p", auth: "a" },
    ]);
    push.mockRejectedValue({ statusCode: 410 });

    await ingestAttentionNotification({
      instanceId: "instance-1",
      payload: basePayload,
      deps: { isActivelyPresent: vi.fn().mockResolvedValue(false) },
    });

    expect(db.pushSubscription.delete).toHaveBeenCalledWith({ where: { id: "sub-1" } });
  });

  it("rejects oversized or non-fixed-string attention payloads", () => {
    expect(() =>
      normalizeAttentionPayload({
        ...basePayload,
        fixedStringTitle: "x".repeat(161),
      }),
    ).toThrow();
  });
});
