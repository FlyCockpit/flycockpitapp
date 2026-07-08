import { createRouterClient } from "@orpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";

// Mutable env mock — appConfig reads env.SMTP_HOST (and the SSO/SIGNUP flags
// re-exported from the env module) at call time, so flipping SMTP_HOST between
// tests exercises both branches of the emailEnabled flag.
const envMock = {
  SMTP_HOST: undefined as string | undefined,
  SSO_PROVIDER_NAME: "SSO",
  SSO_ENABLED: false,
  FORCE_SSO: false,
  SIGNUP_ENABLED: true,
};
const adminEmailsMock = new Set<string>();
vi.mock("@flycockpit/env/server", () => ({
  env: envMock,
  get SSO_ENABLED() {
    return envMock.SSO_ENABLED;
  },
  get FORCE_SSO() {
    return envMock.FORCE_SSO;
  },
  get SIGNUP_ENABLED() {
    return envMock.SIGNUP_ENABLED;
  },
  ADMIN_EMAILS: adminEmailsMock,
}));

// Mock @flycockpit/db so importing the full appRouter graph never touches Postgres.
vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

// @flycockpit/queue opens IORedis sockets at import time — mock every producer the
// import graph touches or the suite hangs in CI (no Redis). See
// CI test isolation guidance.
vi.mock("@flycockpit/queue", () => {
  const fakeQueue = { add: vi.fn() };
  return {
    analyzeAssetQueue: fakeQueue,
    cleanupAssetsQueue: fakeQueue,
    cleanupVideosQueue: fakeQueue,
    echoQueue: fakeQueue,
    seedQueue: fakeQueue,
    transcodeAudioTrackQueue: fakeQueue,
    transcodeVideoQueue: fakeQueue,
    echoJobSchema: { parse: (v: unknown) => v },
    QUEUE_NAMES: {},
  };
});

// @flycockpit/auth builds the Better-Auth instance (prismaAdapter, plugins) at
// import time — stub it so the graph loads without that machinery.
vi.mock("@flycockpit/auth", () => ({
  auth: { api: {} },
}));

// @flycockpit/mailer would open SMTP — stub the surface the import graph uses.
vi.mock("@flycockpit/mailer", () => ({
  sendEmail: vi.fn(),
  renderInviteUser: vi.fn(() => ({ subject: "", html: "" })),
  verifyTransport: vi.fn(async () => false),
}));

// videos router imports the storage lib, which constructs an S3 client. Stub it.
vi.mock("../lib/storage", () => ({
  createMultipartUpload: vi.fn(),
  presignUploadPart: vi.fn(),
  completeMultipartUpload: vi.fn(),
  abortMultipartUpload: vi.fn(),
  headStorageObject: vi.fn(),
  putStorageObject: vi.fn(),
  deleteStorageObject: vi.fn(),
  listStorageObjects: vi.fn(),
}));

const { appRouter } = await import("./index");

const publicContext: Context = { session: null };

describe("appConfig", () => {
  beforeEach(() => {
    envMock.SMTP_HOST = undefined;
    envMock.SSO_ENABLED = false;
    envMock.FORCE_SSO = false;
    envMock.SIGNUP_ENABLED = true;
    envMock.SSO_PROVIDER_NAME = "SSO";
    adminEmailsMock.clear();
  });

  it("reports emailEnabled=false when SMTP_HOST is unset", async () => {
    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config.emailEnabled).toBe(false);
  });

  it("reports emailEnabled=true when SMTP_HOST is configured", async () => {
    envMock.SMTP_HOST = "smtp.example.com";
    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config.emailEnabled).toBe(true);
  });

  it("surfaces the SSO and signup flags alongside emailEnabled", async () => {
    envMock.SSO_ENABLED = true;
    envMock.FORCE_SSO = true;
    envMock.SIGNUP_ENABLED = false;
    envMock.SSO_PROVIDER_NAME = "Okta";
    envMock.SMTP_HOST = "smtp.example.com";

    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config).toEqual({
      ssoEnabled: true,
      forceSso: true,
      ssoProviderName: "Okta",
      signupEnabled: false,
      adminBootstrapSignupEnabled: false,
      emailEnabled: true,
    });
  });

  it("surfaces the admin bootstrap signup carve-out when signup is otherwise disabled", async () => {
    envMock.SIGNUP_ENABLED = false;
    adminEmailsMock.add("admin@example.com");

    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config.adminBootstrapSignupEnabled).toBe(true);
  });
});
