import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {
    DEPLOYMENT_PROFILE: "oss",
    COCKPIT_INSTANCE_LIMIT: 10,
    PRODUCT_NAME: "Flycockpit",
    BETTER_AUTH_SECRET: "1234567890abcdef1234567890abcdef",
    BETTER_AUTH_URL: "https://app.example.test",
  },
}));

vi.mock("./deployment-profile", async (importOriginal) => {
  const original = await importOriginal<typeof import("./deployment-profile")>();
  return { ...original, getEnterpriseLicenseStatus: vi.fn() };
});

const { default: prisma } = await import("@flycockpit/db");
const { env } = await import("@flycockpit/env/server");
const { getEnterpriseLicenseStatus } = await import("./deployment-profile");
const { getUserEntitlements } = await import("./entitlements");

const db = prisma as unknown as {
  user: { findUnique: ReturnType<typeof vi.fn> };
};
const mutableEnv = env as unknown as {
  DEPLOYMENT_PROFILE: "hosted" | "enterprise" | "oss";
  COCKPIT_INSTANCE_LIMIT: number;
};
const licenseStatus = getEnterpriseLicenseStatus as unknown as ReturnType<typeof vi.fn>;

describe("getUserEntitlements", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mutableEnv.DEPLOYMENT_PROFILE = "oss";
    mutableEnv.COCKPIT_INSTANCE_LIMIT = 10;
    db.user.findUnique.mockResolvedValue({ plan: "FREE", hostedTrialEndsAt: null });
    licenseStatus.mockReturnValue(null);
  });

  it("allows OSS instance connections but not native app access", async () => {
    await expect(getUserEntitlements("user-1")).resolves.toMatchObject({
      profile: "oss",
      nativeAppAccess: false,
      ownedInstanceConnections: true,
      maxInstances: 10,
    });
  });

  it("blocks hosted free users from owning connected instances", async () => {
    mutableEnv.DEPLOYMENT_PROFILE = "hosted";
    await expect(getUserEntitlements("user-1")).resolves.toMatchObject({
      profile: "hosted",
      nativeAppAccess: false,
      ownedInstanceConnections: false,
      maxInstances: 0,
    });
  });

  it("allows hosted PRO users to connect instances and use native", async () => {
    mutableEnv.DEPLOYMENT_PROFILE = "hosted";
    db.user.findUnique.mockResolvedValue({ plan: "PRO", hostedTrialEndsAt: null });
    await expect(getUserEntitlements("user-1")).resolves.toMatchObject({
      nativeAppAccess: true,
      ownedInstanceConnections: true,
      maxInstances: 10,
    });
  });

  it("honors active hosted trials without changing the plan", async () => {
    mutableEnv.DEPLOYMENT_PROFILE = "hosted";
    db.user.findUnique.mockResolvedValue({
      plan: "FREE",
      hostedTrialEndsAt: new Date("2030-01-01T00:00:00.000Z"),
    });
    const entitlements = await getUserEntitlements("user-1", new Date("2029-01-01T00:00:00.000Z"));
    expect(entitlements.nativeAppAccess).toBe(true);
    expect(entitlements.plan).toBe("FREE");
  });

  it("uses valid enterprise license entitlements", async () => {
    mutableEnv.DEPLOYMENT_PROFILE = "enterprise";
    licenseStatus.mockReturnValue({
      valid: true,
      entitlements: {
        nativeAppAccess: true,
        maxInstances: 25,
        sharingEnabled: true,
        logExport: true,
      },
    });
    await expect(getUserEntitlements("user-1")).resolves.toMatchObject({
      profile: "enterprise",
      nativeAppAccess: true,
      maxInstances: 25,
      logExport: true,
    });
  });

  it("degrades expired or invalid enterprise licenses to no connected features", async () => {
    mutableEnv.DEPLOYMENT_PROFILE = "enterprise";
    licenseStatus.mockReturnValue({ valid: false, entitlements: { maxInstances: 25 } });
    await expect(getUserEntitlements("user-1")).resolves.toMatchObject({
      nativeAppAccess: false,
      ownedInstanceConnections: false,
      maxInstances: 0,
    });
  });
});
