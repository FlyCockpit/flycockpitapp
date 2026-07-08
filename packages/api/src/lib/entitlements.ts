import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { getEnterpriseLicenseStatus } from "./deployment-profile";

export type EntitlementCapability =
  | "nativeAppAccess"
  | "ownedInstanceConnections"
  | "sharingEnabled"
  | "logExport";

export type EntitlementResource = "instances";

export type UserEntitlements = {
  profile: "hosted" | "enterprise" | "oss";
  plan: "FREE" | "PRO";
  trialEndsAt: Date | null;
  nativeAppAccess: boolean;
  ownedInstanceConnections: boolean;
  sharingEnabled: boolean;
  logExport: boolean;
  maxInstances: number;
};

function trialActive(trialEndsAt: Date | null | undefined, now: Date) {
  return Boolean(trialEndsAt && trialEndsAt > now);
}

export async function getUserEntitlements(
  userId: string,
  now = new Date(),
): Promise<UserEntitlements> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { plan: true, hostedTrialEndsAt: true },
  });
  const plan = String(user?.plan ?? "FREE") as "FREE" | "PRO";
  const hostedConnected = plan === "PRO" || trialActive(user?.hostedTrialEndsAt, now);

  if (env.DEPLOYMENT_PROFILE === "hosted") {
    return {
      profile: "hosted",
      plan,
      trialEndsAt: user?.hostedTrialEndsAt ?? null,
      nativeAppAccess: hostedConnected,
      ownedInstanceConnections: hostedConnected,
      sharingEnabled: hostedConnected,
      logExport: false,
      maxInstances: hostedConnected ? env.COCKPIT_INSTANCE_LIMIT : 0,
    };
  }

  if (env.DEPLOYMENT_PROFILE === "enterprise") {
    const license = getEnterpriseLicenseStatus(now);
    const valid = license?.valid === true;
    return {
      profile: "enterprise",
      plan,
      trialEndsAt: user?.hostedTrialEndsAt ?? null,
      nativeAppAccess: valid && (license.entitlements.nativeAppAccess ?? true),
      ownedInstanceConnections: valid,
      sharingEnabled: valid && (license.entitlements.sharingEnabled ?? true),
      logExport: valid && (license.entitlements.logExport ?? true),
      maxInstances: valid ? (license.entitlements.maxInstances ?? env.COCKPIT_INSTANCE_LIMIT) : 0,
    };
  }

  return {
    profile: "oss",
    plan,
    trialEndsAt: user?.hostedTrialEndsAt ?? null,
    nativeAppAccess: false,
    ownedInstanceConnections: true,
    sharingEnabled: true,
    logExport: false,
    maxInstances: env.COCKPIT_INSTANCE_LIMIT,
  };
}

export async function can(userId: string, capability: EntitlementCapability) {
  const entitlements = await getUserEntitlements(userId);
  return entitlements[capability];
}

export async function limit(userId: string, resource: EntitlementResource) {
  const entitlements = await getUserEntitlements(userId);
  if (resource === "instances") return entitlements.maxInstances;
  return 0;
}
