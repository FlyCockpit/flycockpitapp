import { isAdminRole } from "@flycockpit/auth/roles";
import prisma from "@flycockpit/db";

export const FORCE_2FA_PUBLIC_USERS_SETTING_KEY = "force2faPublicUsers";
export const FORCE_2FA_INTERNAL_USERS_SETTING_KEY = "force2faInternalUsers";
export const LEGACY_FORCE_2FA_SETTING_KEY = "force2fa";

export const FORCE_2FA_SETTING_KEYS = [
  FORCE_2FA_PUBLIC_USERS_SETTING_KEY,
  FORCE_2FA_INTERNAL_USERS_SETTING_KEY,
] as const;

// Migration compatibility: `force2fa` is read-only fallback for apps created
// before the role-scoped settings existed. Remove it from this readable list
// and from the fallback checks after shipped apps have deleted or migrated old
// `AppSetting.key = "force2fa"` rows.
export const READABLE_FORCE_2FA_SETTING_KEYS = [
  ...FORCE_2FA_SETTING_KEYS,
  LEGACY_FORCE_2FA_SETTING_KEY,
] as const;

export type ForceTwoFactorSettingKey = (typeof FORCE_2FA_SETTING_KEYS)[number];

export function forcedTwoFactorSettingKeyForRole(role: unknown): ForceTwoFactorSettingKey {
  return isAdminRole(role)
    ? FORCE_2FA_INTERNAL_USERS_SETTING_KEY
    : FORCE_2FA_PUBLIC_USERS_SETTING_KEY;
}

export async function isForcedTwoFactorEnabledForRole(role: unknown): Promise<boolean> {
  const targetKey = forcedTwoFactorSettingKeyForRole(role);
  const settings = await prisma.appSetting.findMany({
    where: {
      key: {
        in: [targetKey, LEGACY_FORCE_2FA_SETTING_KEY],
      },
    },
    select: { key: true, value: true },
  });
  const byKey = new Map(settings.map((setting) => [setting.key, setting.value]));

  return (byKey.get(targetKey) ?? byKey.get(LEGACY_FORCE_2FA_SETTING_KEY)) === "true";
}

export async function isTwoFactorPolicySatisfied(user: {
  role?: unknown;
  twoFactorEnabled?: boolean | null;
}): Promise<boolean> {
  if (user.twoFactorEnabled) return true;
  return !(await isForcedTwoFactorEnabledForRole(user.role));
}
