import { isAdminRole } from "@flycockpit/auth/roles";

type ForcedTwoFactorSettingKey = "force2faPublicUsers" | "force2faInternalUsers";
type ForcedTwoFactorSettings = Partial<
  Record<ForcedTwoFactorSettingKey | "force2fa", string | undefined>
>;

export function forcedTwoFactorSettingKeyForRole(role: unknown): ForcedTwoFactorSettingKey {
  return isAdminRole(role) ? "force2faInternalUsers" : "force2faPublicUsers";
}

export function isForcedTwoFactorEnabledForRole(
  settings: ForcedTwoFactorSettings | undefined,
  role: unknown,
): boolean {
  return (settings?.[forcedTwoFactorSettingKeyForRole(role)] ?? settings?.force2fa) === "true";
}
