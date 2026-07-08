function normalizeRoleToken(value: string): string {
  return value.trim().toLowerCase();
}

export function parseRoles(value: unknown): string[] {
  if (typeof value !== "string") return [];
  return value
    .split(",")
    .map(normalizeRoleToken)
    .filter((role) => role.length > 0);
}

export function hasRole(value: unknown, expectedRole: string): boolean {
  const expected = normalizeRoleToken(expectedRole);
  return parseRoles(value).includes(expected);
}

export function isAdminRole(value: unknown): boolean {
  return hasRole(value, "admin");
}
