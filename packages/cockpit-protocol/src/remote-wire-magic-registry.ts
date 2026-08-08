export interface RemoteWireMagicOwnerV1 {
  magic: string;
  symbolicType: string;
  owningPackage: string;
  owningVersion: number;
}
export function parseRemoteWireMagicRegistry(value: unknown): readonly RemoteWireMagicOwnerV1[] {
  if (!Array.isArray(value) || value.length === 0)
    throw new Error("magic registry must be nonempty");
  const magics = new Set<string>(),
    types = new Set<string>();
  let previous = "";
  return value.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error("invalid registry entry");
    const x = raw as Record<string, unknown>;
    if (
      Object.keys(x).sort().join(",") !== "magic,owningPackage,owningVersion,symbolicType" ||
      typeof x.magic !== "string" ||
      !/^FC[A-Z0-9]{2}$/.test(x.magic) ||
      typeof x.symbolicType !== "string" ||
      !x.symbolicType ||
      typeof x.owningPackage !== "string" ||
      !x.owningPackage ||
      x.owningVersion !== 1
    )
      throw new Error("invalid registry entry");
    if (x.magic <= previous) throw new Error("registry not sorted or duplicate magic");
    if (types.has(x.symbolicType)) throw new Error("duplicate symbolic type");
    previous = x.magic;
    magics.add(x.magic);
    types.add(x.symbolicType);
    return x as unknown as RemoteWireMagicOwnerV1;
  });
}
export function assertRegisteredProductionMagics(
  registry: readonly RemoteWireMagicOwnerV1[],
  declared: readonly { magic: string; symbolicType: string }[],
) {
  const owners = new Map(registry.map((x) => [x.magic, x.symbolicType]));
  for (const x of declared)
    if (owners.get(x.magic) !== x.symbolicType)
      throw new Error(`unregistered production codec ${x.magic}`);
}
