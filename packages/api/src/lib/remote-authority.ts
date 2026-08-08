import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { canonicalizeRfc8785, parseCanonicalU64DecimalString } from "@flycockpit/cockpit-protocol";

export const REMOTE_AUTHORITY = {
  leaseTtl: 30n,
  leaseRenew: 10n,
  statusRefresh: 20n,
  statusLifetime: 60n,
  verificationSkew: 60n,
  maxGrantLifetime: 300n,
  maxCertificateLifetime: 2_592_000n,
  jwksCacheAge: 30n,
} as const;
export type KeyState = "current" | "verification_only" | "revoked";
export interface AuthorityPrivateKey {
  kid: string;
  alg: "ES256";
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d: string;
  state: KeyState;
  activatedAt: string;
  retireAt: string | null;
}
export interface AuthorityRingFile {
  schemaVersion: 1;
  revision: string;
  authorityEpoch: string;
  currentKid: string;
  keys: AuthorityPrivateKey[];
}
export interface AuthorityConfig {
  issuer: string;
  deploymentId: string;
  allowedDigests: readonly string[];
}
export interface PublicAuthorityKey {
  kid: string;
  alg: "ES256";
  crv: "P-256";
  x: string;
  y: string;
  state: KeyState;
  activatedAt: string;
  retireAt: string | null;
}
export interface PublicAuthorityRing {
  schemaVersion: 1;
  issuer: string;
  deploymentId: string;
  revision: string;
  authorityEpoch: string;
  currentKid: string;
  keys: PublicAuthorityKey[];
}
const exact = (actual: object, names: readonly string[], label: string) => {
  const actualNames = Object.keys(actual).sort(),
    expected = [...names].sort();
  if (
    actualNames.length !== expected.length ||
    actualNames.some((name, index) => name !== expected[index])
  )
    throw new Error(`${label} has missing or unknown fields`);
};
const b64 = (value: string, label: string) => {
  if (
    !/^[A-Za-z0-9_-]{43}$/.test(value) ||
    Buffer.from(value, "base64url").length !== 32 ||
    Buffer.from(Buffer.from(value, "base64url")).toString("base64url") !== value
  )
    throw new Error(`${label} must be canonical 32-byte base64url`);
};
export function normalizeAuthorityIssuer(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("issuer must be a URL");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    throw new Error("issuer must be an HTTPS origin");
  const normalized = `https://${url.hostname.toLowerCase()}${url.port && url.port !== "443" ? `:${url.port}` : ""}`;
  if (normalized !== value || normalized.length > 255 || !/^[\x20-\x7e]+$/.test(normalized))
    throw new Error("issuer must be a canonical ASCII HTTPS origin");
  return normalized;
}
export function parseAuthorityConfig(input: {
  issuer: string;
  deploymentId: string;
  digests: string;
}): AuthorityConfig {
  const issuer = normalizeAuthorityIssuer(input.issuer);
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(input.deploymentId)) throw new Error("invalid deployment ID");
  let values: unknown;
  try {
    values = JSON.parse(input.digests);
  } catch {
    throw new Error("digest plan must be compact JSON");
  }
  if (
    JSON.stringify(values) !== input.digests ||
    !Array.isArray(values) ||
    ![1, 3].includes(values.length) ||
    values.some((x) => typeof x !== "string" || !/^[0-9a-f]{64}$/.test(x)) ||
    new Set(values).size !== values.length
  )
    throw new Error("digest plan must contain one or three unique lowercase digests");
  return { issuer, deploymentId: input.deploymentId, allowedDigests: values as string[] };
}
function u64(value: unknown, label: string) {
  if (typeof value !== "string") throw new Error(`${label} must be a decimal string`);
  parseCanonicalU64DecimalString(value);
  return value;
}
function validateKey(raw: unknown, index: number): AuthorityPrivateKey {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid key");
  const key = raw as Record<string, unknown>;
  exact(
    key,
    ["kid", "alg", "kty", "crv", "x", "y", "d", "state", "activatedAt", "retireAt"],
    "key",
  );
  if (
    typeof key.kid !== "string" ||
    Buffer.byteLength(key.kid) < 1 ||
    Buffer.byteLength(key.kid) > 128 ||
    Buffer.from(key.kid).some((byte) => byte < 32 || byte === 127)
  )
    throw new Error("invalid kid");
  if (
    key.alg !== "ES256" ||
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    !(["current", "verification_only", "revoked"] as unknown[]).includes(key.state)
  )
    throw new Error("invalid key discriminant");
  for (const name of ["x", "y", "d"]) {
    if (typeof key[name] !== "string") throw new Error(`invalid ${name}`);
    b64(key[name] as string, `${name}[${index}]`);
  }
  const x = key.x as string,
    y = key.y as string,
    d = key.d as string;
  u64(key.activatedAt, "activatedAt");
  if (key.retireAt !== null) {
    u64(key.retireAt, "retireAt");
    if (BigInt(key.retireAt as string) <= BigInt(key.activatedAt as string))
      throw new Error("retirement must follow activation");
  }
  const jwk = { kty: "EC", crv: "P-256", x, y, d };
  try {
    const privateKey = createPrivateKey({ key: jwk, format: "jwk" });
    const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
    if (publicJwk.x !== key.x || publicJwk.y !== key.y) throw new Error("private/public mismatch");
  } catch {
    throw new Error("invalid P-256 key or private/public mismatch");
  }
  return key as unknown as AuthorityPrivateKey;
}
export function parseAuthorityRingFile(raw: unknown, previousRevision?: string): AuthorityRingFile {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid ring");
  const value = raw as Record<string, unknown>;
  exact(value, ["schemaVersion", "revision", "authorityEpoch", "currentKid", "keys"], "ring");
  if (
    value.schemaVersion !== 1 ||
    typeof value.currentKid !== "string" ||
    !Array.isArray(value.keys) ||
    value.keys.length === 0 ||
    value.keys.length > 64
  )
    throw new Error("invalid ring header");
  const revision = u64(value.revision, "revision"),
    authorityEpoch = u64(value.authorityEpoch, "authorityEpoch");
  if (
    previousRevision !== undefined &&
    parseCanonicalU64DecimalString(revision) <= parseCanonicalU64DecimalString(previousRevision)
  )
    throw new Error("nonmonotonic revision");
  const keys = value.keys.map(validateKey);
  for (let i = 1; i < keys.length; i++)
    if (Buffer.compare(Buffer.from(keys[i - 1]!.kid), Buffer.from(keys[i]!.kid)) >= 0)
      throw new Error("keys must be unique and UTF-8 sorted");
  const current = keys.filter((k) => k.state === "current");
  if (current.length !== 1 || current[0]!.kid !== value.currentKid)
    throw new Error("ring requires exactly one matching current key");
  if (current[0]!.retireAt !== null) throw new Error("current key cannot be retired");
  return { schemaVersion: 1, revision, authorityEpoch, currentKid: value.currentKid, keys };
}
export function publicAuthorityRing(
  ring: AuthorityRingFile,
  config: Pick<AuthorityConfig, "issuer" | "deploymentId">,
): PublicAuthorityRing {
  return {
    schemaVersion: 1,
    issuer: normalizeAuthorityIssuer(config.issuer),
    deploymentId: config.deploymentId,
    revision: ring.revision,
    authorityEpoch: ring.authorityEpoch,
    currentKid: ring.currentKid,
    keys: ring.keys.map(({ d: _, kty: __, ...key }) => key),
  };
}
export function canonicalAuthorityRing(
  ring: AuthorityRingFile,
  config: Pick<AuthorityConfig, "issuer" | "deploymentId">,
) {
  return canonicalizeRfc8785(publicAuthorityRing(ring, config));
}
export function authorityRingDigest(
  ring: AuthorityRingFile,
  config: Pick<AuthorityConfig, "issuer" | "deploymentId">,
) {
  return createHash("sha256").update(canonicalAuthorityRing(ring, config)).digest("hex");
}
export function publicAuthorityRingDigest(ring: PublicAuthorityRing) {
  return createHash("sha256").update(canonicalizeRfc8785(ring)).digest("hex");
}

function same(a: unknown, b: unknown) {
  return canonicalizeRfc8785(a) === canonicalizeRfc8785(b);
}
function arraysEqual(a: readonly string[], b: readonly string[]) {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
export function validateThreeDigestPlan(
  d0: PublicAuthorityRing,
  d1: PublicAuthorityRing,
  d2: PublicAuthorityRing,
) {
  if (
    d0.issuer !== d1.issuer ||
    d1.issuer !== d2.issuer ||
    d0.deploymentId !== d1.deploymentId ||
    d1.deploymentId !== d2.deploymentId
  )
    throw new Error("issuer/deployment changes require a new lifecycle");
  if (
    BigInt(d1.revision) !== BigInt(d0.revision) + 1n ||
    BigInt(d2.revision) !== BigInt(d1.revision) + 1n ||
    BigInt(d1.authorityEpoch) !== BigInt(d0.authorityEpoch) + 1n ||
    BigInt(d2.authorityEpoch) !== BigInt(d1.authorityEpoch) + 1n
  )
    throw new Error("revision and epoch must increment by one");
  const k0 = d0.keys.find((k) => k.kid === d0.currentKid)!;
  if (d1.currentKid !== k0.kid) throw new Error("D1 must retain K0");
  for (const key of d0.keys) {
    const next = d1.keys.find((k) => k.kid === key.kid);
    if (!next || !same(next, key)) throw new Error("D1 must be strictly additive");
  }
  const additions = d1.keys.filter((k) => !d0.keys.some((old) => old.kid === k.kid));
  if (additions.length !== 1 || additions[0]!.state !== "verification_only")
    throw new Error("D1 must add one verification-only key");
  const k1 = additions[0]!;
  if (d2.currentKid !== k1.kid || d2.keys.length !== d1.keys.length)
    throw new Error("D2 must promote K1");
  for (const key of d1.keys) {
    const next = d2.keys.find((k) => k.kid === key.kid);
    if (!next) throw new Error("D2 key missing");
    const expected =
      key.kid === k1.kid
        ? { ...key, state: "current" }
        : key.kid === k0.kid
          ? { ...key, state: "verification_only" }
          : key;
    if (!same(next, expected)) throw new Error("D2 changed forbidden key fields");
  }
}

export interface ReplicaMember {
  replicaId: string;
  replicaGeneration: string;
  state: "joining" | "required" | "draining";
}
export interface MembershipSnapshot {
  membershipGeneration: string;
  members: readonly ReplicaMember[];
}
export interface ObservationLease {
  issuerDigest: string;
  deploymentId: string;
  membershipGeneration: string;
  replicaId: string;
  replicaGeneration: string;
  leaseGeneration: string;
  revision: string;
  digest: string;
  currentKid: string;
  publicKids: readonly string[];
  authorityEpoch: string;
  observedRedisTime: string;
  expiresAt: string;
}
export interface RolloutDecision {
  ready: boolean;
  mayMint: boolean;
  signingKid: string | null;
  phase: "D0" | "D1" | "D2" | "steady" | "unavailable";
  reason: string;
}
export function reduceAuthorityRollout(args: {
  now: string;
  issuerDigest: string;
  deploymentId: string;
  snapshot: MembershipSnapshot;
  leases: readonly ObservationLease[];
  plan: readonly [string] | readonly [string, string, string];
  rings: ReadonlyMap<string, PublicAuthorityRing>;
  localDigest: string;
  previousRedisTime?: string;
}): RolloutDecision {
  const unavailable = (reason: string): RolloutDecision => ({
    ready: false,
    mayMint: false,
    signingKid: null,
    phase: "unavailable",
    reason,
  });
  const required = args.snapshot.members.filter((m) => m.state === "required");
  if (required.length === 0) return unavailable("empty_required_membership");
  try {
    u64(args.now, "redis time");
    u64(args.snapshot.membershipGeneration, "membership generation");
    if (args.previousRedisTime) u64(args.previousRedisTime, "previous redis time");
    for (const lease of args.leases) {
      for (const [name, value] of [
        ["replica generation", lease.replicaGeneration],
        ["lease generation", lease.leaseGeneration],
        ["revision", lease.revision],
        ["authority epoch", lease.authorityEpoch],
        ["observed redis time", lease.observedRedisTime],
        ["expiry", lease.expiresAt],
      ] as const)
        u64(value, name);
    }
  } catch {
    return unavailable("malformed_counter");
  }
  if (args.previousRedisTime && BigInt(args.now) < BigInt(args.previousRedisTime))
    return unavailable("redis_time_regression");
  for (const digest of args.plan) {
    const planned = args.rings.get(digest);
    if (!planned || publicAuthorityRingDigest(planned) !== digest)
      return unavailable("digest_ring_mismatch");
  }
  if (args.plan.length === 3) {
    try {
      validateThreeDigestPlan(
        args.rings.get(args.plan[0])!,
        args.rings.get(args.plan[1])!,
        args.rings.get(args.plan[2])!,
      );
    } catch {
      return unavailable("invalid_rotation_plan");
    }
  }
  const observed: ObservationLease[] = [];
  for (const member of required) {
    const matches = args.leases.filter(
      (l) =>
        l.replicaId === member.replicaId &&
        l.replicaGeneration === member.replicaGeneration &&
        l.membershipGeneration === args.snapshot.membershipGeneration &&
        l.deploymentId === args.deploymentId &&
        l.issuerDigest === args.issuerDigest &&
        BigInt(l.expiresAt) > BigInt(args.now),
    );
    if (matches.length !== 1) return unavailable("missing_or_ambiguous_required_lease");
    observed.push(matches[0]!);
  }
  if (!args.plan.includes(args.localDigest) || observed.some((l) => !args.plan.includes(l.digest)))
    return unavailable("unconfigured_digest");
  const ring = args.rings.get(args.localDigest);
  if (
    !ring ||
    observed.some((l) => {
      const r = args.rings.get(l.digest);
      return (
        !r ||
        r.currentKid !== l.currentKid ||
        r.revision !== l.revision ||
        r.authorityEpoch !== l.authorityEpoch ||
        !arraysEqual(
          r.keys.filter((k) => k.state !== "revoked").map((k) => k.kid),
          l.publicKids,
        )
      );
    })
  )
    return unavailable("ring_lease_mismatch");
  if (args.plan.length === 1) {
    if (observed.some((l) => l.digest !== args.plan[0])) return unavailable("steady_not_converged");
    return {
      ready: true,
      mayMint: true,
      signingKid: ring.currentKid,
      phase: "steady",
      reason: "ready",
    };
  }
  const [d0, d1, d2] = args.plan;
  if (observed.some((l) => l.digest === d0) && observed.some((l) => l.digest === d2))
    return unavailable("d0_d2_coexistence");
  if (args.localDigest === d0 || args.localDigest === d1) {
    return {
      ready: true,
      mayMint: true,
      signingKid: ring.currentKid,
      phase: args.localDigest === d0 ? "D0" : "D1",
      reason: "ready",
    };
  }
  if (observed.some((l) => l.digest === d0)) return unavailable("d2_waits_for_d0");
  return { ready: true, mayMint: true, signingKid: ring.currentKid, phase: "D2", reason: "ready" };
}

export interface RemoteAuthoritySigner {
  readonly kid: string;
  signP1363(input: Uint8Array, mintId: string): Promise<Uint8Array>;
}
export interface RemoteAuthorityVerifier {
  verifyP1363(input: Uint8Array, signature: Uint8Array, kid: string): Promise<boolean>;
}
export type NativeEs256Signature =
  | { encoding: "ieee-p1363"; bytes: Uint8Array }
  | { encoding: "der"; bytes: Uint8Array };

const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

function readDerLength(bytes: Uint8Array, offset: number): [number, number] {
  const first = bytes[offset];
  if (first === undefined) throw new Error("truncated DER signature");
  if (first < 0x80) return [first, offset + 1];
  const width = first & 0x7f;
  if (width === 0 || width > 2 || offset + width >= bytes.length)
    throw new Error("invalid DER length");
  if (bytes[offset + 1] === 0) throw new Error("nonminimal DER length");
  let value = 0;
  for (let i = 0; i < width; i++) value = value * 256 + bytes[offset + 1 + i]!;
  if (value < 0x80) throw new Error("nonminimal DER length");
  return [value, offset + width + 1];
}

function readDerScalar(bytes: Uint8Array, offset: number): [Buffer, number] {
  if (bytes[offset] !== 0x02) throw new Error("invalid DER scalar");
  const [length, start] = readDerLength(bytes, offset + 1),
    end = start + length;
  if (length === 0 || end > bytes.length) throw new Error("truncated DER scalar");
  let scalar = Buffer.from(bytes.subarray(start, end));
  if ((scalar[0]! & 0x80) !== 0) throw new Error("negative DER scalar");
  if (scalar.length > 1 && scalar[0] === 0 && (scalar[1]! & 0x80) === 0)
    throw new Error("nonminimal DER scalar");
  if (scalar[0] === 0) scalar = scalar.subarray(1);
  if (scalar.length > 32) throw new Error("oversized DER scalar");
  return [Buffer.concat([Buffer.alloc(32 - scalar.length), scalar]), end];
}

/** Normalize a provider-native ES256 signature without exposing provider key material. */
export function normalizeEs256Signature(value: NativeEs256Signature): Uint8Array {
  let signature: Buffer;
  if (value.encoding === "ieee-p1363") {
    if (value.bytes.length !== 64) throw new Error("provider returned non-P1363 signature");
    signature = Buffer.from(value.bytes);
  } else {
    const bytes = value.bytes;
    if (bytes[0] !== 0x30) throw new Error("invalid DER signature");
    const [length, start] = readDerLength(bytes, 1);
    if (start + length !== bytes.length) throw new Error("invalid DER signature length");
    const [r, next] = readDerScalar(bytes, start),
      [s, end] = readDerScalar(bytes, next);
    if (end !== bytes.length) throw new Error("trailing DER signature data");
    signature = Buffer.concat([r, s]);
  }
  const r = BigInt(`0x${signature.subarray(0, 32).toString("hex")}`),
    s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (r === 0n || r >= P256_ORDER || s === 0n || s >= P256_ORDER)
    throw new Error("provider returned invalid P-256 scalar");
  if (s > P256_ORDER / 2n)
    signature.set(Buffer.from((P256_ORDER - s).toString(16).padStart(64, "0"), "hex"), 32);
  return signature;
}

export class InjectedAuthoritySigner implements RemoteAuthoritySigner {
  constructor(
    readonly kid: string,
    private readonly providerSign: (
      input: Uint8Array,
      mintId: string,
    ) => Promise<NativeEs256Signature>,
  ) {
    if (!kid || Buffer.byteLength(kid) > 128) throw new Error("invalid provider kid");
  }
  async signP1363(input: Uint8Array, mintId: string) {
    return normalizeEs256Signature(await this.providerSign(input, mintId));
  }
}
export class FileAuthoritySigner implements RemoteAuthoritySigner {
  readonly kid: string;
  #key: ReturnType<typeof createPrivateKey>;
  constructor(key: AuthorityPrivateKey) {
    if (key.state !== "current") throw new Error("signer key must be current");
    this.kid = key.kid;
    this.#key = createPrivateKey({
      key: { kty: key.kty, crv: key.crv, x: key.x, y: key.y, d: key.d },
      format: "jwk",
    });
  }
  async signP1363(input: Uint8Array, _mintId: string) {
    const value = sign("sha256", input, { key: this.#key, dsaEncoding: "ieee-p1363" });
    return normalizeEs256Signature({ encoding: "ieee-p1363", bytes: value });
  }
}

export interface RemoteAuthorityStatusV1 {
  schemaVersion: 1;
  iss: string;
  aud: "flycockpit-remote-authority-status-v1";
  deploymentId: string;
  revision: string;
  ringDigest: string;
  authorityEpoch: string;
  statusGeneration: string;
  revokedKids: string[];
  iat: string;
  validUntil: string;
}
const toB64 = (value: Uint8Array | string) => Buffer.from(value).toString("base64url");
export async function createRemoteAuthorityStatusJws(
  status: RemoteAuthorityStatusV1,
  signer: RemoteAuthoritySigner,
) {
  exact(
    status,
    [
      "schemaVersion",
      "iss",
      "aud",
      "deploymentId",
      "revision",
      "ringDigest",
      "authorityEpoch",
      "statusGeneration",
      "revokedKids",
      "iat",
      "validUntil",
    ],
    "status",
  );
  if (status.schemaVersion !== 1 || status.aud !== "flycockpit-remote-authority-status-v1")
    throw new Error("invalid status version or audience");
  normalizeAuthorityIssuer(status.iss);
  if (
    !/^[A-Za-z0-9_-]{1,64}$/.test(status.deploymentId) ||
    !/^[0-9a-f]{64}$/.test(status.ringDigest)
  )
    throw new Error("invalid status identity");
  for (const key of [
    "revision",
    "authorityEpoch",
    "statusGeneration",
    "iat",
    "validUntil",
  ] as const)
    u64(status[key], key);
  if (BigInt(status.validUntil) !== BigInt(status.iat) + 60n)
    throw new Error("status lifetime must be 60 seconds");
  if (
    status.revokedKids.length > 64 ||
    new Set(status.revokedKids).size !== status.revokedKids.length ||
    status.revokedKids.some(
      (kid, i) =>
        Buffer.byteLength(kid) < 1 ||
        Buffer.byteLength(kid) > 128 ||
        (i > 0 && Buffer.compare(Buffer.from(status.revokedKids[i - 1]!), Buffer.from(kid)) >= 0),
    )
  )
    throw new Error("revoked kids must be unique and sorted");
  const header = { alg: "ES256", kid: signer.kid, typ: "flycockpit-remote-authority-status+jws" };
  const protectedPart = toB64(canonicalizeRfc8785(header)),
    payloadPart = toB64(canonicalizeRfc8785(status)),
    input = `${protectedPart}.${payloadPart}`,
    signature = await signer.signP1363(
      new TextEncoder().encode(input),
      `status:${status.deploymentId}:${status.statusGeneration}`,
    );
  if (signature.length !== 64) throw new Error("invalid provider signature");
  const compact = `${input}.${toB64(signature)}`;
  if (Buffer.byteLength(compact) > 16_384) throw new Error("status JWS exceeds limit");
  return compact;
}
function decodeB64(value: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.includes("="))
    throw new Error("noncanonical base64url");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) throw new Error("noncanonical base64url");
  return bytes;
}
export async function verifyRemoteAuthorityStatusJws(
  compact: string,
  verifier: RemoteAuthorityVerifier,
  expected: {
    issuer: string;
    deploymentId: string;
    ringDigest: string;
    authorityEpoch: string;
    minimumGeneration: string;
    now: string;
  },
) {
  if (Buffer.byteLength(compact) > 16_384) throw new Error("status JWS exceeds limit");
  const parts = compact.split(".");
  if (parts.length !== 3) throw new Error("invalid compact status");
  const headerBytes = decodeB64(parts[0]!),
    payloadBytes = decodeB64(parts[1]!),
    signature = decodeB64(parts[2]!);
  if (signature.length !== 64) throw new Error("invalid P1363 width");
  const r = BigInt(`0x${signature.subarray(0, 32).toString("hex")}`),
    s = BigInt(`0x${signature.subarray(32).toString("hex")}`),
    order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  if (r === 0n || r >= order || s === 0n || s >= order)
    throw new Error("invalid P-256 signature scalar");
  let header: unknown, payload: unknown;
  try {
    header = JSON.parse(headerBytes.toString("utf8"));
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    throw new Error("invalid status JSON");
  }
  if (
    Buffer.from(canonicalizeRfc8785(header)).compare(headerBytes) !== 0 ||
    Buffer.from(canonicalizeRfc8785(payload)).compare(payloadBytes) !== 0
  )
    throw new Error("noncanonical status JSON");
  if (!header || typeof header !== "object" || Array.isArray(header))
    throw new Error("invalid status header");
  exact(header, ["alg", "kid", "typ"], "status header");
  const h = header as Record<string, unknown>;
  if (
    h.alg !== "ES256" ||
    h.typ !== "flycockpit-remote-authority-status+jws" ||
    typeof h.kid !== "string"
  )
    throw new Error("invalid status header");
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("invalid status payload");
  const p = payload as RemoteAuthorityStatusV1;
  exact(
    p,
    [
      "schemaVersion",
      "iss",
      "aud",
      "deploymentId",
      "revision",
      "ringDigest",
      "authorityEpoch",
      "statusGeneration",
      "revokedKids",
      "iat",
      "validUntil",
    ],
    "status payload",
  );
  await createRemoteAuthorityStatusJws(
    { ...p },
    {
      kid: h.kid,
      async signP1363() {
        return new Uint8Array(64).fill(1);
      },
    },
  ).catch((error) => {
    if (error instanceof Error && error.message === "invalid provider signature") return;
    throw error;
  });
  if (
    p.iss !== expected.issuer ||
    p.deploymentId !== expected.deploymentId ||
    p.ringDigest !== expected.ringDigest ||
    p.authorityEpoch !== expected.authorityEpoch ||
    BigInt(p.statusGeneration) < BigInt(expected.minimumGeneration) ||
    BigInt(expected.now) > BigInt(p.validUntil) + REMOTE_AUTHORITY.verificationSkew
  )
    throw new Error("status scope, generation, or time mismatch");
  u64(expected.now, "expected time");
  u64(expected.minimumGeneration, "minimum generation");
  if (BigInt(p.iat) > BigInt(expected.now) + REMOTE_AUTHORITY.verificationSkew)
    throw new Error("status issued in the future");
  const input = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  if (!(await verifier.verifyP1363(input, signature, h.kid)))
    throw new Error("status signature invalid");
  return { header: h, payload: p };
}
export interface AuthorityPublicJwks {
  keys: Array<{
    alg: "ES256";
    crv: "P-256";
    kid: string;
    kty: "EC";
    use: "sig";
    x: string;
    y: string;
  }>;
}
export function publicAuthorityJwks(ring: AuthorityRingFile, now: string): AuthorityPublicJwks {
  u64(now, "JWKS time");
  const time = BigInt(now);
  return {
    keys: ring.keys
      .filter(
        (key) =>
          key.state !== "revoked" &&
          BigInt(key.activatedAt) <= time &&
          (key.retireAt === null || BigInt(key.retireAt) > time),
      )
      .map((key) => ({
        alg: "ES256",
        crv: "P-256",
        kid: key.kid,
        kty: "EC",
        use: "sig",
        x: key.x,
        y: key.y,
      })),
  };
}
export function strongEtag(body: string) {
  return `"${createHash("sha256").update(body).digest("hex")}"`;
}
export class AuthorityPublicSnapshot {
  #body:
    | { jwks: string; status: string; etagJwks: string; etagStatus: string; serveUntil: bigint }
    | undefined;
  publish(jwks: AuthorityPublicJwks, status: string, statusValidUntil: string, now: string) {
    u64(statusValidUntil, "status expiry");
    u64(now, "snapshot time");
    const jwksBody = canonicalizeRfc8785(jwks);
    if (jwksBody.includes('"d"')) throw new Error("private key material cannot be published");
    this.#body = {
      jwks: jwksBody,
      status,
      etagJwks: strongEtag(jwksBody),
      etagStatus: strongEtag(status),
      serveUntil:
        BigInt(statusValidUntil) < BigInt(now) + 60n ? BigInt(statusValidUntil) : BigInt(now) + 60n,
    };
  }
  read(kind: "jwks" | "status", now: string) {
    try {
      u64(now, "snapshot time");
    } catch {
      return undefined;
    }
    if (!this.#body || BigInt(now) > this.#body.serveUntil) return undefined;
    return kind === "jwks"
      ? { body: this.#body.jwks, etag: this.#body.etagJwks }
      : { body: this.#body.status, etag: this.#body.etagStatus };
  }
}

export type SigningJournalState = "reserved" | "signed" | "finalized" | "aborted";
export interface SigningJournalEntry {
  mintId: string;
  deploymentId: string;
  signingGeneration: string;
  kid: string;
  claimsHash: string;
  state: SigningJournalState;
  signatureP1363?: string;
  compactJws?: string;
  signedAt?: string;
}
export interface SigningFence {
  kid: string;
  signingGeneration: string;
  state: "open" | "closing" | "frozen";
  cutoff?: string;
}
export type ProviderReconciliation = "confirmed_signed" | "confirmed_not_started" | "indeterminate";
export function reserveAuthorityMint(
  fence: SigningFence,
  entry: Omit<SigningJournalEntry, "state">,
): SigningJournalEntry {
  if (
    fence.state !== "open" ||
    entry.kid !== fence.kid ||
    entry.signingGeneration !== fence.signingGeneration
  )
    throw new Error("signing fence closed or generation mismatch");
  return { ...entry, state: "reserved" };
}
export function reconcileAuthorityFence(args: {
  fence: SigningFence;
  rows: readonly SigningJournalEntry[];
  provider: ReadonlyMap<string, ProviderReconciliation>;
  postgresNow: string;
}): { fence: SigningFence; rows: SigningJournalEntry[]; ready: boolean } {
  u64(args.postgresNow, "Postgres time");
  if (args.fence.state !== "closing") throw new Error("fence must be closing");
  const rows = args.rows.map((row) => {
    if (row.signingGeneration !== args.fence.signingGeneration) return row;
    if (row.state === "reserved") {
      const result = args.provider.get(row.mintId);
      if (result === "confirmed_not_started") return { ...row, state: "aborted" as const };
      if (result === "confirmed_signed") return { ...row, state: "signed" as const };
    }
    if (row.state === "signed")
      return { ...row, state: "finalized" as const, signedAt: args.postgresNow };
    return row;
  });
  const pending = rows.some(
    (row) =>
      row.signingGeneration === args.fence.signingGeneration &&
      (row.state === "reserved" || row.state === "signed"),
  );
  if (pending) return { fence: args.fence, rows, ready: false };
  const finalized = rows
    .filter((row) => row.kid === args.fence.kid && row.state === "finalized" && row.signedAt)
    .map((row) => BigInt(row.signedAt!));
  const cutoff = finalized.length
    ? finalized.reduce((a, b) => (a > b ? a : b)).toString()
    : args.postgresNow;
  return { fence: { ...args.fence, state: "frozen", cutoff }, rows, ready: true };
}
export function authorityRetirementFloor(cutoff: string) {
  u64(cutoff, "signing cutoff");
  return (
    BigInt(cutoff) +
    REMOTE_AUTHORITY.maxCertificateLifetime +
    REMOTE_AUTHORITY.verificationSkew
  ).toString();
}

export interface LifecycleTransition {
  transitionId: string;
  state: "reserved" | "status_signed" | "committed" | "aborted";
  fromRevision: string;
  toRevision: string;
  fromDigest: string;
  toDigest: string;
  fromAuthorityEpoch: string;
  toAuthorityEpoch: string;
  fromCurrentKid: string;
  toCurrentKid: string;
  statusGeneration: string;
  statusBodyDigest: string;
  signingGeneration: string;
}
export function validateLifecycleTransition(
  value: LifecycleTransition,
  replacementSignerKid: string,
) {
  for (const key of [
    "fromRevision",
    "toRevision",
    "fromAuthorityEpoch",
    "toAuthorityEpoch",
    "statusGeneration",
    "signingGeneration",
  ] as const)
    u64(value[key], key);
  if (
    BigInt(value.toRevision) !== BigInt(value.fromRevision) + 1n ||
    BigInt(value.toAuthorityEpoch) !== BigInt(value.fromAuthorityEpoch) + 1n
  )
    throw new Error("lifecycle counters must increment");
  if (
    !/^[0-9a-f]{64}$/.test(value.fromDigest) ||
    !/^[0-9a-f]{64}$/.test(value.toDigest) ||
    !/^[0-9a-f]{64}$/.test(value.statusBodyDigest)
  )
    throw new Error("invalid lifecycle digest");
  if (
    !replacementSignerKid ||
    (replacementSignerKid === value.fromCurrentKid && value.toCurrentKid === value.fromCurrentKid)
  )
    throw new Error("transition requires an authorized non-revoked signer");
  return value;
}
export class RingAuthorityVerifier implements RemoteAuthorityVerifier {
  #keys = new Map<string, ReturnType<typeof createPublicKey>>();
  constructor(ring: AuthorityRingFile, now: string) {
    u64(now, "verifier time");
    const time = BigInt(now);
    for (const key of ring.keys)
      if (
        key.state !== "revoked" &&
        BigInt(key.activatedAt) <= time &&
        (key.retireAt === null || BigInt(key.retireAt) > time)
      )
        this.#keys.set(
          key.kid,
          createPublicKey({
            key: { kty: key.kty, crv: key.crv, x: key.x, y: key.y },
            format: "jwk",
          }),
        );
  }
  async verifyP1363(input: Uint8Array, signature: Uint8Array, kid: string) {
    const key = this.#keys.get(kid);
    return Boolean(
      key &&
        signature.length === 64 &&
        verify("sha256", input, { key, dsaEncoding: "ieee-p1363" }, signature),
    );
  }
  hasKid(kid: string) {
    return this.#keys.has(kid);
  }
}

/** Issuer-scoped verifier cache. Unknown-kid refresh is coalesced and rate limited. */
export class CachedAuthorityVerifier implements RemoteAuthorityVerifier {
  #verifier: RingAuthorityVerifier;
  #refresh: Promise<void> | undefined;
  #lastUnknownRefresh = Number.NEGATIVE_INFINITY;
  constructor(
    readonly issuer: string,
    initialRing: AuthorityRingFile,
    private readonly nowSeconds: () => number,
    private readonly loadRing: () => Promise<AuthorityRingFile>,
  ) {
    normalizeAuthorityIssuer(issuer);
    this.#verifier = new RingAuthorityVerifier(initialRing, String(Math.floor(nowSeconds())));
  }
  async verifyP1363(input: Uint8Array, signature: Uint8Array, kid: string) {
    if (this.#verifier.hasKid(kid)) return this.#verifier.verifyP1363(input, signature, kid);
    const now = this.nowSeconds();
    if (this.#refresh) await this.#refresh;
    else if (now - this.#lastUnknownRefresh >= Number(REMOTE_AUTHORITY.jwksCacheAge)) {
      this.#lastUnknownRefresh = now;
      this.#refresh = this.loadRing()
        .then((ring) => {
          this.#verifier = new RingAuthorityVerifier(ring, String(Math.floor(this.nowSeconds())));
        })
        .finally(() => {
          this.#refresh = undefined;
        });
      await this.#refresh;
    }
    return this.#verifier.verifyP1363(input, signature, kid);
  }
}
