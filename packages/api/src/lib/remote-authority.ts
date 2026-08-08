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
  if (Object.keys(actual).sort().join(",") !== [...names].sort().join(","))
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
    Buffer.byteLength(key.kid) > 128
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
  if (key.retireAt !== null) u64(key.retireAt, "retireAt");
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
    value.keys.length === 0
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

function same(a: unknown, b: unknown) {
  return canonicalizeRfc8785(a) === canonicalizeRfc8785(b);
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
  if (args.previousRedisTime && BigInt(args.now) < BigInt(args.previousRedisTime))
    return unavailable("redis_time_regression");
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
        r.keys
          .filter((k) => k.state !== "revoked")
          .map((k) => k.kid)
          .join("\0") !== l.publicKids.join("\0")
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
  if (args.localDigest === d0 || args.localDigest === d1) {
    if (observed.some((l) => l.digest === d2 && args.localDigest === d0))
      return unavailable("d0_d2_coexistence");
    return {
      ready: true,
      mayMint: true,
      signingKid: args.rings.get(d0)!.currentKid,
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
    if (value.length !== 64) throw new Error("provider returned non-P1363 signature");
    const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
      s = BigInt(`0x${value.subarray(32).toString("hex")}`),
      normalized = s > order / 2n ? order - s : s;
    value.set(Buffer.from(normalized.toString(16).padStart(64, "0"), "hex"), 32);
    return value;
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
export function publicAuthorityJwks(ring: AuthorityRingFile, now: string) {
  const time = BigInt(now);
  return {
    keys: ring.keys
      .filter(
        (key) => key.state !== "revoked" && (key.retireAt === null || BigInt(key.retireAt) > time),
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
  publish(jwks: unknown, status: string, statusValidUntil: string, now: string) {
    const jwksBody = canonicalizeRfc8785(jwks);
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
    if (!this.#body || BigInt(now) > this.#body.serveUntil) return undefined;
    return kind === "jwks"
      ? { body: this.#body.jwks, etag: this.#body.etagJwks }
      : { body: this.#body.status, etag: this.#body.etagStatus };
  }
}
export class RingAuthorityVerifier implements RemoteAuthorityVerifier {
  #keys = new Map<string, ReturnType<typeof createPublicKey>>();
  constructor(ring: AuthorityRingFile) {
    for (const key of ring.keys)
      if (key.state !== "revoked")
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
}
