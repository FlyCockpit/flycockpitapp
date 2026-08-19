/**
 * Cross-language attempt-grant verification for `RemoteAttemptGrantV1`.
 *
 * This module is the TypeScript peer of the Rust verifier at
 * `crates/cockpit-core/src/daemon/remote_attempt.rs:verify_attempt_grant`.
 * Both sides accept and reject the same fixture vectors byte-identically:
 * the fixture corpus at
 * `packages/cockpit-protocol/fixtures/remote/attempt-grants-v1.json` is the
 * single source of truth (L5).
 *
 * # Ceremony order (cheap-before-crypto, mirroring Rust)
 *
 * 1. Size — reject oversize before any decode.
 * 2. Structure — ASCII, exactly three non-empty base64url segments.
 * 3. Protected header — strict `{alg, kid, typ}`.
 * 4. Payload canonicality — RFC 8785 JCS re-encode must byte-equal the
 *    payload bytes. A validly re-signed non-canonical payload is rejected
 *    HERE, before the signature check (AC3).
 * 5. Claim typing — strict member set + typed decoding.
 * 6. Signature — ES256 (P-1363) over `header.payload`, kid lookup fails closed.
 * 7. Semantic claims — time, transport, tuple set, ceiling digest.
 * 8. Expectation binding — every claim pinned to caller-known values.
 *
 * # Security
 *
 * - No `CredentialStore`, no `Db::open`, no file KEK, no `credentials.json`.
 * - Fail closed on every error path.
 * - Secrets (private keys) never appear in this module; only public keys.
 */

import { createHash } from "node:crypto";
import { canonicalizeRfc8785 } from "./remote-protocol-id";

// ---------------------------------------------------------------------------
// Constants — mirror Rust exactly
// ---------------------------------------------------------------------------

export const GRANT_JWS_TYP = "flycockpit-remote-attempt+jwt";
export const GRANT_JWS_ALG = "ES256";
export const GRANT_MAX_BYTES = 8192;
export const GRANT_LIFETIME_SECONDS = 300n;
export const GRANT_SKEW_SECONDS = 60n;
export const GRANT_SCHEMA_VERSION = 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GrantDeviceIdentity {
  deviceId: Uint8Array;
  certificateId: Uint8Array;
  generation: bigint;
  p256Thumbprint: Uint8Array;
}

export interface GrantProjectCapability {
  projectId: Uint8Array;
  capabilities: number[];
}

export interface GrantPermissionCeiling {
  attachmentCapabilities: number[];
  projects: GrantProjectCapability[];
}

export interface RemoteAttemptGrantV1 {
  schemaVersion: number;
  issuer: string;
  audience: string;
  tenantId: Uint8Array;
  accountId: Uint8Array;
  instanceId: Uint8Array;
  logicalAttachmentId: Uint8Array;
  childAttemptId: Uint8Array;
  jti: Uint8Array;
  client: GrantDeviceIdentity;
  daemon: GrantDeviceIdentity;
  serverNonce: Uint8Array;
  serviceVersion: bigint;
  servicePolicyDigest: Uint8Array;
  policyEpoch: bigint;
  policyDigest: Uint8Array;
  authorityEpoch: bigint;
  permissionCeiling: GrantPermissionCeiling;
  permissionCeilingDigest: Uint8Array;
  authorizedTransports: number;
  compatibleTupleIds: number[];
  tenantAuthorizationDigest: Uint8Array | null;
  iat: bigint;
  nbf: bigint;
  exp: bigint;
  compactJws: string;
}

export type TenantAuthorizationExpectation =
  | { kind: "controlPlane" }
  | { kind: "enterprise"; digest: Uint8Array };

export interface GrantVerificationExpectations {
  issuer: string;
  audience: string;
  tenantId: Uint8Array;
  accountId: Uint8Array;
  instanceId: Uint8Array;
  logicalAttachmentId: Uint8Array;
  childAttemptId: Uint8Array;
  client: GrantDeviceIdentity;
  daemon: GrantDeviceIdentity;
  serverNonce: Uint8Array;
  serviceVersion: bigint;
  servicePolicyDigest: Uint8Array;
  policyEpoch: bigint;
  policyDigest: Uint8Array;
  authorityEpoch: bigint;
  tenantAuthorization: TenantAuthorizationExpectation;
}

export interface VerifiedAttemptGrant {
  readonly grant: RemoteAttemptGrantV1;
}

export interface AttemptGrantKeyRing {
  get(kid: string): AttemptGrantPublicKey | undefined;
}

export interface AttemptGrantPublicKey {
  x: Uint8Array;
  y: Uint8Array;
}

export interface AttemptGrantVerifier {
  /**
   * Verify an ES256 P-1363 signature over `input` using the EXACT public key
   * (`x`, `y` coordinates) returned by the key ring for `kid`. The verifier
   * MUST cryptographically bind to this key — never re-lookup `kid` in an
   * independent key store. This prevents a grant signed with key A from
   * verifying against key B for the same `kid`.
   */
  verifyP1363(
    input: Uint8Array,
    signature: Uint8Array,
    key: AttemptGrantPublicKey,
    kid: string,
  ): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class AttemptGrantError extends Error {
  readonly kind: "jws" | "signature" | "claims" | "ceiling" | "transport" | "tupleSet" | "time";
  constructor(kind: AttemptGrantError["kind"], message: string) {
    super(message);
    this.name = "AttemptGrantError";
    this.kind = kind;
  }
}

// ---------------------------------------------------------------------------
// Decoding helpers — mirror Rust's decode_alias16, decode_hex32, etc.
// ---------------------------------------------------------------------------

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function decodeAlias16(s: string, field: string): Uint8Array {
  if (s.length !== 22 || !B64URL_RE.test(s)) {
    throw new AttemptGrantError("claims", `${field} must be 22-char base64url`);
  }
  const bytes = Buffer.from(s, "base64url");
  if (bytes.length !== 16 || bytes.toString("base64url") !== s) {
    throw new AttemptGrantError("claims", `${field} must be canonical base64url`);
  }
  return bytes;
}

function decodeHex32(s: string, field: string): Uint8Array {
  if (s.length !== 64 || !/^[0-9a-f]{64}$/.test(s)) {
    throw new AttemptGrantError("claims", `${field} must be 64-char lowercase hex`);
  }
  return Buffer.from(s, "hex");
}

function decodeHexId16(s: string, field: string): Uint8Array {
  if (s.length !== 32 || !/^[0-9a-f]{32}$/.test(s)) {
    throw new AttemptGrantError("claims", `${field} must be 32-char lowercase hex`);
  }
  return Buffer.from(s, "hex");
}

// P-256 group order n and n/2, shared by the u64 range check and the low-S rule.
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_ORDER = P256_ORDER >> 1n;
const U64_MAX = 18446744073709551615n;

// Rust parity: `parse_decimal_u64` accepts ANY all-ASCII-digit string that fits
// in u64 (including leading zeros such as "01") and rejects empty. It does NOT
// enforce the canonical no-leading-zero spelling that
// `parseCanonicalU64DecimalString` requires — enforcing that here would make TS
// reject grants Rust accepts. Mirror Rust exactly: nonempty, all digits, <= u64
// max. Leading zeros are permitted.
function parseDecimalU64(s: string, field: string): bigint {
  if (s.length === 0 || !/^[0-9]+$/.test(s)) {
    throw new AttemptGrantError("claims", `${field} must be a decimal string`);
  }
  const v = BigInt(s);
  if (v > U64_MAX) {
    throw new AttemptGrantError("claims", `${field} exceeds u64 range`);
  }
  return v;
}

function parseDecimalI64(s: string, field: string): bigint {
  if (s.length === 0 || !/^[0-9]+$/.test(s)) {
    throw new AttemptGrantError("claims", `${field} must be a decimal string`);
  }
  const v = BigInt(s);
  // i64 range: 0..=9223372036854775807 (non-negative timestamps only).
  const I64_MAX = 9223372036854775807n;
  if (v > I64_MAX) {
    throw new AttemptGrantError("claims", `${field} exceeds i64 range`);
  }
  return v;
}

// ---------------------------------------------------------------------------
// Runtime type validators — mirror Rust's typed RawClaims deserialization.
// Every scalar, object, and array member is type-checked before semantic
// validation, mapping malformed values to AttemptGrantError("claims", ...).
// ---------------------------------------------------------------------------

/** Assert `value` is a string; throw AttemptGrantError("claims") otherwise. */
function assertString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new AttemptGrantError("claims", `${field} must be a string`);
  }
  return value;
}

/** Assert `value` is a plain object (not array, not null); throw otherwise. */
function assertObject(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AttemptGrantError("claims", `${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

/** Assert `value` is an array; throw otherwise. */
function assertArray(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new AttemptGrantError("claims", `${field} must be an array`);
  }
  return value;
}

/** Assert `value` is a non-negative safe integer within u8 range (0..=255). */
function assertU8(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 255) {
    throw new AttemptGrantError("claims", `${field} must be a u8 integer (0..=255)`);
  }
  return value;
}

/** Assert `value` is a non-negative safe integer within u16 range (0..=65535). */
function assertU16(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 65535) {
    throw new AttemptGrantError("claims", `${field} must be a u16 integer (0..=65535)`);
  }
  return value;
}

/** Assert `value` is null or a string (for nullable string fields). */
function assertNullOrString(value: unknown, field: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new AttemptGrantError("claims", `${field} must be null or a string`);
  }
  return value;
}

function decodeB64urlSegment(seg: string): Buffer {
  if (!B64URL_RE.test(seg) || seg.includes("=")) {
    throw new AttemptGrantError("jws", "segment is not padding-free base64url");
  }
  const bytes = Buffer.from(seg, "base64url");
  if (bytes.toString("base64url") !== seg) {
    throw new AttemptGrantError("jws", "segment is not canonical base64url");
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Raw claim types (strict member set, deny unknown)
// ---------------------------------------------------------------------------

const REQUIRED_HEADER_MEMBERS = ["alg", "kid", "typ"] as const;
const REQUIRED_PAYLOAD_MEMBERS = [
  "schemaVersion",
  "iss",
  "aud",
  "tenantId",
  "accountId",
  "instanceId",
  "logicalAttachmentId",
  "childAttemptId",
  "jti",
  "client",
  "daemon",
  "serverNonce",
  "serviceVersion",
  "servicePolicyDigest",
  "policyEpoch",
  "policyDigest",
  "authorityEpoch",
  "attachmentCapabilities",
  "projectCapabilities",
  "permissionCeilingDigest",
  "authorizedTransports",
  "compatibleTupleIds",
  "tenantAuthorizationDigest",
  "iat",
  "nbf",
  "exp",
] as const;
const REQUIRED_IDENTITY_MEMBERS = [
  "deviceId",
  "certificateId",
  "generation",
  "p256Thumbprint",
] as const;

function assertExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  context: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  if (actual.length !== expected.length || actual.some((k, i) => k !== expected[i])) {
    throw new AttemptGrantError("claims", `${context} has missing or unknown fields`);
  }
}

function decodeIdentity(raw: Record<string, unknown>): GrantDeviceIdentity {
  assertExactKeys(raw, REQUIRED_IDENTITY_MEMBERS, "identity");
  return {
    deviceId: decodeAlias16(assertString(raw.deviceId, "deviceId"), "deviceId"),
    certificateId: decodeAlias16(assertString(raw.certificateId, "certificateId"), "certificateId"),
    generation: parseDecimalU64(assertString(raw.generation, "generation"), "generation"),
    p256Thumbprint: decodeHex32(
      assertString(raw.p256Thumbprint, "p256Thumbprint"),
      "p256Thumbprint",
    ),
  };
}

function decodeClaims(raw: Record<string, unknown>, compactJws: string): RemoteAttemptGrantV1 {
  assertExactKeys(raw, REQUIRED_PAYLOAD_MEMBERS, "payload");

  // projectCapabilities: array of objects with typed members.
  const projects: GrantProjectCapability[] = [];
  const rawProjects = assertArray(raw.projectCapabilities, "projectCapabilities");
  for (const p of rawProjects) {
    const pObj = assertObject(p, "projectCapabilities entry");
    assertExactKeys(pObj, ["capabilities", "projectId"], "projectCapabilities entry");
    const rawCaps = assertArray(pObj.capabilities, "projectCapabilities.capabilities");
    const caps: number[] = [];
    for (const c of rawCaps) {
      const ord = assertU8(c, "projectCapabilities.capabilities ordinal");
      // Closed project capability vocabulary (ordinals 1..=15), mirroring Rust
      // `RemoteProjectCapabilityV1::from_ordinal` at decode time — an
      // out-of-vocabulary ordinal is a "claims" rejection BEFORE signature
      // verification, exactly as Rust's `decode_claims` rejects it.
      if (ord < 1 || ord > PROJECT_CAPABILITY_MAX_ORDINAL) {
        throw new AttemptGrantError(
          "claims",
          `projectCapabilities.capabilities ordinal ${ord} out of vocabulary`,
        );
      }
      caps.push(ord);
    }
    projects.push({
      projectId: decodeHexId16(
        assertString(pObj.projectId, "projectCapabilities.projectId"),
        "projectCapabilities.projectId",
      ),
      capabilities: caps,
    });
  }

  // tenantAuthorizationDigest: null or 64-char lowercase hex string.
  const tenantAuthRaw = assertNullOrString(
    raw.tenantAuthorizationDigest,
    "tenantAuthorizationDigest",
  );
  let tenantAuthorizationDigest: Uint8Array | null = null;
  if (tenantAuthRaw !== null) {
    tenantAuthorizationDigest = decodeHex32(tenantAuthRaw, "tenantAuthorizationDigest");
  }

  // attachmentCapabilities: array of u8 ordinals.
  const rawAttCaps = assertArray(raw.attachmentCapabilities, "attachmentCapabilities");
  const attachmentCapabilities: number[] = [];
  for (const c of rawAttCaps) {
    const ord = assertU8(c, "attachmentCapabilities ordinal");
    // Closed attachment capability vocabulary (ordinals 1..=13), mirroring Rust
    // `RemoteAttachmentCapabilityV1::from_ordinal` at decode time.
    if (ord < 1 || ord > ATTACHMENT_CAPABILITY_MAX_ORDINAL) {
      throw new AttemptGrantError(
        "claims",
        `attachmentCapabilities ordinal ${ord} out of vocabulary`,
      );
    }
    attachmentCapabilities.push(ord);
  }

  // compatibleTupleIds: array of u16 ids.
  const rawTupleIds = assertArray(raw.compatibleTupleIds, "compatibleTupleIds");
  const compatibleTupleIds: number[] = [];
  for (const t of rawTupleIds) {
    compatibleTupleIds.push(assertU16(t, "compatibleTupleIds entry"));
  }

  return {
    schemaVersion: assertU8(raw.schemaVersion, "schemaVersion"),
    issuer: assertString(raw.iss, "iss"),
    audience: assertString(raw.aud, "aud"),
    tenantId: decodeAlias16(assertString(raw.tenantId, "tenantId"), "tenantId"),
    accountId: decodeAlias16(assertString(raw.accountId, "accountId"), "accountId"),
    instanceId: decodeAlias16(assertString(raw.instanceId, "instanceId"), "instanceId"),
    logicalAttachmentId: decodeAlias16(
      assertString(raw.logicalAttachmentId, "logicalAttachmentId"),
      "logicalAttachmentId",
    ),
    childAttemptId: decodeAlias16(
      assertString(raw.childAttemptId, "childAttemptId"),
      "childAttemptId",
    ),
    jti: decodeAlias16(assertString(raw.jti, "jti"), "jti"),
    client: decodeIdentity(assertObject(raw.client, "client")),
    daemon: decodeIdentity(assertObject(raw.daemon, "daemon")),
    serverNonce: decodeHex32(assertString(raw.serverNonce, "serverNonce"), "serverNonce"),
    serviceVersion: parseDecimalU64(
      assertString(raw.serviceVersion, "serviceVersion"),
      "serviceVersion",
    ),
    servicePolicyDigest: decodeHex32(
      assertString(raw.servicePolicyDigest, "servicePolicyDigest"),
      "servicePolicyDigest",
    ),
    policyEpoch: parseDecimalU64(assertString(raw.policyEpoch, "policyEpoch"), "policyEpoch"),
    policyDigest: decodeHex32(assertString(raw.policyDigest, "policyDigest"), "policyDigest"),
    authorityEpoch: parseDecimalU64(
      assertString(raw.authorityEpoch, "authorityEpoch"),
      "authorityEpoch",
    ),
    permissionCeiling: {
      attachmentCapabilities,
      projects,
    },
    permissionCeilingDigest: decodeHex32(
      assertString(raw.permissionCeilingDigest, "permissionCeilingDigest"),
      "permissionCeilingDigest",
    ),
    authorizedTransports: assertU8(raw.authorizedTransports, "authorizedTransports"),
    compatibleTupleIds,
    tenantAuthorizationDigest,
    iat: parseDecimalI64(assertString(raw.iat, "iat"), "iat"),
    nbf: parseDecimalI64(assertString(raw.nbf, "nbf"), "nbf"),
    exp: parseDecimalI64(assertString(raw.exp, "exp"), "exp"),
    compactJws,
  };
}

// ---------------------------------------------------------------------------
// Semantic claim validation — mirror Rust's validate_claims
// ---------------------------------------------------------------------------

const TRANSPORT_BITS_VALID = [0x01, 0x02, 0x03];

function validateTime(grant: RemoteAttemptGrantV1, now: bigint): void {
  if (grant.iat > grant.nbf || grant.nbf > grant.exp) {
    throw new AttemptGrantError("time", "iat/nbf/exp ordering violation");
  }
  if (grant.exp - grant.iat > GRANT_LIFETIME_SECONDS) {
    throw new AttemptGrantError("time", "grant lifetime exceeds cap");
  }
  if (now + GRANT_SKEW_SECONDS < grant.nbf) {
    throw new AttemptGrantError("time", "grant not yet valid");
  }
  if (now > grant.exp) {
    throw new AttemptGrantError("time", "grant expired");
  }
}

function validateTransportBits(grant: RemoteAttemptGrantV1): void {
  if (!TRANSPORT_BITS_VALID.includes(grant.authorizedTransports)) {
    throw new AttemptGrantError("transport", "transport bits not in valid set");
  }
}

function validateTupleSet(grant: RemoteAttemptGrantV1): void {
  const ids = grant.compatibleTupleIds;
  if (ids.length < 1 || ids.length > 16) {
    throw new AttemptGrantError("tupleSet", "tuple set count must be 1..=16");
  }
  let prev = 0;
  for (let i = 0; i < ids.length; i++) {
    if (ids[i]! === 0) throw new AttemptGrantError("tupleSet", "tuple id must be nonzero");
    if (i > 0 && ids[i]! <= prev) {
      throw new AttemptGrantError("tupleSet", "tuple ids must be strictly increasing");
    }
    prev = ids[i]!;
  }
}

/** Maximum encoded size of the permission ceiling — mirrors Rust's
 * `PERMISSION_CEILING_MAX_BYTES`. */
const PERMISSION_CEILING_MAX_BYTES = 512;
const ATTACHMENT_CAPABILITY_MAX_ORDINAL = 13;
const PROJECT_CAPABILITY_MAX_ORDINAL = 15;

/**
 * Validate a strictly-ascending, unique, nonzero ordinal list within a closed
 * vocabulary and a count cap — mirrors Rust's `validate_sorted_unique_ordinals`
 * plus the per-kind `from_ordinal` vocabulary bound. A duplicate/unsorted list
 * (e.g. `[1,1]` or `[3,1]`) and an out-of-vocabulary ordinal (e.g. `255`) are
 * both rejected, matching the Rust `encode`/`from_ordinal` acceptance set.
 */
function validateOrdinalList(ords: number[], maxOrdinal: number, label: string): void {
  if (ords.length > 16) {
    throw new AttemptGrantError("ceiling", `${label} capability count exceeds 16`);
  }
  let prev = 0;
  for (let i = 0; i < ords.length; i++) {
    const o = ords[i]!;
    if (o === 0) {
      throw new AttemptGrantError("ceiling", `zero ${label} capability ordinal`);
    }
    if (o > maxOrdinal) {
      throw new AttemptGrantError("ceiling", `unknown ${label} capability ordinal ${o}`);
    }
    if (i > 0 && o <= prev) {
      throw new AttemptGrantError("ceiling", `${label} capabilities must be strictly ascending`);
    }
    prev = o;
  }
}

/** Big-endian byte-lexicographic comparison of two 16-byte project ids. */
function projectIdLessThanOrEqual(prev: Uint8Array, cur: Uint8Array): boolean {
  for (let i = 0; i < 16; i++) {
    if (prev[i]! < cur[i]!) return false;
    if (prev[i]! > cur[i]!) return true;
  }
  return true; // equal
}

/**
 * Permission ceiling binary encoder — mirrors Rust's
 * `RemotePermissionCeilingV1::encode` exactly, INCLUDING its validation:
 * closed capability vocabularies, strictly-ascending/unique attachment and
 * project-capability ordinals, count caps (<=16), strictly-ascending nonzero
 * project ids, project-capability count 1..=16, and the 512-byte aggregate cap.
 * The wire layout is
 * `version:u8(1) | attachmentCount:u8 | attachmentCapability:u8[] |
 *  projectCount:u8 | (projectId:[16] | capabilityCount:u8 |
 *  projectCapability:u8[])[]`.
 *
 * Enforcing these rules here (not only the digest recompute) is what makes a
 * validly-signed JCS grant carrying duplicate/unsorted caps, an out-of-vocab
 * ordinal, or an unsorted/duplicate/zero project id fail exactly as Rust's
 * `verify_attempt_grant` rejects it.
 */
export function encodeAttemptGrantCeiling(ceiling: GrantPermissionCeiling): Uint8Array {
  // Attachment capabilities: closed vocab, strictly-ascending, unique, <=16.
  validateOrdinalList(
    ceiling.attachmentCapabilities,
    ATTACHMENT_CAPABILITY_MAX_ORDINAL,
    "attachment",
  );

  // Projects: <=16, strictly-ascending nonzero ids, each 1..=16 sorted-unique caps.
  if (ceiling.projects.length > 16) {
    throw new AttemptGrantError("ceiling", "project count exceeds 16");
  }
  let prevId: Uint8Array | null = null;
  for (const p of ceiling.projects) {
    if (p.projectId.length !== 16) {
      throw new AttemptGrantError("ceiling", "projectId must be 16 bytes");
    }
    if (p.projectId.every((b) => b === 0)) {
      throw new AttemptGrantError("ceiling", "project id must be nonzero");
    }
    if (prevId !== null && projectIdLessThanOrEqual(prevId, p.projectId)) {
      throw new AttemptGrantError("ceiling", "project ids must be strictly ascending");
    }
    prevId = p.projectId;
    if (p.capabilities.length === 0 || p.capabilities.length > 16) {
      throw new AttemptGrantError("ceiling", "project capability count must be 1..16");
    }
    validateOrdinalList(p.capabilities, PROJECT_CAPABILITY_MAX_ORDINAL, "project");
  }

  const parts: number[] = [];
  parts.push(1); // version
  parts.push(ceiling.attachmentCapabilities.length);
  for (const c of ceiling.attachmentCapabilities) parts.push(c);
  parts.push(ceiling.projects.length);
  for (const p of ceiling.projects) {
    for (const b of p.projectId) parts.push(b);
    parts.push(p.capabilities.length);
    for (const c of p.capabilities) parts.push(c);
  }
  if (parts.length > PERMISSION_CEILING_MAX_BYTES) {
    throw new AttemptGrantError(
      "ceiling",
      `permission ceiling is ${parts.length} bytes; cap is ${PERMISSION_CEILING_MAX_BYTES}`,
    );
  }
  return new Uint8Array(parts);
}

/**
 * Compute the `permissionCeilingDigest` for an attempt grant — mirrors
 * Rust's `permission_ceiling_digest`: `SHA-256(ceiling.encode())`.
 * Named distinctly from the public-service-policy module's async
 * `permissionCeilingDigest` to avoid a re-export collision.
 */
export function attemptGrantCeilingDigest(ceiling: GrantPermissionCeiling): Uint8Array {
  const bytes = encodeAttemptGrantCeiling(ceiling);
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function validatePermissionCeiling(grant: RemoteAttemptGrantV1): void {
  const digest = attemptGrantCeilingDigest(grant.permissionCeiling);
  if (!Buffer.from(digest).equals(grant.permissionCeilingDigest)) {
    throw new AttemptGrantError("ceiling", "permissionCeilingDigest does not match");
  }
}

function validateClaims(grant: RemoteAttemptGrantV1, now: bigint): void {
  if (grant.schemaVersion !== GRANT_SCHEMA_VERSION) {
    throw new AttemptGrantError("claims", `schemaVersion must be ${GRANT_SCHEMA_VERSION}`);
  }
  validateTime(grant, now);
  validateTransportBits(grant);
  validateTupleSet(grant);
  validatePermissionCeiling(grant);
}

// ---------------------------------------------------------------------------
// Expectation binding — mirror Rust's bind_expectations
// ---------------------------------------------------------------------------

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return Buffer.from(a).equals(Buffer.from(b));
}

function bindExpectations(
  grant: RemoteAttemptGrantV1,
  expected: GrantVerificationExpectations,
): void {
  const bind = (a: unknown, b: unknown, name: string) => {
    if (a instanceof Uint8Array && b instanceof Uint8Array) {
      if (!bytesEqual(a, b)) throw new AttemptGrantError("claims", `${name} mismatch`);
    } else if (typeof a === "bigint" && typeof b === "bigint") {
      if (a !== b) throw new AttemptGrantError("claims", `${name} mismatch`);
    } else if (typeof a === "string" && typeof b === "string") {
      if (a !== b) throw new AttemptGrantError("claims", `${name} mismatch`);
    } else if (typeof a === "number" && typeof b === "number") {
      if (a !== b) throw new AttemptGrantError("claims", `${name} mismatch`);
    } else {
      throw new AttemptGrantError("claims", `${name} type mismatch`);
    }
  };

  bind(grant.issuer, expected.issuer, "iss");
  bind(grant.audience, expected.audience, "aud");
  bind(grant.tenantId, expected.tenantId, "tenantId");
  bind(grant.accountId, expected.accountId, "accountId");
  bind(grant.instanceId, expected.instanceId, "instanceId");
  bind(grant.logicalAttachmentId, expected.logicalAttachmentId, "logicalAttachmentId");
  bind(grant.childAttemptId, expected.childAttemptId, "childAttemptId");
  bind(grant.client.deviceId, expected.client.deviceId, "client.deviceId");
  bind(grant.client.certificateId, expected.client.certificateId, "client.certificateId");
  bind(grant.client.generation, expected.client.generation, "client.generation");
  bind(grant.client.p256Thumbprint, expected.client.p256Thumbprint, "client.p256Thumbprint");
  bind(grant.daemon.deviceId, expected.daemon.deviceId, "daemon.deviceId");
  bind(grant.daemon.certificateId, expected.daemon.certificateId, "daemon.certificateId");
  bind(grant.daemon.generation, expected.daemon.generation, "daemon.generation");
  bind(grant.daemon.p256Thumbprint, expected.daemon.p256Thumbprint, "daemon.p256Thumbprint");
  bind(grant.serverNonce, expected.serverNonce, "serverNonce");
  bind(grant.serviceVersion, expected.serviceVersion, "serviceVersion");
  bind(grant.servicePolicyDigest, expected.servicePolicyDigest, "servicePolicyDigest");
  bind(grant.policyEpoch, expected.policyEpoch, "policyEpoch");
  bind(grant.policyDigest, expected.policyDigest, "policyDigest");
  bind(grant.authorityEpoch, expected.authorityEpoch, "authorityEpoch");

  switch (expected.tenantAuthorization.kind) {
    case "controlPlane":
      if (grant.tenantAuthorizationDigest !== null) {
        throw new AttemptGrantError("claims", "tenantAuthorizationDigest must be null");
      }
      break;
    case "enterprise":
      if (
        grant.tenantAuthorizationDigest === null ||
        !bytesEqual(grant.tenantAuthorizationDigest, expected.tenantAuthorization.digest)
      ) {
        throw new AttemptGrantError("claims", "tenantAuthorizationDigest mismatch");
      }
      break;
  }
}

// ---------------------------------------------------------------------------
// Production entry point — verify_attempt_grant
// ---------------------------------------------------------------------------

/**
 * Verify a compact-JWS attempt grant end to end and return the sealed
 * verified grant. Steps run in the mandated cheap-before-crypto order,
 * mirroring the Rust verifier exactly.
 *
 * @param compactJws  The compact JWS string (ASCII, 3 segments).
 * @param keyRing     The authority key ring (`kid` → public key).
 * @param verifier    The ES256 P-1363 signature verifier.
 * @param expected    Caller-known expectation values for every claim.
 * @param now         The verification clock (Unix seconds, decimal string).
 */
export async function verifyAttemptGrant(
  compactJws: string,
  keyRing: AttemptGrantKeyRing,
  verifier: AttemptGrantVerifier,
  expected: GrantVerificationExpectations,
  now: string,
): Promise<VerifiedAttemptGrant> {
  // 1. Size — before any decoding.
  if (Buffer.byteLength(compactJws) > GRANT_MAX_BYTES) {
    throw new AttemptGrantError("jws", "compact JWS exceeds max bytes");
  }

  // 2. Structure — ASCII, exactly three non-empty base64url segments.
  if (!/^[\x21-\x7e]+$/.test(compactJws)) {
    throw new AttemptGrantError("jws", "compact JWS is not ASCII");
  }
  const segments = compactJws.split(".");
  if (segments.length !== 3) {
    throw new AttemptGrantError("jws", `compact JWS must have 3 segments, got ${segments.length}`);
  }
  const [headerSeg, payloadSeg, signatureSeg] = segments;
  for (const seg of segments) {
    if (!seg || !B64URL_RE.test(seg)) {
      throw new AttemptGrantError("jws", "segment is empty or not base64url");
    }
  }

  // 3. Protected header — strict {alg, kid, typ}.
  const headerBytes = decodeB64urlSegment(headerSeg!);
  let headerRaw: unknown;
  try {
    headerRaw = JSON.parse(headerBytes.toString("utf8"));
  } catch {
    throw new AttemptGrantError("jws", "header is not JSON");
  }
  if (!headerRaw || typeof headerRaw !== "object" || Array.isArray(headerRaw)) {
    throw new AttemptGrantError("jws", "header is not an object");
  }
  assertExactKeys(headerRaw as Record<string, unknown>, REQUIRED_HEADER_MEMBERS, "header");
  const header = headerRaw as Record<string, unknown>;
  if (header.alg !== GRANT_JWS_ALG) {
    throw new AttemptGrantError("jws", `alg must be ${GRANT_JWS_ALG}`);
  }
  if (header.typ !== GRANT_JWS_TYP) {
    throw new AttemptGrantError("jws", `typ must be ${GRANT_JWS_TYP}`);
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    throw new AttemptGrantError("jws", "kid must be non-empty string");
  }

  // 4. Payload canonicality — RFC 8785 JCS re-encode must byte-equal payload.
  const payloadBytes = decodeB64urlSegment(payloadSeg!);
  let payloadRaw: unknown;
  try {
    payloadRaw = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    throw new AttemptGrantError("jws", "payload is not JSON");
  }
  const canonicalPayload = canonicalizeRfc8785(payloadRaw);
  if (Buffer.from(canonicalPayload).compare(payloadBytes) !== 0) {
    throw new AttemptGrantError(
      "jws",
      "payload is not RFC 8785 canonical (ordering, whitespace, duplicate, or number form)",
    );
  }

  // 5. Claim typing — strict member set + typed decoding.
  if (!payloadRaw || typeof payloadRaw !== "object" || Array.isArray(payloadRaw)) {
    throw new AttemptGrantError("claims", "payload is not an object");
  }
  const grant = decodeClaims(payloadRaw as Record<string, unknown>, compactJws);

  // 6. Signature — kid lookup fails closed; ES256 over "header.payload".
  const key = keyRing.get(header.kid as string);
  if (!key) {
    throw new AttemptGrantError("signature", "unknown kid");
  }
  const signature = decodeB64urlSegment(signatureSeg!);
  if (signature.length !== 64) {
    throw new AttemptGrantError("signature", "signature must be 64 bytes P-1363");
  }
  // Scalar range + low-S enforcement, mirroring the sole Rust verifier
  // `cockpit_proto::es256::verify_es256_p1363`: r,s must be nonzero and below
  // the group order, AND s must be low-S (`s <= n/2`). Rust rejects any high-S
  // signature outright (`Signature::normalize_s().is_some()`), so a canonical
  // grant re-signed with the high-S counterpart `(r, n-s)` — accepted by the
  // old `s < order` check — must be rejected here too for byte-identical
  // cross-language acceptance.
  const r = BigInt(`0x${signature.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (r === 0n || r >= P256_ORDER || s === 0n || s >= P256_ORDER) {
    throw new AttemptGrantError("signature", "invalid P-256 signature scalar");
  }
  if (s > P256_HALF_ORDER) {
    throw new AttemptGrantError("signature", "signature is high-S; only low-S (s <= n/2) accepted");
  }
  const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
  // The actual public key (x, y) is passed to the verifier so it
  // cryptographically binds to the key returned by the key ring — not just
  // the kid string. A grant signed with key A but verified against key B
  // (same kid) is rejected.
  const sigOk = await verifier.verifyP1363(signingInput, signature, key, header.kid as string);
  if (!sigOk) {
    throw new AttemptGrantError("signature", "ES256 verification failed");
  }

  // 7. Semantic claims (time, transport, tuple, ceiling digest).
  const nowBig = parseDecimalI64(now, "now");
  validateClaims(grant, nowBig);

  // 8. Expectation binding — every claim pinned to caller-known values.
  bindExpectations(grant, expected);

  return { grant };
}

/**
 * Compute SHA-256 of the complete compact JWS bytes — mirrors Rust's
 * `RemoteAttemptGrantV1::digest`.
 */
export function attemptGrantDigest(grant: RemoteAttemptGrantV1): Uint8Array {
  return new Uint8Array(createHash("sha256").update(grant.compactJws).digest());
}

// ---------------------------------------------------------------------------
// Key ring builder — convenience for fixture consumption
// ---------------------------------------------------------------------------

/**
 * A simple in-memory key ring backed by a `Map<string, AttemptGrantPublicKey>`.
 */
export class SimpleKeyRing implements AttemptGrantKeyRing {
  readonly #keys = new Map<string, AttemptGrantPublicKey>();

  addKey(kid: string, key: AttemptGrantPublicKey): this {
    this.#keys.set(kid, key);
    return this;
  }

  get(kid: string): AttemptGrantPublicKey | undefined {
    return this.#keys.get(kid);
  }
}

/**
 * Build a `SimpleKeyRing` from the fixture's `authorityKeys` array.
 * Each entry has `kid`, `x`, `y` as base64url coordinates.
 */
export function keyRingFromFixture(
  authorityKeys: ReadonlyArray<{
    kid: string;
    x: string;
    y: string;
  }>,
): SimpleKeyRing {
  const ring = new SimpleKeyRing();
  for (const k of authorityKeys) {
    const xBytes = Buffer.from(k.x, "base64url");
    const yBytes = Buffer.from(k.y, "base64url");
    if (xBytes.length !== 32 || yBytes.length !== 32) {
      throw new AttemptGrantError("signature", `authority key ${k.kid} has invalid coordinates`);
    }
    ring.addKey(k.kid, { x: xBytes, y: yBytes });
  }
  return ring;
}
