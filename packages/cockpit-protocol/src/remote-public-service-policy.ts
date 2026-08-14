/**
 * Signed public SaaS remote service-policy foundation (TypeScript pair).
 *
 * Byte-identical mirror of `crates/cockpit-proto/src/remote_public_service_policy.rs`
 * and its shared `es256` verifier. This module is the sole TypeScript owner of
 * the closed capability vocabularies, the permission-ceiling binary codec + its
 * SHA-256 digest, the transport-bit and tuple-set codecs, the connection-policy
 * schema, the signed `RemotePublicServicePolicyV1` envelope, strict ES256 JWS
 * verification (WebCrypto, low-S enforced, fail-closed), three-valued change
 * classification, and the cross-language state vocabulary. Downstream consumers
 * import these definitions; they do not redefine the enums, bit assignments,
 * tuple layout, permission bytes, or digest derivation.
 */
import { z } from "zod";
import {
  canonicalizeRfc8785,
  decodeProtocolIdBase64Url,
  encodeProtocolIdBase64Url,
  parseCanonicalU64DecimalString,
} from "./remote-protocol-id";
import { registryTuple } from "./remote-version";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const POLICY_SCHEMA_VERSION = 1 as const;
export const POLICY_JWS_TYP = "flycockpit-public-remote-policy+jws" as const;
export const POLICY_JWS_ALG = "ES256" as const;
export const IMPORT_CLOCK_SKEW_SECONDS = 60n;
export const NOT_BEFORE_MAX_OFFSET_SECONDS = 2_592_000n; // 30 days
export const PERMISSION_CEILING_MAX_BYTES = 512;
export const TUPLE_SET_MIN = 1;
export const TUPLE_SET_MAX = 16;

export const ALLOWED_TURN_REGIONS = [
  "africa",
  "asia_pacific",
  "europe",
  "local",
  "middle_east",
  "north_america",
  "oceania",
  "south_america",
] as const;

export const ALLOWED_TRANSPORTS = ["webrtc", "websocket_data"] as const;

export const CRITICAL_CONSUMER_IDS = [
  "attempt_issuer",
  "signaling_gateway",
  "daemon_authorizer",
  "turn_issuer",
  "websocket_fallback_gateway",
  "web_route_selector",
  "native_route_selector",
  "metadata_retention_worker",
] as const;

// Timing constants (seconds) — pinned cross-language by the fixture corpus.
export const CONVERGENCE_TIMEOUT_SECONDS = 300;
export const REPLICA_LEASE_RENEW_SECONDS = 15;
export const REPLICA_LEASE_TTL_SECONDS = 45;
export const STALE_REAP_GRACE_SECONDS = 90;

// P-256 group order n and n/2 (for low-S enforcement).
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N >> 1n;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export type RemotePublicPolicyErrorKind = "invalid" | "ceiling" | "jws" | "jwks" | "capability";

export class RemotePublicPolicyError extends Error {
  readonly kind: RemotePublicPolicyErrorKind;
  constructor(kind: RemotePublicPolicyErrorKind, message: string) {
    super(`${kind}: ${message}`);
    this.name = "RemotePublicPolicyError";
    this.kind = kind;
  }
}

function fail(kind: RemotePublicPolicyErrorKind, message: string): never {
  throw new RemotePublicPolicyError(kind, message);
}

// ---------------------------------------------------------------------------
// base64url (pure JS, no Buffer/btoa — portable to web and native)
// ---------------------------------------------------------------------------

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_LOOKUP: ReadonlyMap<string, number> = new Map(
  Array.from(B64URL_ALPHABET, (ch, i) => [ch, i] as const),
);

function base64UrlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const has1 = i + 1 < bytes.length;
    const has2 = i + 2 < bytes.length;
    const b1 = has1 ? (bytes[i + 1] as number) : 0;
    const b2 = has2 ? (bytes[i + 2] as number) : 0;
    out += B64URL_ALPHABET[b0 >> 2];
    out += B64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (has1) out += B64URL_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)];
    if (has2) out += B64URL_ALPHABET[b2 & 0x3f];
  }
  return out;
}

function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    fail("jws", "invalid base64url");
  }
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text) {
    const value = B64URL_LOOKUP.get(ch);
    if (value === undefined) {
      fail("jws", "invalid base64url character");
    }
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// Hex + SHA-256
// ---------------------------------------------------------------------------

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** SHA-256 via WebCrypto (no hand-rolled hash on any security/digest path). */
async function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return new Uint8Array(digest);
}

const TEXT_ENCODER = new TextEncoder();

// ---------------------------------------------------------------------------
// Capability enums (closed const maps; ordinals 1..13 overlap by design)
// ---------------------------------------------------------------------------

export const RemoteProjectCapabilityV1 = {
  ProjectRead: 1,
  ProjectWrite: 2,
  FilesystemRead: 3,
  FilesystemWrite: 4,
  TerminalRead: 5,
  TerminalControl: 6,
  SessionRead: 7,
  SessionWrite: 8,
  NotesRead: 9,
  NotesWrite: 10,
  SchedulerRead: 11,
  SchedulerWrite: 12,
  ResourcePromote: 13,
  LspControl: 14,
  ImageGenerationAdmin: 15,
} as const;
export type RemoteProjectCapabilityV1 =
  (typeof RemoteProjectCapabilityV1)[keyof typeof RemoteProjectCapabilityV1];

export const RemoteAttachmentCapabilityV1 = {
  AttachmentRead: 1,
  AttachmentManageChildren: 2,
  SessionCreate: 3,
  SessionImport: 4,
  SessionArchive: 5,
  SessionDelete: 6,
  ModelConfigure: 7,
  AgentConfigure: 8,
  ApprovalConfigure: 9,
  SandboxConfigure: 10,
  CredentialManage: 11,
  DaemonManage: 12,
  UsageRecord: 13,
} as const;
export type RemoteAttachmentCapabilityV1 =
  (typeof RemoteAttachmentCapabilityV1)[keyof typeof RemoteAttachmentCapabilityV1];

const PROJECT_CAPABILITY_ORDINALS: ReadonlySet<number> = new Set(
  Object.values(RemoteProjectCapabilityV1),
);
const ATTACHMENT_CAPABILITY_ORDINALS: ReadonlySet<number> = new Set(
  Object.values(RemoteAttachmentCapabilityV1),
);

export function projectCapabilityFromOrdinal(v: number): RemoteProjectCapabilityV1 {
  if (!PROJECT_CAPABILITY_ORDINALS.has(v)) {
    fail("capability", `unknown project capability ordinal ${v}`);
  }
  return v as RemoteProjectCapabilityV1;
}

export function attachmentCapabilityFromOrdinal(v: number): RemoteAttachmentCapabilityV1 {
  if (!ATTACHMENT_CAPABILITY_ORDINALS.has(v)) {
    fail("capability", `unknown attachment capability ordinal ${v}`);
  }
  return v as RemoteAttachmentCapabilityV1;
}

// ---------------------------------------------------------------------------
// RemotePermissionCeilingV1 (exact network-byte-order binary codec)
// ---------------------------------------------------------------------------

export interface RemotePermissionCeilingV1 {
  attachmentCapabilities: RemoteAttachmentCapabilityV1[];
  /** (16-byte project id, project capabilities) pairs, raw-id-byte sorted. */
  projects: Array<{ projectId: Uint8Array; capabilities: RemoteProjectCapabilityV1[] }>;
}

export function emptyPermissionCeiling(): RemotePermissionCeilingV1 {
  return { attachmentCapabilities: [], projects: [] };
}

function validateSortedUniqueOrdinals(ords: number[], max: number, label: string): void {
  if (ords.length > max) fail("ceiling", `${label} capability count exceeds ${max}`);
  let prev = 0;
  for (let i = 0; i < ords.length; i++) {
    const o = ords[i] as number;
    if (o === 0) fail("ceiling", `zero ${label} capability ordinal`);
    if (i > 0 && o <= prev) fail("ceiling", `${label} capabilities must be strictly ascending`);
    prev = o;
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

export function encodePermissionCeiling(
  ceiling: RemotePermissionCeilingV1,
): Uint8Array<ArrayBuffer> {
  validateSortedUniqueOrdinals(ceiling.attachmentCapabilities, 16, "attachment");
  if (ceiling.attachmentCapabilities.length > 16) {
    fail("ceiling", "attachment capability count exceeds 16");
  }
  if (ceiling.projects.length > 16) fail("ceiling", "project count exceeds 16");

  let prevId: Uint8Array | null = null;
  for (const { projectId, capabilities } of ceiling.projects) {
    if (projectId.length !== 16) fail("ceiling", "project id must be 16 bytes");
    if (projectId.every((b) => b === 0)) fail("ceiling", "project id must be nonzero");
    if (prevId !== null && compareBytes(prevId, projectId) >= 0) {
      fail("ceiling", "project ids must be strictly ascending");
    }
    prevId = projectId;
    if (capabilities.length === 0 || capabilities.length > 16) {
      fail("ceiling", "project capability count must be 1..16");
    }
    validateSortedUniqueOrdinals(capabilities, 16, "project");
  }

  const total =
    1 +
    1 +
    ceiling.attachmentCapabilities.length +
    1 +
    ceiling.projects.reduce((acc, p) => acc + 16 + 1 + p.capabilities.length, 0);
  if (total > PERMISSION_CEILING_MAX_BYTES) {
    fail("ceiling", `permission ceiling is ${total} bytes; cap is ${PERMISSION_CEILING_MAX_BYTES}`);
  }

  const buf = new Uint8Array(total);
  let pos = 0;
  buf[pos++] = 1;
  buf[pos++] = ceiling.attachmentCapabilities.length;
  for (const cap of ceiling.attachmentCapabilities) buf[pos++] = cap;
  buf[pos++] = ceiling.projects.length;
  for (const { projectId, capabilities } of ceiling.projects) {
    buf.set(projectId, pos);
    pos += 16;
    buf[pos++] = capabilities.length;
    for (const cap of capabilities) buf[pos++] = cap;
  }
  return buf;
}

export function decodePermissionCeiling(bytes: Uint8Array): RemotePermissionCeilingV1 {
  if (bytes.length === 0) fail("ceiling", "permission ceiling is empty");
  if (bytes[0] !== 1) fail("ceiling", "permission ceiling version must be 1");
  let pos = 1;
  if (pos >= bytes.length) fail("ceiling", "truncated attachment count");
  const attCount = bytes[pos++] as number;
  if (attCount > 16) fail("ceiling", "attachment capability count exceeds 16");
  if (pos + attCount > bytes.length) fail("ceiling", "truncated attachment capabilities");
  const attachmentCapabilities: RemoteAttachmentCapabilityV1[] = [];
  let prevAtt = 0;
  for (let i = 0; i < attCount; i++) {
    const ord = bytes[pos + i] as number;
    if (ord === 0) fail("ceiling", "zero attachment capability ordinal");
    if (i > 0 && ord <= prevAtt)
      fail("ceiling", "attachment capabilities must be strictly ascending");
    prevAtt = ord;
    attachmentCapabilities.push(attachmentCapabilityFromOrdinal(ord));
  }
  pos += attCount;

  if (pos >= bytes.length) fail("ceiling", "truncated project count");
  const projCount = bytes[pos++] as number;
  if (projCount > 16) fail("ceiling", "project count exceeds 16");

  const projects: RemotePermissionCeilingV1["projects"] = [];
  let prevPid: Uint8Array | null = null;
  for (let p = 0; p < projCount; p++) {
    if (pos + 16 > bytes.length) fail("ceiling", "truncated project id");
    const projectId = bytes.slice(pos, pos + 16);
    pos += 16;
    if (projectId.every((b) => b === 0)) fail("ceiling", "project id must be nonzero");
    if (prevPid !== null && compareBytes(prevPid, projectId) >= 0) {
      fail("ceiling", "project ids must be strictly ascending");
    }
    prevPid = projectId;
    if (pos >= bytes.length) fail("ceiling", "truncated project capability count");
    const capCount = bytes[pos++] as number;
    if (capCount === 0 || capCount > 16) fail("ceiling", "project capability count must be 1..16");
    if (pos + capCount > bytes.length) fail("ceiling", "truncated project capabilities");
    const capabilities: RemoteProjectCapabilityV1[] = [];
    let prevCap = 0;
    for (let i = 0; i < capCount; i++) {
      const ord = bytes[pos + i] as number;
      if (ord === 0) fail("ceiling", "zero project capability ordinal");
      if (i > 0 && ord <= prevCap)
        fail("ceiling", "project capabilities must be strictly ascending");
      prevCap = ord;
      capabilities.push(projectCapabilityFromOrdinal(ord));
    }
    pos += capCount;
    projects.push({ projectId, capabilities });
  }

  if (pos !== bytes.length) fail("ceiling", "trailing bytes in permission ceiling");

  const ceiling: RemotePermissionCeilingV1 = { attachmentCapabilities, projects };
  const re = encodePermissionCeiling(ceiling);
  if (compareBytes(re, bytes) !== 0 || re.length !== bytes.length) {
    fail("ceiling", "permission ceiling noncanonical re-encoding");
  }
  return ceiling;
}

/** SHA-256 of the complete canonical permission-ceiling bytes. */
export async function permissionCeilingDigest(
  ceiling: RemotePermissionCeilingV1,
): Promise<Uint8Array<ArrayBuffer>> {
  return sha256(encodePermissionCeiling(ceiling));
}

export async function permissionCeilingDigestHex(
  ceiling: RemotePermissionCeilingV1,
): Promise<string> {
  return toHex(await permissionCeilingDigest(ceiling));
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedTransportBitsV1
// ---------------------------------------------------------------------------

export const TRANSPORT_BIT_WEBRTC = 0x01;
export const TRANSPORT_BIT_WEBSOCKET_DATA = 0x02;
export const TRANSPORT_BITS_VALID = [0x01, 0x02, 0x03] as const;

export function validateTransportBits(bits: number): void {
  if (!TRANSPORT_BITS_VALID.includes(bits as (typeof TRANSPORT_BITS_VALID)[number])) {
    fail("invalid", `transport bits must be 0x01, 0x02, or 0x03; got 0x${bits.toString(16)}`);
  }
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedTupleSetV1
// ---------------------------------------------------------------------------

function checkRevokedSet(revoked: readonly number[]): void {
  if (revoked.includes(0)) fail("invalid", "revoked tuple id must be nonzero");
}

export function encodeTupleSet(
  tupleIds: readonly number[],
  revoked: readonly number[],
): Uint8Array<ArrayBuffer> {
  checkRevokedSet(revoked);
  if (tupleIds.length < TUPLE_SET_MIN || tupleIds.length > TUPLE_SET_MAX) {
    fail("invalid", `tuple set count must be ${TUPLE_SET_MIN}..=${TUPLE_SET_MAX}`);
  }
  let prev = 0;
  for (let i = 0; i < tupleIds.length; i++) {
    const id = tupleIds[i] as number;
    if (id === 0) fail("invalid", "tuple id must be nonzero");
    if (i > 0 && id <= prev) fail("invalid", "tuple ids must be strictly increasing");
    prev = id;
    if (registryTuple(id) === undefined) fail("invalid", `tuple id ${id} not in enabled registry`);
    if (revoked.includes(id)) fail("invalid", `tuple id ${id} is revoked`);
  }
  const buf = new Uint8Array(1 + tupleIds.length * 2);
  buf[0] = tupleIds.length;
  for (let i = 0; i < tupleIds.length; i++) {
    const id = tupleIds[i] as number;
    buf[1 + i * 2] = (id >> 8) & 0xff;
    buf[2 + i * 2] = id & 0xff;
  }
  return buf;
}

export function decodeTupleSet(bytes: Uint8Array, revoked: readonly number[]): number[] {
  checkRevokedSet(revoked);
  if (bytes.length === 0) fail("invalid", "tuple set is empty");
  const count = bytes[0] as number;
  if (count < TUPLE_SET_MIN || count > TUPLE_SET_MAX) {
    fail("invalid", `tuple set count must be ${TUPLE_SET_MIN}..=${TUPLE_SET_MAX}`);
  }
  if (bytes.length !== 1 + count * 2) fail("invalid", "tuple set length mismatch");
  const ids: number[] = [];
  let prev = 0;
  for (let i = 0; i < count; i++) {
    const off = 1 + i * 2;
    const id = ((bytes[off] as number) << 8) | (bytes[off + 1] as number);
    if (id === 0) fail("invalid", "tuple id must be nonzero");
    if (i > 0 && id <= prev) fail("invalid", "tuple ids must be strictly increasing");
    prev = id;
    if (registryTuple(id) === undefined) fail("invalid", `tuple id ${id} not in enabled registry`);
    if (revoked.includes(id)) fail("invalid", `tuple id ${id} is revoked`);
    ids.push(id);
  }
  const re = encodeTupleSet(ids, revoked);
  if (compareBytes(re, bytes) !== 0 || re.length !== bytes.length) {
    fail("invalid", "tuple set noncanonical re-encoding");
  }
  return ids;
}

// ---------------------------------------------------------------------------
// RemoteConnectionPolicyV1 — custody ranks + policy schema
// ---------------------------------------------------------------------------

export type DaemonCustodyPolicy = "os_protected" | "hardware_or_external";
export type ClientCustodyPolicy = "origin_protected" | "os_protected" | "hardware";
export type DirectIpMode = "forbid" | "mutual_consent";
export type SharedSessionRoute = "relay_only" | "per_leg_policy";
export type TenantAuthorization = "control_plane" | "tenant_signer_required";

const DAEMON_CUSTODY_RANK: Record<DaemonCustodyPolicy, number> = {
  os_protected: 0,
  hardware_or_external: 1,
};
const CLIENT_CUSTODY_RANK: Record<ClientCustodyPolicy, number> = {
  origin_protected: 0,
  os_protected: 1,
  hardware: 2,
};
const DIRECT_IP_RANK: Record<DirectIpMode, number> = { forbid: 0, mutual_consent: 1 };
const ROUTE_RANK: Record<SharedSessionRoute, number> = { relay_only: 0, per_leg_policy: 1 };
const TENANT_AUTH_RANK: Record<TenantAuthorization, number> = {
  tenant_signer_required: 0,
  control_plane: 1,
};

export interface RemoteConnectionLimitsV1 {
  registeredDaemons: string;
  concurrentAttachments: string;
  concurrentChildrenPerAttachment: string;
  concurrentParticipantsPerSession: string;
  turnBytesPerAttachment: string;
  turnDurationSeconds: string;
  websocketBytesPerAttachment: string;
  websocketDurationSeconds: string;
}

export interface RemoteConnectionPolicyV1 {
  allowedTransports: string[];
  directIpMode: DirectIpMode;
  sharedSessionRoute: SharedSessionRoute;
  websocketFallback: boolean;
  tenantAuthorization: TenantAuthorization;
  minimumDaemonCustody: DaemonCustodyPolicy;
  minimumClientCustody: ClientCustodyPolicy;
  sharingEnabled: boolean;
  limits: RemoteConnectionLimitsV1;
  allowedTurnRegions: string[];
  metadataRetentionDays: string;
}

export type ChangeClass = "narrowing_or_equal" | "widening";

export interface RemotePublicServicePolicyV1 {
  schemaVersion: number;
  policyId: string;
  serviceVersion: string;
  previousDigest: string | null;
  issuedAt: string;
  notBefore: string;
  changeClass: ChangeClass;
  policy: RemoteConnectionPolicyV1;
}

const canonicalU64String = z.string().refine((s) => {
  try {
    parseCanonicalU64DecimalString(s);
    return true;
  } catch {
    return false;
  }
}, "canonical u64 decimal string required");

const limitsSchema = z
  .object({
    registeredDaemons: canonicalU64String,
    concurrentAttachments: canonicalU64String,
    concurrentChildrenPerAttachment: canonicalU64String,
    concurrentParticipantsPerSession: canonicalU64String,
    turnBytesPerAttachment: canonicalU64String,
    turnDurationSeconds: canonicalU64String,
    websocketBytesPerAttachment: canonicalU64String,
    websocketDurationSeconds: canonicalU64String,
  })
  .strict();

export const remoteConnectionPolicyV1Schema = z
  .object({
    allowedTransports: z.array(z.string()),
    directIpMode: z.enum(["forbid", "mutual_consent"]),
    sharedSessionRoute: z.enum(["relay_only", "per_leg_policy"]),
    websocketFallback: z.boolean(),
    tenantAuthorization: z.enum(["control_plane", "tenant_signer_required"]),
    minimumDaemonCustody: z.enum(["os_protected", "hardware_or_external"]),
    minimumClientCustody: z.enum(["origin_protected", "os_protected", "hardware"]),
    sharingEnabled: z.boolean(),
    limits: limitsSchema,
    allowedTurnRegions: z.array(z.string()),
    metadataRetentionDays: canonicalU64String,
  })
  .strict();

export const remotePublicServicePolicyV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    policyId: z.string(),
    serviceVersion: canonicalU64String,
    previousDigest: z.string().nullable(),
    issuedAt: canonicalU64String,
    notBefore: canonicalU64String,
    changeClass: z.enum(["narrowing_or_equal", "widening"]),
    policy: remoteConnectionPolicyV1Schema,
  })
  .strict();

function validateSortedUniqueStrings(
  values: string[],
  allowed: readonly string[],
  label: string,
): void {
  let prev = "";
  for (let i = 0; i < values.length; i++) {
    const v = values[i] as string;
    if (!allowed.includes(v)) fail("invalid", `unknown ${label} ${v}`);
    if (i > 0 && v <= prev) fail("invalid", `${label}s must be strictly ascending and unique`);
    prev = v;
  }
}

export function validateConnectionPolicy(policy: RemoteConnectionPolicyV1): void {
  if (policy.allowedTransports.length === 0) fail("invalid", "allowedTransports must be nonempty");
  validateSortedUniqueStrings(policy.allowedTransports, ALLOWED_TRANSPORTS, "transport");
  validateSortedUniqueStrings(policy.allowedTurnRegions, ALLOWED_TURN_REGIONS, "turn region");

  const retention = parseCanonicalU64DecimalString(policy.metadataRetentionDays);
  if (retention > 365n) fail("invalid", `metadataRetentionDays must be 0..365; got ${retention}`);

  const limitEntries: Array<[string, string]> = [
    ["registeredDaemons", policy.limits.registeredDaemons],
    ["concurrentAttachments", policy.limits.concurrentAttachments],
    ["concurrentChildrenPerAttachment", policy.limits.concurrentChildrenPerAttachment],
    ["concurrentParticipantsPerSession", policy.limits.concurrentParticipantsPerSession],
    ["turnBytesPerAttachment", policy.limits.turnBytesPerAttachment],
    ["turnDurationSeconds", policy.limits.turnDurationSeconds],
    ["websocketBytesPerAttachment", policy.limits.websocketBytesPerAttachment],
    ["websocketDurationSeconds", policy.limits.websocketDurationSeconds],
  ];
  for (const [name, value] of limitEntries) {
    if (parseCanonicalU64DecimalString(value) === 0n) {
      fail("invalid", `limit ${name} must be positive (nonzero)`);
    }
  }

  if (policy.websocketFallback && !policy.allowedTransports.includes("websocket_data")) {
    fail("invalid", "websocketFallback=true requires websocket_data in allowedTransports");
  }
  if (policy.sharedSessionRoute === "relay_only") {
    const hasWebrtc = policy.allowedTransports.includes("webrtc");
    const hasRegion = policy.allowedTurnRegions.length > 0;
    if (!(hasWebrtc && hasRegion) && !policy.websocketFallback) {
      fail(
        "invalid",
        "sharedSessionRoute=relay_only requires either WebRTC with at least one region or WebSocket fallback",
      );
    }
  }
}

export function validateDigestHex(hex: string): void {
  if (hex.length !== 64) fail("invalid", `digest must be 64 hex chars; got ${hex.length}`);
  if (!/^[0-9a-f]{64}$/.test(hex)) fail("invalid", "digest must be lowercase hex");
}

export function validatePublicServicePolicy(policy: RemotePublicServicePolicyV1): void {
  if (policy.schemaVersion !== POLICY_SCHEMA_VERSION) {
    fail("invalid", `schemaVersion must be ${POLICY_SCHEMA_VERSION}; got ${policy.schemaVersion}`);
  }
  if (policy.previousDigest !== null) validateDigestHex(policy.previousDigest);
  parseCanonicalU64DecimalString(policy.serviceVersion);
  parseCanonicalU64DecimalString(policy.issuedAt);
  parseCanonicalU64DecimalString(policy.notBefore);
  validateConnectionPolicy(policy.policy);
}

/** RFC 8785 canonical JSON of exactly the envelope fields. */
export function canonicalPolicyJson(policy: RemotePublicServicePolicyV1): string {
  return canonicalizeRfc8785(policy);
}

export async function payloadDigestHex(policy: RemotePublicServicePolicyV1): Promise<string> {
  const canonical = canonicalPolicyJson(policy);
  return toHex(await sha256(TEXT_ENCODER.encode(canonical)));
}

/** Import-time validation with 60s skew and 30-day notBefore window. */
export function validateForImport(policy: RemotePublicServicePolicyV1, importTime: bigint): void {
  validatePublicServicePolicy(policy);
  const issued = parseCanonicalU64DecimalString(policy.issuedAt);
  const notBefore = parseCanonicalU64DecimalString(policy.notBefore);

  if (issued > importTime + IMPORT_CLOCK_SKEW_SECONDS) {
    fail(
      "invalid",
      `issuedAt ${issued} exceeds importTime ${importTime} + ${IMPORT_CLOCK_SKEW_SECONDS}s skew`,
    );
  }
  if (notBefore < issued - IMPORT_CLOCK_SKEW_SECONDS) {
    fail(
      "invalid",
      `notBefore ${notBefore} is before issuedAt ${issued} - ${IMPORT_CLOCK_SKEW_SECONDS}s skew`,
    );
  }
  if (notBefore > issued + NOT_BEFORE_MAX_OFFSET_SECONDS) {
    fail(
      "invalid",
      `notBefore ${notBefore} exceeds issuedAt ${issued} + ${NOT_BEFORE_MAX_OFFSET_SECONDS}s (30 days)`,
    );
  }
}

// ---------------------------------------------------------------------------
// Three-valued change classification (mirrors the Rust foundation)
// ---------------------------------------------------------------------------

export type PolicyChangeClassification = "narrowing_or_equal" | "widening" | "mixed";

export function classifyPolicyChange(
  previous: RemoteConnectionPolicyV1,
  next: RemoteConnectionPolicyV1,
): PolicyChangeClassification {
  const transportWidening = next.allowedTransports.some(
    (t) => !previous.allowedTransports.includes(t),
  );
  const transportNarrowing = previous.allowedTransports.some(
    (t) => !next.allowedTransports.includes(t),
  );
  const regionWidening = next.allowedTurnRegions.some(
    (r) => !previous.allowedTurnRegions.includes(r),
  );
  const regionNarrowing = previous.allowedTurnRegions.some(
    (r) => !next.allowedTurnRegions.includes(r),
  );

  const wsWidening = next.websocketFallback && !previous.websocketFallback;
  const wsNarrowing = previous.websocketFallback && !next.websocketFallback;
  const sharingWidening = next.sharingEnabled && !previous.sharingEnabled;
  const sharingNarrowing = previous.sharingEnabled && !next.sharingEnabled;

  const limitPairs: Array<[bigint, bigint]> = [
    [n64(previous.limits.registeredDaemons), n64(next.limits.registeredDaemons)],
    [n64(previous.limits.concurrentAttachments), n64(next.limits.concurrentAttachments)],
    [
      n64(previous.limits.concurrentChildrenPerAttachment),
      n64(next.limits.concurrentChildrenPerAttachment),
    ],
    [
      n64(previous.limits.concurrentParticipantsPerSession),
      n64(next.limits.concurrentParticipantsPerSession),
    ],
    [n64(previous.limits.turnBytesPerAttachment), n64(next.limits.turnBytesPerAttachment)],
    [n64(previous.limits.turnDurationSeconds), n64(next.limits.turnDurationSeconds)],
    [
      n64(previous.limits.websocketBytesPerAttachment),
      n64(next.limits.websocketBytesPerAttachment),
    ],
    [n64(previous.limits.websocketDurationSeconds), n64(next.limits.websocketDurationSeconds)],
  ];
  const limitsWidening = limitPairs.some(([p, nv]) => nv > p);
  const limitsNarrowing = limitPairs.some(([p, nv]) => nv < p);

  const daemonWidening =
    DAEMON_CUSTODY_RANK[next.minimumDaemonCustody] <
    DAEMON_CUSTODY_RANK[previous.minimumDaemonCustody];
  const daemonNarrowing =
    DAEMON_CUSTODY_RANK[next.minimumDaemonCustody] >
    DAEMON_CUSTODY_RANK[previous.minimumDaemonCustody];
  const clientWidening =
    CLIENT_CUSTODY_RANK[next.minimumClientCustody] <
    CLIENT_CUSTODY_RANK[previous.minimumClientCustody];
  const clientNarrowing =
    CLIENT_CUSTODY_RANK[next.minimumClientCustody] >
    CLIENT_CUSTODY_RANK[previous.minimumClientCustody];

  const directIpWidening =
    DIRECT_IP_RANK[next.directIpMode] > DIRECT_IP_RANK[previous.directIpMode];
  const directIpNarrowing =
    DIRECT_IP_RANK[next.directIpMode] < DIRECT_IP_RANK[previous.directIpMode];
  const routeWidening =
    ROUTE_RANK[next.sharedSessionRoute] > ROUTE_RANK[previous.sharedSessionRoute];
  const routeNarrowing =
    ROUTE_RANK[next.sharedSessionRoute] < ROUTE_RANK[previous.sharedSessionRoute];
  const authWidening =
    TENANT_AUTH_RANK[next.tenantAuthorization] > TENANT_AUTH_RANK[previous.tenantAuthorization];
  const authNarrowing =
    TENANT_AUTH_RANK[next.tenantAuthorization] < TENANT_AUTH_RANK[previous.tenantAuthorization];

  const retentionWidening = n64(next.metadataRetentionDays) > n64(previous.metadataRetentionDays);
  const retentionNarrowing = n64(next.metadataRetentionDays) < n64(previous.metadataRetentionDays);

  const anyWidening =
    transportWidening ||
    regionWidening ||
    wsWidening ||
    sharingWidening ||
    limitsWidening ||
    daemonWidening ||
    clientWidening ||
    directIpWidening ||
    routeWidening ||
    authWidening ||
    retentionWidening;
  const anyNarrowing =
    transportNarrowing ||
    regionNarrowing ||
    wsNarrowing ||
    sharingNarrowing ||
    limitsNarrowing ||
    daemonNarrowing ||
    clientNarrowing ||
    directIpNarrowing ||
    routeNarrowing ||
    authNarrowing ||
    retentionNarrowing;

  if (anyWidening && anyNarrowing) return "mixed";
  if (anyWidening) return "widening";
  return "narrowing_or_equal";
}

function n64(s: string): bigint {
  return parseCanonicalU64DecimalString(s);
}

// ---------------------------------------------------------------------------
// Compact ES256 JWS + JWKS ring
// ---------------------------------------------------------------------------

export interface ParsedPolicyJws {
  protectedHeader: Record<string, unknown>;
  payload: unknown;
  signature: Uint8Array<ArrayBuffer>;
  signingInput: Uint8Array<ArrayBuffer>;
}

export function parsePolicyJws(compact: string): ParsedPolicyJws {
  const parts = compact.split(".");
  if (parts.length !== 3) fail("jws", "compact JWS must have exactly three parts");
  const [h, p, s] = parts as [string, string, string];

  const headerBytes = base64UrlDecode(h);
  const payloadBytes = base64UrlDecode(p);
  const signature = base64UrlDecode(s);

  if (base64UrlEncode(headerBytes) !== h) fail("jws", "noncanonical base64url header");
  if (base64UrlEncode(payloadBytes) !== p) fail("jws", "noncanonical base64url payload");
  if (base64UrlEncode(signature) !== s) fail("jws", "noncanonical base64url signature");

  const header = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(headerBytes),
  ) as unknown;
  validatePolicyJwsHeader(header);
  const payload = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes),
  ) as unknown;

  return {
    protectedHeader: header as Record<string, unknown>,
    payload,
    signature,
    signingInput: TEXT_ENCODER.encode(`${h}.${p}`),
  };
}

export function validatePolicyJwsHeader(
  header: unknown,
): asserts header is Record<string, unknown> {
  if (typeof header !== "object" || header === null || Array.isArray(header)) {
    fail("jws", "header must be an object");
  }
  const obj = header as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== 3) fail("jws", `header must have exactly 3 keys; got ${keys.length}`);
  if (obj.alg !== POLICY_JWS_ALG) fail("jws", `header alg must be ${POLICY_JWS_ALG}`);
  if (obj.typ !== POLICY_JWS_TYP) fail("jws", `header typ must be ${POLICY_JWS_TYP}`);
  if (typeof obj.kid !== "string" || obj.kid.length === 0)
    fail("jws", "header kid must be nonempty");
}

export type JwkRole = "current" | "previous" | "next";

export interface PolicyJwk {
  kid: string;
  kty: string;
  crv: string;
  x: string;
  y: string;
  use: string;
  key_ops: string[];
  flycockpit_role: JwkRole;
}

export interface PolicyJwksRing {
  keys: PolicyJwk[];
}

function validateBase64Url32Bytes(s: string, label: string): Uint8Array {
  if (s.includes("=")) fail("jwks", `${label} must be unpadded base64url`);
  const bytes = base64UrlDecode(s);
  if (bytes.length !== 32) fail("jwks", `${label} must be 32 bytes; got ${bytes.length}`);
  if (base64UrlEncode(bytes) !== s) fail("jwks", `${label} noncanonical base64url`);
  return bytes;
}

async function rfc7638Thumbprint(x: string, y: string): Promise<string> {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`;
  return base64UrlEncode(await sha256(TEXT_ENCODER.encode(canonical)));
}

/** Parse and validate the strict rotation ring (mirrors the Rust parser). */
export async function parsePolicyJwks(json: string): Promise<PolicyJwksRing> {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch (e) {
    fail("jwks", `JWKS parse failed: ${(e as Error).message}`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("jwks", "JWKS must be an object");
  }
  const obj = value as Record<string, unknown>;
  if (Object.keys(obj).length !== 1 || !Object.hasOwn(obj, "keys")) {
    fail("jwks", "JWKS must have exactly one 'keys' field");
  }
  const keysArr = obj.keys;
  if (!Array.isArray(keysArr)) fail("jwks", "'keys' must be an array");
  if (keysArr.length < 1 || keysArr.length > 3) {
    fail("jwks", `JWKS must have 1..=3 keys; got ${keysArr.length}`);
  }

  const allowed = ["kid", "kty", "crv", "x", "y", "use", "key_ops", "flycockpit_role"];
  const keys: PolicyJwk[] = [];
  const kids: string[] = [];
  const thumbprints: string[] = [];
  const roleSeen: Record<JwkRole, boolean> = { current: false, previous: false, next: false };

  for (const keyVal of keysArr) {
    if (typeof keyVal !== "object" || keyVal === null || Array.isArray(keyVal)) {
      fail("jwks", "JWK must be an object");
    }
    const keyObj = keyVal as Record<string, unknown>;
    for (const k of Object.keys(keyObj)) {
      if (!allowed.includes(k)) fail("jwks", `unknown JWK field ${k}`);
    }
    if (Object.keys(keyObj).length !== allowed.length) {
      fail(
        "jwks",
        `JWK must have exactly ${allowed.length} fields; got ${Object.keys(keyObj).length}`,
      );
    }

    const kid = keyObj.kid;
    if (typeof kid !== "string" || kid.length === 0) fail("jwks", "kid must be nonempty");
    if (kids.includes(kid)) fail("jwks", `duplicate kid ${kid}`);
    kids.push(kid);

    if (keyObj.kty !== "EC") fail("jwks", `kty must be EC; got ${String(keyObj.kty)}`);
    if (keyObj.crv !== "P-256") fail("jwks", `crv must be P-256; got ${String(keyObj.crv)}`);
    if (typeof keyObj.x !== "string" || typeof keyObj.y !== "string") {
      fail("jwks", "x and y must be strings");
    }
    const xBytes = validateBase64Url32Bytes(keyObj.x, "x");
    const yBytes = validateBase64Url32Bytes(keyObj.y, "y");
    if (xBytes.every((b) => b === 0) || yBytes.every((b) => b === 0)) {
      fail("jwks", "P-256 point coordinate must be nonzero");
    }

    const thumbprint = await rfc7638Thumbprint(keyObj.x, keyObj.y);
    if (thumbprints.includes(thumbprint)) fail("jwks", "duplicate RFC 7638 thumbprint");
    thumbprints.push(thumbprint);

    if (keyObj.use !== "sig") fail("jwks", `use must be sig; got ${String(keyObj.use)}`);
    const keyOps = keyObj.key_ops;
    if (!Array.isArray(keyOps) || keyOps.length !== 1 || keyOps[0] !== "verify") {
      fail("jwks", 'key_ops must be ["verify"]');
    }
    const role = keyObj.flycockpit_role;
    if (role !== "current" && role !== "previous" && role !== "next") {
      fail("jwks", `flycockpit_role must be current|previous|next; got ${String(role)}`);
    }
    if (roleSeen[role]) fail("jwks", `duplicate ${role} role`);
    roleSeen[role] = true;

    keys.push({
      kid,
      kty: "EC",
      crv: "P-256",
      x: keyObj.x,
      y: keyObj.y,
      use: "sig",
      key_ops: ["verify"],
      flycockpit_role: role,
    });
  }

  if (!roleSeen.current) fail("jwks", "JWKS must have exactly one current key");
  return { keys };
}

export type PolicyKeyUsage = "import" | "verify_imported";

function bigIntFromBytes(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/**
 * Verify a compact ES256 policy JWS against the ring, fail-closed. Mirrors the
 * Rust `verify_policy_jws`: strict header, kid resolution, role gate, 64-byte
 * raw signature, explicit low-S / zero-scalar rejection BEFORE the WebCrypto
 * verify (jose is deliberately not used on this path).
 */
export async function verifyPolicyJws(
  compact: string,
  ring: PolicyJwksRing,
  usage: PolicyKeyUsage,
): Promise<ParsedPolicyJws> {
  // Closed-set usage validation, mirroring the Rust `PolicyKeyUsage` enum. An
  // untyped/deserialized value other than these two must fail closed BEFORE the
  // role gate — never silently fall through to the previous-key verify path.
  if (usage !== "import" && usage !== "verify_imported") {
    fail("jws", `unknown policy key usage ${String(usage)}`);
  }

  const parsed = parsePolicyJws(compact);
  const kid = parsed.protectedHeader.kid;
  if (typeof kid !== "string") fail("jws", "header missing kid");

  const jwk = ring.keys.find((k) => k.kid === kid);
  if (jwk === undefined) fail("jwks", `no ring JWK for kid ${kid}`);

  const role = jwk.flycockpit_role;
  if (usage === "import") {
    if (role !== "current") {
      fail("jwks", `import requires the current key; the ${role} role cannot import`);
    }
  } else if (role === "next") {
    fail("jwks", "the next role never verifies imported policy");
  }

  if (parsed.signature.length !== 64) {
    fail(
      "jws",
      `policy JWS signature must be 64-byte raw r||s; got ${parsed.signature.length} bytes`,
    );
  }
  const r = parsed.signature.slice(0, 32);
  const s = parsed.signature.slice(32, 64);
  if (r.every((b) => b === 0) || s.every((b) => b === 0)) {
    fail("jws", "policy JWS signature scalar r or s is zero");
  }
  const sBig = bigIntFromBytes(s);
  if (sBig > P256_HALF_N) fail("jws", "policy JWS signature is high-S; only low-S is accepted");
  const rBig = bigIntFromBytes(r);
  if (rBig >= P256_N || sBig >= P256_N) fail("jws", "policy JWS signature scalar out of range");

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    fail("jwks", "JWK coordinates are not a valid P-256 point");
  }

  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new Uint8Array(parsed.signature),
    new Uint8Array(parsed.signingInput),
  );
  if (!ok) fail("jws", "policy JWS signature verification failed");
  return parsed;
}

// ---------------------------------------------------------------------------
// Baseline + state vocabulary
// ---------------------------------------------------------------------------

export const INITIAL_SERVICE_VERSION = 1n;

/** The sole initial service version 1 connection policy baseline. */
export function initialServiceVersion1Policy(): RemoteConnectionPolicyV1 {
  return {
    allowedTransports: ["webrtc", "websocket_data"],
    directIpMode: "mutual_consent",
    sharedSessionRoute: "relay_only",
    websocketFallback: true,
    tenantAuthorization: "control_plane",
    minimumDaemonCustody: "os_protected",
    minimumClientCustody: "origin_protected",
    sharingEnabled: true,
    limits: {
      registeredDaemons: "10",
      concurrentAttachments: "5",
      concurrentChildrenPerAttachment: "3",
      concurrentParticipantsPerSession: "8",
      turnBytesPerAttachment: "10737418240",
      turnDurationSeconds: "28800",
      websocketBytesPerAttachment: "10737418240",
      websocketDurationSeconds: "28800",
    },
    allowedTurnRegions: [...ALLOWED_TURN_REGIONS],
    metadataRetentionDays: "30",
  };
}

export type PolicyRowState =
  | "scheduled"
  | "preparing"
  | "active_converging"
  | "active"
  | "active_convergence_failed"
  | "scheduled_failed";
export const POLICY_ROW_STATES: readonly PolicyRowState[] = [
  "scheduled",
  "preparing",
  "active_converging",
  "active",
  "active_convergence_failed",
  "scheduled_failed",
];

export type ConsumerGroupState = "disabled" | "required" | "draining" | "retired";
export const CONSUMER_GROUP_STATES: readonly ConsumerGroupState[] = [
  "disabled",
  "required",
  "draining",
  "retired",
];

export type ReplicaLeaseState = "starting" | "ready" | "draining" | "stale";
export const REPLICA_LEASE_STATES: readonly ReplicaLeaseState[] = [
  "starting",
  "ready",
  "draining",
  "stale",
];

/** Command acknowledgement for a successful import (decimal-string u64s). */
export interface ImportAcknowledgement {
  policyId: string;
  serviceVersion: string;
  state: PolicyRowState;
  notBefore: string;
  digest: string;
}

// ---------------------------------------------------------------------------
// Branded RemotePublicPolicyId (codec reuse only; NOT a protocol-id kind)
// ---------------------------------------------------------------------------

declare const PUBLIC_POLICY_ID_BRAND: unique symbol;
/**
 * Nominal brand over the shared 16-byte / 22-char base64url identifier codec.
 * Deliberately NOT a member of `RemoteProtocolIdKind` / `REMOTE_PROTOCOL_ID_KINDS`
 * and NOT a control-plane allocation kind: policy ids are content/immutable row
 * ids, not mapping-table allocations. Codec reuse ≠ mapping-kind membership.
 */
export type RemotePublicPolicyId = Uint8Array & {
  readonly [PUBLIC_POLICY_ID_BRAND]: "public_policy";
};

export function tagPublicPolicyId(bytes: Uint8Array): RemotePublicPolicyId {
  if (bytes.length !== 16 || bytes.every((b) => b === 0)) {
    fail("invalid", "invalid public policy id bytes");
  }
  return new Uint8Array(bytes) as RemotePublicPolicyId;
}

export function encodePublicPolicyId(id: RemotePublicPolicyId): string {
  return encodeProtocolIdBase64Url(id);
}

export function decodePublicPolicyId(text: string): RemotePublicPolicyId {
  return tagPublicPolicyId(decodeProtocolIdBase64Url(text));
}
