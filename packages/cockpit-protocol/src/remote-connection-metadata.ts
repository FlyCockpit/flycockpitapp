/**
 * Privacy-minimal remote connection metadata retention — closed v1 buckets,
 * pseudonym schemas, and classification guard.
 *
 * @see prompts/flycockpitapp/ready/remote-connection-metadata-retention.md
 *
 * This module defines the closed enums, bucket boundary functions, pseudonym
 * framing schemas, and the forbidden-field classification guard for the
 * pseudonymous connection-metadata ledger. It does NOT persist any raw IP,
 * candidate, SDP, credential, key body, content, or transcript.
 */
import fixture from "../fixtures/remote/connection-metadata-v1.json";

// ---------------------------------------------------------------------------
// Closed v1 enums — colocated with cross-language fixtures.
// ---------------------------------------------------------------------------

export const RemoteMetadataServiceTier = {
  public_saas: 1,
  enterprise: 2,
} as const;
export type RemoteMetadataServiceTierV1 = 1 | 2;

export const RemoteMetadataTransport = {
  webrtc: 1,
  websocket_data: 2,
} as const;
export type RemoteMetadataTransportV1 = 1 | 2;

export const RemoteMetadataRouteClass = {
  direct: 1,
  turn: 2,
  websocket_gateway: 3,
} as const;
export type RemoteMetadataRouteClassV1 = 1 | 2 | 3;

export const RemoteMetadataOutcome = {
  connected: 1,
  rejected: 2,
  cancelled: 3,
  superseded: 4,
  failed: 5,
  revoked: 6,
  expired: 7,
} as const;
export type RemoteMetadataOutcomeV1 = 1 | 2 | 3 | 4 | 5 | 6 | 7;

export const RemoteMetadataReason = {
  none: 0,
  policy: 1,
  authentication: 2,
  authorization: 3,
  dependency: 4,
  network: 5,
  quota: 6,
  protocol: 7,
  user: 8,
  revocation: 9,
  timeout: 10,
  internal: 11,
} as const;
export type RemoteMetadataReasonV1 = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11;

export const RemoteMetadataCustodyClass = {
  origin_protected: 1,
  os_protected: 2,
  hardware_or_external: 3,
} as const;
export type RemoteMetadataCustodyClassV1 = 1 | 2 | 3;

export const RemoteMetadataRegion = {
  unknown: 0,
  local: 1,
  north_america: 2,
  south_america: 3,
  europe: 4,
  africa: 5,
  middle_east: 6,
  asia_pacific: 7,
  oceania: 8,
} as const;
export type RemoteMetadataRegionV1 = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;

export const RemoteMetadataDurationBucket = {
  lt_5s: 1,
  "5s_lt_30s": 2,
  "30s_lt_2m": 3,
  "2m_lt_10m": 4,
  "10m_lt_1h": 5,
  gte_1h: 6,
} as const;
export type RemoteMetadataDurationBucketV1 = 1 | 2 | 3 | 4 | 5 | 6;

export const RemoteMetadataBytesBucket = {
  zero: 0,
  "1b_lt_64kib": 1,
  "64kib_lt_1mib": 2,
  "1mib_lt_16mib": 3,
  "16mib_lt_256mib": 4,
  "256kib_lt_1gib": 5,
  gte_1gib: 6,
} as const;
export type RemoteMetadataBytesBucketV1 = 0 | 1 | 2 | 3 | 4 | 5 | 6;

// ---------------------------------------------------------------------------
// Retention bounds.
// ---------------------------------------------------------------------------

export const REMOTE_METADATA_DEFAULT_RETENTION_DAYS = 30;
export const REMOTE_METADATA_MIN_RETENTION_DAYS = 0;
export const REMOTE_METADATA_MAX_RETENTION_DAYS = 365;

/**
 * Validates an enterprise retention-days policy. Returns the clamped integer
 * or throws on out-of-range. Zero suppresses row creation.
 */
export function validateMetadataRetentionDays(days: number): number {
  if (!Number.isInteger(days) || days < 0 || days > 365)
    throw new RemoteMetadataError("retention days must be integer 0..365");
  return days;
}

// ---------------------------------------------------------------------------
// Bucket boundary functions — exact closed v1 boundaries.
// ---------------------------------------------------------------------------

/**
 * `timeBucket` is the Unix epoch of the containing UTC hour
 * (`floor(epochSeconds/3600)*3600`).
 */
export function remoteMetadataTimeBucket(epochSeconds: number): number {
  if (!Number.isInteger(epochSeconds) || epochSeconds < 0)
    throw new RemoteMetadataError("epochSeconds must be a nonnegative integer");
  return Math.floor(epochSeconds / 3600) * 3600;
}

/**
 * Duration bucket: `lt_5s | 5s_lt_30s | 30s_lt_2m | 2m_lt_10m | 10m_lt_1h | gte_1h`.
 * Lower bounds are inclusive, upper bounds exclusive.
 */
export function remoteMetadataDurationBucket(
  durationSeconds: number,
): RemoteMetadataDurationBucketV1 {
  if (!Number.isInteger(durationSeconds) || durationSeconds < 0)
    throw new RemoteMetadataError("durationSeconds must be a nonnegative integer");
  if (durationSeconds < 5) return 1;
  if (durationSeconds < 30) return 2;
  if (durationSeconds < 120) return 3;
  if (durationSeconds < 600) return 4;
  if (durationSeconds < 3600) return 5;
  return 6;
}

/**
 * Each directional byte total is `zero | 1b_lt_64kib | 64kib_lt_1mib |
 * 1mib_lt_16mib | 16mib_lt_256mib | 256kib_lt_1gib | gte_1gib`.
 * Lower bounds are inclusive, upper bounds exclusive.
 */
export function remoteMetadataBytesBucket(bytes: number): RemoteMetadataBytesBucketV1 {
  if (!Number.isInteger(bytes) || bytes < 0 || !Number.isSafeInteger(bytes))
    throw new RemoteMetadataError("bytes must be a nonnegative safe integer");
  if (bytes === 0) return 0;
  if (bytes < 65536) return 1;
  if (bytes < 1048576) return 2;
  if (bytes < 16777216) return 3;
  if (bytes < 268435456) return 4;
  if (bytes < 1073741824) return 5;
  return 6;
}

/**
 * Aggregate cell tuple — canonical fixed-width 7-discriminant tuple:
 * `tier:u8 | region:u8 | routeClass:u8 | outcome:u8 | ingressBytesBucket:u8 |
 *  egressBytesBucket:u8 | durationBucket:u8`.
 */
export function remoteMetadataCellTuple(input: {
  serviceTier: RemoteMetadataServiceTierV1;
  region: RemoteMetadataRegionV1;
  routeClass: RemoteMetadataRouteClassV1;
  outcome: RemoteMetadataOutcomeV1;
  ingressBytesBucket: RemoteMetadataBytesBucketV1;
  egressBytesBucket: RemoteMetadataBytesBucketV1;
  durationBucket: RemoteMetadataDurationBucketV1;
}): Uint8Array {
  return Uint8Array.from([
    input.serviceTier,
    input.region,
    input.routeClass,
    input.outcome,
    input.ingressBytesBucket,
    input.egressBytesBucket,
    input.durationBucket,
  ]);
}

// ---------------------------------------------------------------------------
// Pseudonym schemas — five literal and exhaustive domains.
// ---------------------------------------------------------------------------

export const RemoteMetadataPseudonymComponentKind = {
  tenant_id: 1,
  account_id: 2,
  device_id: 3,
  instance_id: 4,
  attempt_id: 5,
} as const;

export const REMOTE_METADATA_PSEUDONYM_DOMAINS = {
  tenant: "flycockpit.remote.metadata.tenant.v1",
  account: "flycockpit.remote.metadata.account.v1",
  device: "flycockpit.remote.metadata.device.v1",
  instance: "flycockpit.remote.metadata.instance.v1",
  attempt: "flycockpit.remote.metadata.attempt.v1",
} as const;

const SCHEMA_REQUIRED_KIND: Record<string, number> = {
  [REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant]: 1,
  [REMOTE_METADATA_PSEUDONYM_DOMAINS.account]: 2,
  [REMOTE_METADATA_PSEUDONYM_DOMAINS.device]: 3,
  [REMOTE_METADATA_PSEUDONYM_DOMAINS.instance]: 4,
  [REMOTE_METADATA_PSEUDONYM_DOMAINS.attempt]: 5,
};

export interface RemoteMetadataPseudonymComponent {
  kind: number;
  bytes: Uint8Array;
}

/**
 * Rejection codes for pseudonym-message construction and decode. For the
 * fixture's malformed vectors these equal the fixture `rejection` strings
 * exactly; `invalid_component_bytes`/`truncated` cover non-fixture failures.
 */
export type RemoteMetadataErrorCode =
  | "unknown_domain"
  | "zero_components"
  | "multiple_components"
  | "domain_component_mismatch"
  | "invalid_component_bytes"
  | "trailing_byte"
  | "truncated";

export class RemoteMetadataError extends Error {
  /**
   * Present on construction/decode rejections; equals the fixture `rejection`
   * string for malformed vectors. Undefined for other validation errors
   * (retention, bucket, digest, pseudonym length).
   */
  readonly code?: RemoteMetadataErrorCode;
  constructor(message: string, code?: RemoteMetadataErrorCode) {
    super(message);
    this.name = "RemoteMetadataError";
    this.code = code;
  }
}

// Descriptive `Error.message` for each rejection code. These preserve the
// original human-readable messages (callers may branch on/report `.message`)
// while the machine-readable wire code is passed via the 2nd constructor arg.
const REMOTE_METADATA_REJECTION_MESSAGES: Record<RemoteMetadataErrorCode, string> = {
  unknown_domain: "unknown pseudonym domain",
  zero_components: "exactly one component required",
  multiple_components: "exactly one component required",
  domain_component_mismatch: "domain-component kind mismatch",
  invalid_component_bytes: "component bytes must be nonzero 16 bytes",
  trailing_byte: "trailing bytes after message",
  truncated: "truncated pseudonym message",
};

function rejectMetadata(code: RemoteMetadataErrorCode): RemoteMetadataError {
  return new RemoteMetadataError(REMOTE_METADATA_REJECTION_MESSAGES[code], code);
}

const te = new TextEncoder();

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Runtime shape check for a pseudonym component at the public API boundary: a
 * sparse array element, `null`, or a wrong-typed field must fail closed with a
 * stable `invalid_component_bytes` code rather than a raw `TypeError`.
 */
function isPseudonymComponent(c: unknown): c is RemoteMetadataPseudonymComponent {
  return (
    typeof c === "object" &&
    c !== null &&
    typeof (c as { kind?: unknown }).kind === "number" &&
    (c as { bytes?: unknown }).bytes instanceof Uint8Array
  );
}

/**
 * Builds the canonical HMAC message for a pseudonym schema:
 * `domainUtf8 | 0x00 | componentCount:u8 | components`.
 * Each component is `kind:u8 | length:u16be | bytes`.
 */
export function remoteMetadataPseudonymMessage(
  domain: string,
  components: RemoteMetadataPseudonymComponent[],
): Uint8Array {
  // Fail closed on a null/undefined/non-array container before touching
  // `.length`, so a malformed call at the public boundary yields a stable
  // RemoteMetadataError code instead of a raw TypeError.
  if (!Array.isArray(components)) throw rejectMetadata("invalid_component_bytes");
  // Own-property lookup only: a prototype name like "toString" must be an
  // unknown domain (parity with Rust), not an inherited function that slips
  // past an `=== undefined` check into later kind/framing classification.
  if (!Object.hasOwn(SCHEMA_REQUIRED_KIND, domain)) throw rejectMetadata("unknown_domain");
  const requiredKind = SCHEMA_REQUIRED_KIND[domain]!;
  if (components.length === 0) throw rejectMetadata("zero_components");
  if (components.length > 1) throw rejectMetadata("multiple_components");
  const c = components[0];
  if (!isPseudonymComponent(c)) throw rejectMetadata("invalid_component_bytes");
  if (c.kind !== requiredKind) throw rejectMetadata("domain_component_mismatch");
  if (c.bytes.length !== 16 || c.bytes.every((b) => b === 0))
    throw rejectMetadata("invalid_component_bytes");
  const domainUtf8 = te.encode(domain);
  const comp = new Uint8Array(3 + 16);
  comp[0] = c.kind;
  new DataView(comp.buffer).setUint16(1, 16);
  comp.set(c.bytes, 3);
  return concat(domainUtf8, Uint8Array.of(0x00), Uint8Array.of(1), comp);
}

/**
 * Decodes a canonical pseudonym message
 * (`domainUtf8 | 0x00 | componentCount:u8 | kind:u8 | length:u16be | bytes`)
 * back into its domain and single component. This is the verify path that ties
 * every malformed fixture vector to a real rejection. Checks are ordered to
 * match construction: unknown domain, then component count, then a fully-parsed
 * single component, then an exact-length check (a trailing byte fails), then
 * the kind/domain match, then the nonzero-bytes rule.
 */
export function remoteMetadataDecodePseudonymMessage(bytes: Uint8Array): {
  domain: string;
  components: RemoteMetadataPseudonymComponent[];
} {
  // Fail closed on a null/undefined/non-Uint8Array input before touching
  // `.indexOf`, so a malformed call at the public boundary yields a stable
  // RemoteMetadataError code instead of a raw TypeError (parity with the
  // construct boundary's Array.isArray guard).
  if (!(bytes instanceof Uint8Array)) throw rejectMetadata("invalid_component_bytes");
  // The domain is ASCII and never contains 0x00, so the first 0x00 is the
  // separator between the domain and the component count. A missing separator
  // is truncation; a leading 0x00 (empty domain segment) is an unknown domain,
  // matching Rust and the construction API (which treats "" as unknown).
  const sep = bytes.indexOf(0x00);
  if (sep === -1) throw rejectMetadata("truncated");
  if (sep === 0) throw rejectMetadata("unknown_domain");
  let domain: string;
  try {
    domain = new TextDecoder("utf-8", { fatal: true }).decode(bytes.slice(0, sep));
  } catch {
    throw rejectMetadata("unknown_domain");
  }
  // Own-property lookup only: a prototype name like "toString" must be an
  // unknown domain (parity with Rust), not an inherited function that slips
  // past an `=== undefined` check into later kind/framing classification.
  if (!Object.hasOwn(SCHEMA_REQUIRED_KIND, domain)) throw rejectMetadata("unknown_domain");
  const requiredKind = SCHEMA_REQUIRED_KIND[domain]!;

  let n = sep + 1;
  if (n >= bytes.length) throw rejectMetadata("truncated");
  const count = bytes[n]!;
  n += 1;
  // Reject zero/multiple from the declared count byte without parsing a second
  // component: a count of exactly one is the only valid shape.
  if (count === 0) throw rejectMetadata("zero_components");
  if (count > 1) throw rejectMetadata("multiple_components");

  if (n >= bytes.length) throw rejectMetadata("truncated");
  const kind = bytes[n]!;
  n += 1;
  if (n + 2 > bytes.length) throw rejectMetadata("truncated");
  const length = (bytes[n]! << 8) | bytes[n + 1]!;
  n += 2;
  if (length !== 16) throw rejectMetadata("invalid_component_bytes");
  if (n + 16 > bytes.length) throw rejectMetadata("truncated");
  const componentBytes = bytes.slice(n, n + 16);
  n += 16;

  // Exact length: any leftover byte after the single component fails. A count
  // of one followed by extra bytes is a trailing byte, not a count error.
  if (n !== bytes.length) throw rejectMetadata("trailing_byte");
  if (kind !== requiredKind) throw rejectMetadata("domain_component_mismatch");
  if (componentBytes.every((b) => b === 0)) throw rejectMetadata("invalid_component_bytes");

  return { domain, components: [{ kind, bytes: componentBytes }] };
}

/**
 * Pseudonym is the first 16 bytes of HMAC-SHA-256. This function takes a
 * pre-computed HMAC digest and returns the 16-byte pseudonym.
 */
export function remoteMetadataPseudonymFromDigest(digest: Uint8Array): Uint8Array {
  if (digest.length !== 32) throw new RemoteMetadataError("digest must be 32 bytes");
  return digest.slice(0, 16);
}

export function remoteMetadataPseudonymToHex(pseudonym: Uint8Array): string {
  if (pseudonym.length !== 16) throw new RemoteMetadataError("pseudonym must be 16 bytes");
  return Array.from(pseudonym, (b) => b.toString(16).padStart(2, "0")).join("");
}

// Distinct non-interchangeable pseudonym schema types.
export type TenantMetadataPseudonymV1 = Uint8Array & { readonly _tenantPseudonym: true };
export type AccountMetadataPseudonymV1 = Uint8Array & { readonly _accountPseudonym: true };
export type DeviceMetadataPseudonymV1 = Uint8Array & { readonly _devicePseudonym: true };
export type InstanceMetadataPseudonymV1 = Uint8Array & { readonly _instancePseudonym: true };
export type AttemptMetadataPseudonymV1 = Uint8Array & { readonly _attemptPseudonym: true };

// ---------------------------------------------------------------------------
// Classification guard — forbidden-field corpus.
// ---------------------------------------------------------------------------

export const REMOTE_METADATA_FORBIDDEN_FIELDS = fixture.forbiddenFields as readonly string[];
export const REMOTE_METADATA_ALLOWED_ROW_FIELDS = fixture.allowedRowFields as readonly string[];

export function isAllowedMetadataRowField(field: string): boolean {
  return (REMOTE_METADATA_ALLOWED_ROW_FIELDS as readonly string[]).includes(field);
}

export function isForbiddenMetadataField(field: string): boolean {
  return (REMOTE_METADATA_FORBIDDEN_FIELDS as readonly string[]).some((f) =>
    field.toLowerCase().includes(f.toLowerCase()),
  );
}

// ---------------------------------------------------------------------------
// Key file root schema — strict JSON validation constants.
// ---------------------------------------------------------------------------

export interface RemoteMetadataPseudonymKeyFileRoot {
  schemaVersion: 1;
  currentVersion: number;
  keys: Array<{
    version: number;
    keyBase64url: string;
    state: "current" | "lookup_only";
  }>;
  cardinalityKeys: Array<{
    version: number;
    keyBase64url: string;
    state: "current" | "next";
    activatesAtUtcDay: number;
  }>;
}

export const REMOTE_METADATA_HKDF_SALT_DOMAIN = "flycockpit.remote.metadata.hkdf.salt.v1";
export const REMOTE_METADATA_TENANT_KEY_INFO_DOMAIN = "flycockpit.remote.metadata.tenant-key.v1";
export const REMOTE_METADATA_CARDINALITY_DOMAIN = "flycockpit.remote.metadata.cardinality.v1";

// ---------------------------------------------------------------------------
// Outcome seed — immutable version-pinned seed.
// ---------------------------------------------------------------------------

export interface RemoteMetadataOutcomeSeedV1 {
  outcomeWriteId: Uint8Array;
  keyVersion: number;
  tenantPseudonym: Uint8Array;
  accountPseudonym: Uint8Array;
  devicePseudonym: Uint8Array;
  instancePseudonym: Uint8Array;
  attemptPseudonym: Uint8Array;
  canonicalRowWithoutServerRowId: Uint8Array;
}

export interface RemoteConnectionMetadataRowV1 {
  schemaVersion: 1;
  rowId: Uint8Array;
  createdAt: number;
  timeBucket: number;
  keyVersion: number;
  tenantPseudonym: Uint8Array;
  accountPseudonym: Uint8Array;
  devicePseudonym: Uint8Array;
  instancePseudonym: Uint8Array;
  attemptPseudonym: Uint8Array;
  serviceTier: RemoteMetadataServiceTierV1;
  transport: RemoteMetadataTransportV1;
  routeClass: RemoteMetadataRouteClassV1;
  region: RemoteMetadataRegionV1;
  outcome: RemoteMetadataOutcomeV1;
  reason: RemoteMetadataReasonV1;
  policyEpoch: number;
  custodyClass: RemoteMetadataCustodyClassV1;
  durationBucket: RemoteMetadataDurationBucketV1;
  ingressBytesBucket: RemoteMetadataBytesBucketV1;
  egressBytesBucket: RemoteMetadataBytesBucketV1;
  policyRetentionDaysAtCreation: number;
  expiresAt: number;
}

export interface RemoteMetadataOutcomeTerminalReceiptV1 {
  outcomeWriteId: Uint8Array;
  result: "delivered" | "dropped";
  finishedAt: number;
  discardAfter: number;
}

// ---------------------------------------------------------------------------
// Aggregate row schemas — closed tagged union.
// ---------------------------------------------------------------------------

export interface RemoteMetadataExactAggregateRowV1 {
  schemaVersion: 1;
  utcDay: number;
  serviceTier: RemoteMetadataServiceTierV1;
  cellKind: "exact";
  region: RemoteMetadataRegionV1;
  routeClass: RemoteMetadataRouteClassV1;
  outcome: RemoteMetadataOutcomeV1;
  ingressBytesBucket: RemoteMetadataBytesBucketV1;
  egressBytesBucket: RemoteMetadataBytesBucketV1;
  durationBucket: RemoteMetadataDurationBucketV1;
  connectionCount: number;
}

export interface RemoteMetadataOtherAggregateRowV1 {
  schemaVersion: 1;
  utcDay: number;
  serviceTier: RemoteMetadataServiceTierV1;
  cellKind: "other";
  connectionCount: number;
  mergedCellCount: number;
}

export type RemoteMetadataAggregateRowV1 =
  | RemoteMetadataExactAggregateRowV1
  | RemoteMetadataOtherAggregateRowV1;

export const REMOTE_METADATA_SMALL_CELL_THRESHOLD = 20;
export const REMOTE_METADATA_CORRECTION_HORIZON_DAYS = 7;

/**
 * `correctionClosesAt = utcDay + 8 * 86_400` seconds.
 */
export function remoteMetadataCorrectionClosesAt(utcDay: number): number {
  return utcDay + 8 * 86_400;
}
