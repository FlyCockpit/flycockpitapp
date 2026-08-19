/** Closed portable passkey administration formats. All integers are big-endian. */
import type { RemoteProtocolIdBytes } from "./remote-protocol-id";

export const REMOTE_CREDENTIAL_REGISTRY_MAGIC = "FCWR";
export const REMOTE_ADMIN_APPROVAL_MAGIC = "FCWA";
export const REMOTE_CREDENTIAL_REGISTRY_MAX_BYTES = 131_072;
export const REMOTE_ADMIN_APPROVAL_MAX_BYTES = 16_384;

export type RemoteAdminCredentialRole = 1 | 2;
export type RemoteAdminCustody = 1 | 2 | 3;
export type RemoteAdminCredentialState = 1 | 2;
export type RemoteAdminOperation = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11;
export const RemoteAdminOperationV1 = {
  enterpriseEnrollment: 1,
  highAssuranceDeviceEnrollment: 2,
  daemonEnrollment: 3,
  remotePolicyRevision: 4,
  authorityActivation: 5,
  signerReplacement: 6,
  recovery: 7,
  securityRoleGovernance: 8,
  credentialRegistryGovernance: 9,
  // Aligned with the tenant-authority signer table (discriminants 10 and 11)
  // so an FCWA can encode an identity-revocation approval.
  tenantIdentityRevocationStatus: 10,
  identityRevocation: 11,
} as const satisfies Record<string, RemoteAdminOperation>;

export function remoteAdminOperationRequiresDualControl(operation: RemoteAdminOperation) {
  return operation >= RemoteAdminOperationV1.authorityActivation;
}

export type RemoteCredentialRegistryEntryV1 = {
  principalId: RemoteProtocolIdBytes<"account">;
  role: RemoteAdminCredentialRole;
  credentialIdHash: Uint8Array;
  coseAlg: -7;
  p256X: Uint8Array;
  p256Y: Uint8Array;
  declaredCustody: RemoteAdminCustody;
  state: RemoteAdminCredentialState;
  createdAt: bigint;
  revokedAt: bigint | null;
};
export type RemoteCredentialRegistryV1 = {
  tenantId: RemoteProtocolIdBytes<"tenant">;
  registryGeneration: bigint;
  rpId: string;
  origin: string;
  entries: RemoteCredentialRegistryEntryV1[];
};
export type RemoteAdminApprovalEvidenceV1 = {
  tenantId: RemoteProtocolIdBytes<"tenant">;
  principalId: RemoteProtocolIdBytes<"account">;
  role: RemoteAdminCredentialRole;
  registryGeneration: bigint;
  credentialIdHash: Uint8Array;
  operation: RemoteAdminOperation;
  canonicalRequestDigest: Uint8Array;
  operationEpoch: bigint;
  issuedAt: bigint;
  expiresAt: bigint;
  challengeId: Uint8Array;
  challengeHash: Uint8Array;
  rpId: string;
  origin: string;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  coseAlg: -7;
  signatureP1363: Uint8Array;
};

const utf8 = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const base64url = (bytes: Uint8Array) => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += alphabet.charAt((n >>> 18) & 63) + alphabet.charAt((n >>> 12) & 63);
    if (i + 1 < bytes.length) out += alphabet.charAt((n >>> 6) & 63);
    if (i + 2 < bytes.length) out += alphabet.charAt(n & 63);
  }
  return out;
};
const concat = (...parts: Uint8Array[]) => {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};
const fixed = (value: Uint8Array, length: number, name: string) => {
  if (value.length !== length) throw new Error(`${name}_length`);
  return value;
};
const u8 = (value: number) => Uint8Array.of(value);
const i16 = (value: number) => {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setInt16(0, value);
  return b;
};
const u16 = (value: number) => {
  if (!Number.isInteger(value) || value < 0 || value > 65_535) throw new Error("u16_range");
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, value);
  return b;
};
const i64 = (value: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, value);
  return b;
};
const u64 = (value: bigint) => {
  if (value < 0n || value > 18_446_744_073_709_551_615n) throw new Error("u64_range");
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, value);
  return b;
};
function validatedRpOrigin(rpId: string, origin: string): [Uint8Array, Uint8Array] {
  const labels = rpId.split(".");
  if (
    rpId.length < 1 ||
    rpId.length > 253 ||
    labels.some(
      (label) =>
        label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  )
    throw new Error("rp_id_invalid");
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error("origin_invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== origin ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    (parsed.hostname !== rpId && !parsed.hostname.endsWith(`.${rpId}`))
  )
    throw new Error("origin_invalid");
  const rp = utf8.encode(rpId);
  const originBytes = utf8.encode(origin);
  if (originBytes.length > 512) throw new Error("origin_too_long");
  return [rp, originBytes];
}
function entryKey(entry: RemoteCredentialRegistryEntryV1) {
  return concat(entry.principalId, entry.credentialIdHash);
}
function compareUnsigned(a: Uint8Array, b: Uint8Array) {
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  }
  return a.length - b.length;
}

export function encodeRemoteCredentialRegistryV1(value: RemoteCredentialRegistryV1): Uint8Array {
  fixed(value.tenantId, 16, "tenant_id");
  const [rp, origin] = validatedRpOrigin(value.rpId, value.origin);
  if (value.entries.length < 1 || value.entries.length > 1024) throw new Error("entry_count");
  for (let i = 1; i < value.entries.length; i++) {
    const order = compareUnsigned(entryKey(value.entries[i - 1]!), entryKey(value.entries[i]!));
    if (order === 0) throw new Error("duplicate_entry");
    if (order > 0) throw new Error("entries_unsorted");
  }
  const entries = value.entries.map((entry) => {
    fixed(entry.principalId, 16, "principal_id");
    fixed(entry.credentialIdHash, 32, "credential_id_hash");
    fixed(entry.p256X, 32, "p256_x");
    fixed(entry.p256Y, 32, "p256_y");
    if (
      ![1, 2].includes(entry.role) ||
      ![1, 2, 3].includes(entry.declaredCustody) ||
      ![1, 2].includes(entry.state)
    )
      throw new Error("entry_discriminant");
    if ((entry.state === 1) !== (entry.revokedAt === null))
      throw new Error("credential_state_timestamp_mismatch");
    return concat(
      entry.principalId,
      u8(entry.role),
      entry.credentialIdHash,
      i16(entry.coseAlg),
      entry.p256X,
      entry.p256Y,
      u8(entry.declaredCustody),
      u8(entry.state),
      i64(entry.createdAt),
      u8(entry.revokedAt === null ? 0 : 1),
      ...(entry.revokedAt === null ? [] : [i64(entry.revokedAt)]),
    );
  });
  const result = concat(
    utf8.encode(REMOTE_CREDENTIAL_REGISTRY_MAGIC),
    u8(1),
    value.tenantId,
    u64(value.registryGeneration),
    u16(rp.length),
    rp,
    u16(origin.length),
    origin,
    u16(entries.length),
    ...entries,
  );
  if (result.length > REMOTE_CREDENTIAL_REGISTRY_MAX_BYTES) throw new Error("registry_too_large");
  return result;
}

export async function digestRemoteCredentialRegistryV1(value: RemoteCredentialRegistryV1) {
  const encoded = encodeRemoteCredentialRegistryV1(value);
  const owned = new Uint8Array(encoded.length);
  owned.set(encoded);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", owned));
}

class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  take(length: number) {
    if (length < 0 || this.offset + length > this.bytes.length) throw new Error("truncated");
    const v = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return v;
  }
  byte() {
    return this.take(1)[0]!;
  }
  uint16() {
    return new DataView(this.take(2).buffer).getUint16(0);
  }
  int16() {
    return new DataView(this.take(2).buffer).getInt16(0);
  }
  uint64() {
    return new DataView(this.take(8).buffer).getBigUint64(0);
  }
  int64() {
    return new DataView(this.take(8).buffer).getBigInt64(0);
  }
  done() {
    if (this.offset !== this.bytes.length) throw new Error("trailing_bytes");
  }
}

export function decodeRemoteCredentialRegistryV1(
  bytes: Uint8Array,
  validateP256Point: (x: Uint8Array, y: Uint8Array) => boolean,
): RemoteCredentialRegistryV1 {
  if (bytes.length > REMOTE_CREDENTIAL_REGISTRY_MAX_BYTES) throw new Error("registry_too_large");
  const r = new Reader(bytes);
  if (decoder.decode(r.take(4)) !== REMOTE_CREDENTIAL_REGISTRY_MAGIC || r.byte() !== 1)
    throw new Error("registry_header");
  const tenantId = r.take(16),
    registryGeneration = r.uint64();
  const rpId = decoder.decode(r.take(r.uint16())),
    origin = decoder.decode(r.take(r.uint16()));
  validatedRpOrigin(rpId, origin);
  const count = r.uint16();
  if (count < 1 || count > 1024) throw new Error("entry_count");
  const entries: RemoteCredentialRegistryEntryV1[] = [];
  for (let i = 0; i < count; i++) {
    const principalId = r.take(16),
      role = r.byte(),
      credentialIdHash = r.take(32),
      coseAlg = r.int16();
    const p256X = r.take(32),
      p256Y = r.take(32),
      declaredCustody = r.byte(),
      state = r.byte(),
      createdAt = r.int64();
    const present = r.byte();
    if (present !== 0 && present !== 1) throw new Error("revoked_at_presence");
    if (
      (role !== 1 && role !== 2) ||
      coseAlg !== -7 ||
      ![1, 2, 3].includes(declaredCustody) ||
      (state !== 1 && state !== 2)
    )
      throw new Error("entry_discriminant");
    if (!validateP256Point(p256X, p256Y)) throw new Error("p256_point_invalid");
    const revokedAt = present ? r.int64() : null;
    if ((state === 1) !== (revokedAt === null))
      throw new Error("credential_state_timestamp_mismatch");
    entries.push({
      principalId: principalId as RemoteProtocolIdBytes<"account">,
      role,
      credentialIdHash,
      coseAlg,
      p256X,
      p256Y,
      declaredCustody: declaredCustody as RemoteAdminCustody,
      state,
      createdAt,
      revokedAt,
    });
  }
  r.done();
  for (let i = 1; i < entries.length; i++)
    if (compareUnsigned(entryKey(entries[i - 1]!), entryKey(entries[i]!)) >= 0)
      throw new Error("entries_unsorted_or_duplicate");
  return {
    tenantId: tenantId as RemoteProtocolIdBytes<"tenant">,
    registryGeneration,
    rpId,
    origin,
    entries,
  };
}

/** WebCrypto rejects coordinates that do not identify a point on P-256. */
export async function validateRemoteAdminP256Point(x: Uint8Array, y: Uint8Array): Promise<boolean> {
  if (x.length !== 32 || y.length !== 32) return false;
  try {
    await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: base64url(x), y: base64url(y), ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return true;
  } catch {
    return false;
  }
}

export async function decodeRemoteCredentialRegistryStrictV1(bytes: Uint8Array) {
  const candidate = decodeRemoteCredentialRegistryV1(bytes, () => true);
  for (const entry of candidate.entries) {
    if (!(await validateRemoteAdminP256Point(entry.p256X, entry.p256Y)))
      throw new Error("p256_point_invalid");
  }
  return candidate;
}

export function encodeRemoteAdminApprovalEvidenceV1(
  value: RemoteAdminApprovalEvidenceV1,
): Uint8Array {
  fixed(value.tenantId, 16, "tenant_id");
  fixed(value.principalId, 16, "principal_id");
  fixed(value.credentialIdHash, 32, "credential_id_hash");
  fixed(value.canonicalRequestDigest, 32, "request_digest");
  fixed(value.challengeId, 16, "challenge_id");
  fixed(value.challengeHash, 32, "challenge_hash");
  fixed(value.signatureP1363, 64, "signature");
  if (
    ![1, 2].includes(value.role) ||
    value.operation < 1 ||
    value.operation > 11 ||
    value.coseAlg !== -7
  )
    throw new Error("approval_discriminant");
  if (value.authenticatorData.length < 37 || value.authenticatorData.length > 1024)
    throw new Error("authenticator_data_length");
  if (value.clientDataJson.length < 1 || value.clientDataJson.length > 4096)
    throw new Error("client_data_length");
  decoder.decode(value.clientDataJson);
  const [rp, origin] = validatedRpOrigin(value.rpId, value.origin);
  const result = concat(
    utf8.encode(REMOTE_ADMIN_APPROVAL_MAGIC),
    u8(1),
    value.tenantId,
    value.principalId,
    u8(value.role),
    u64(value.registryGeneration),
    value.credentialIdHash,
    u8(value.operation),
    value.canonicalRequestDigest,
    u64(value.operationEpoch),
    i64(value.issuedAt),
    i64(value.expiresAt),
    value.challengeId,
    value.challengeHash,
    u16(rp.length),
    rp,
    u16(origin.length),
    origin,
    u16(value.authenticatorData.length),
    value.authenticatorData,
    u16(value.clientDataJson.length),
    value.clientDataJson,
    i16(-7),
    value.signatureP1363,
  );
  if (result.length > REMOTE_ADMIN_APPROVAL_MAX_BYTES) throw new Error("approval_too_large");
  return result;
}

export function decodeRemoteAdminApprovalEvidenceV1(
  bytes: Uint8Array,
): RemoteAdminApprovalEvidenceV1 {
  if (bytes.length > REMOTE_ADMIN_APPROVAL_MAX_BYTES) throw new Error("approval_too_large");
  const r = new Reader(bytes);
  if (decoder.decode(r.take(4)) !== REMOTE_ADMIN_APPROVAL_MAGIC || r.byte() !== 1)
    throw new Error("approval_header");
  const tenantId = r.take(16),
    principalId = r.take(16),
    role = r.byte(),
    registryGeneration = r.uint64(),
    credentialIdHash = r.take(32),
    operation = r.byte(),
    canonicalRequestDigest = r.take(32),
    operationEpoch = r.uint64(),
    issuedAt = r.int64(),
    expiresAt = r.int64(),
    challengeId = r.take(16),
    challengeHash = r.take(32);
  const rpId = decoder.decode(r.take(r.uint16())),
    origin = decoder.decode(r.take(r.uint16()));
  validatedRpOrigin(rpId, origin);
  const authenticatorData = r.take(r.uint16()),
    clientDataJson = r.take(r.uint16()),
    coseAlg = r.int16(),
    signatureP1363 = r.take(64);
  r.done();
  if ((role !== 1 && role !== 2) || operation < 1 || operation > 11 || coseAlg !== -7)
    throw new Error("approval_discriminant");
  if (
    authenticatorData.length < 37 ||
    authenticatorData.length > 1024 ||
    clientDataJson.length < 1 ||
    clientDataJson.length > 4096
  )
    throw new Error("approval_field_length");
  decoder.decode(clientDataJson);
  return {
    tenantId: tenantId as RemoteProtocolIdBytes<"tenant">,
    principalId: principalId as RemoteProtocolIdBytes<"account">,
    role,
    registryGeneration,
    credentialIdHash,
    operation: operation as RemoteAdminOperation,
    canonicalRequestDigest,
    operationEpoch,
    issuedAt,
    expiresAt,
    challengeId,
    challengeHash,
    rpId,
    origin,
    authenticatorData,
    clientDataJson,
    coseAlg,
    signatureP1363,
  };
}
