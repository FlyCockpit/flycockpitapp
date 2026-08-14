/**
 * Remote identity enrollment and lifecycle service — TypeScript protocol twin.
 *
 * This module mirrors the Rust protocol surface in
 * `crates/cockpit-proto/src/remote_device_identity_enrollment.rs` byte-for-byte:
 * the SAS-V1 shared-authentication-code derivation, the strict enrollment
 * discovery-link format/parse contract, the closed
 * enrollment/certificate-lifecycle/revocation state and terminal-reason enums,
 * and the strict JSON projection parsers this batch serves.
 *
 * It owns none of the foundation identity wire bytes: FCEN/FCCF/FCPP and the
 * other `remote_identity_protocol` codecs are imported from
 * `./remote-identity-protocol` (only `remoteIdentitySha256Sync` is reused, for
 * the SAS HKDF), never reimplemented here. It performs no network I/O and logs
 * no capabilities, SAS digits, or key material.
 */

import { z } from "zod";
import { remoteIdentitySha256Sync } from "./remote-identity-protocol";
import { canonicalU64DecimalStringSchema, decodeProtocolIdBase64Url } from "./remote-protocol-id";

const TE = new TextEncoder();

/** Typed failure for every enrollment protocol validation in this module. */
export class EnrollmentProtocolError extends Error {}
function fail(message: string): never {
  throw new EnrollmentProtocolError(message);
}

// ─────────────────────────────────────────────────────────────────────────
// SAS-V1 shared authentication code
// ─────────────────────────────────────────────────────────────────────────

/** HKDF prefix: `flycockpit-remote-enrollment-sas-v1` (UTF-8, no NUL). */
export const SAS_V1_PREFIX = "flycockpit-remote-enrollment-sas-v1";
/** Single NUL separator byte (`0x00`) used between HKDF label segments. */
export const SAS_V1_NUL = 0x00;
/** HKDF output length in bytes: 8160 = 1632 nonoverlapping five-byte blocks. */
export const SAS_V1_OKM_LEN = 8160;
/** Number of nonoverlapping five-byte blocks read before exhaustion is terminal. */
export const SAS_V1_BLOCK_COUNT = 1632;
/** Rejection threshold: 40-bit big-endian block values `>=` this are rejected. */
export const SAS_V1_REJECT_THRESHOLD = 1_090_000_000_000;
/** Modulus reducing the first accepted 40-bit block to ten decimal digits. */
export const SAS_V1_MODULUS = 10_000_000_000;
/** Displayed digit width (zero-padded): `12345 67890`. */
export const SAS_V1_DIGITS = 10;

/**
 * Committed salt digest (`SHA-256(salt preimage)`):
 * `5927e846e8ccc0210d666fa104e2aa7af9dcda3039ee97cae6b2978cc97b0508`.
 */
export const SAS_V1_SALT_DIGEST = Uint8Array.from([
  0x59, 0x27, 0xe8, 0x46, 0xe8, 0xcc, 0xc0, 0x21, 0x0d, 0x66, 0x6f, 0xa1, 0x04, 0xe2, 0xaa, 0x7a,
  0xf9, 0xdc, 0xda, 0x30, 0x39, 0xee, 0x97, 0xca, 0xe6, 0xb2, 0x97, 0x8c, 0xc9, 0x7b, 0x05, 0x08,
]);

/**
 * The two-byte sequence `\0` (ASCII backslash + `0`, hex `5c 30`) that MUST NOT
 * appear in a canonical SAS preimage — the separator is a literal NUL byte,
 * never its escaped form.
 */
export const SAS_V1_FORBIDDEN_ESCAPE = Uint8Array.from([0x5c, 0x30]);

/** Build the canonical SAS-V1 HKDF salt preimage: `prefix || NUL || "salt"`. */
export function sasV1SaltPreimage(): Uint8Array {
  const prefix = TE.encode(SAS_V1_PREFIX);
  const salt = TE.encode("salt");
  const buf = new Uint8Array(prefix.length + 1 + salt.length);
  buf.set(prefix, 0);
  buf[prefix.length] = SAS_V1_NUL;
  buf.set(salt, prefix.length + 1);
  assertSasPreimageInvariants(buf);
  return buf;
}

/**
 * Build the canonical SAS-V1 HKDF info preimage:
 * `prefix || NUL || "digits" || NUL || "v1"`.
 */
export function sasV1InfoPreimage(): Uint8Array {
  const prefix = TE.encode(SAS_V1_PREFIX);
  const digits = TE.encode("digits");
  const v1 = TE.encode("v1");
  const buf = new Uint8Array(prefix.length + 1 + digits.length + 1 + v1.length);
  let offset = 0;
  buf.set(prefix, offset);
  offset += prefix.length;
  buf[offset] = SAS_V1_NUL;
  offset += 1;
  buf.set(digits, offset);
  offset += digits.length;
  buf[offset] = SAS_V1_NUL;
  offset += 1;
  buf.set(v1, offset);
  assertSasPreimageInvariants(buf);
  return buf;
}

/**
 * Assert a SAS preimage contains no backslash (`0x5c`), no ASCII `0` (`0x30`),
 * and therefore no `\0` escape (`5c30`); the only permitted separator is a
 * literal NUL.
 */
function assertSasPreimageInvariants(bytes: Uint8Array): void {
  if (bytes.includes(0x5c)) fail("SAS preimage must not contain a backslash");
  if (bytes.includes(0x30)) fail("SAS preimage must not contain an ASCII '0' byte");
}

/**
 * Validate that a candidate preimage uses literal NUL separators and never the
 * `\0` escape (`5c30`), a backslash, or an ASCII `0` byte. Throws
 * {@link EnrollmentProtocolError} for a preimage where a `0x00` separator was
 * replaced by `5c30`.
 */
export function validateSasPreimage(bytes: Uint8Array): void {
  if (bytes.includes(0x5c) || bytes.includes(0x30)) fail("invalid sas preimage: forbidden byte");
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === SAS_V1_FORBIDDEN_ESCAPE[0] && bytes[i + 1] === SAS_V1_FORBIDDEN_ESCAPE[1]) {
      fail("invalid sas preimage: forbidden escape present");
    }
  }
}

/** HMAC-SHA256 over the reused foundation synchronous SHA-256. */
function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  const block = 64;
  let normalizedKey = key;
  if (normalizedKey.length > block) normalizedKey = remoteIdentitySha256Sync(normalizedKey);
  const padded = new Uint8Array(block);
  padded.set(normalizedKey);
  const inner = new Uint8Array(block);
  const outer = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    inner[i] = padded[i]! ^ 0x36;
    outer[i] = padded[i]! ^ 0x5c;
  }
  const innerMsg = new Uint8Array(block + message.length);
  innerMsg.set(inner, 0);
  innerMsg.set(message, block);
  const innerHash = remoteIdentitySha256Sync(innerMsg);
  const outerMsg = new Uint8Array(block + innerHash.length);
  outerMsg.set(outer, 0);
  outerMsg.set(innerHash, block);
  return remoteIdentitySha256Sync(outerMsg);
}

/** HKDF-Extract(salt, IKM) per RFC 5869 with SHA-256. */
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt, ikm);
}

/** HKDF-Expand(PRK, info, L) per RFC 5869 with SHA-256. */
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (length > 255 * 32) fail("HKDF-Expand length exceeds 255 * HashLen ceiling");
  const okm = new Uint8Array(length);
  let previous: Uint8Array = new Uint8Array(0);
  let counter = 1;
  let offset = 0;
  while (offset < length) {
    const message = new Uint8Array(previous.length + info.length + 1);
    message.set(previous, 0);
    message.set(info, previous.length);
    message[message.length - 1] = counter;
    previous = hmacSha256(prk, message);
    const take = Math.min(previous.length, length - offset);
    okm.set(previous.subarray(0, take), offset);
    offset += take;
    counter += 1;
  }
  return okm;
}

/**
 * Compute the complete SAS-V1 HKDF OKM (`L = 8160`) from a transcript digest.
 *
 * `transcriptDigest` is `SHA-256(the complete canonical FCEN bytes)`. The salt
 * and info preimages are the committed canonical bytes.
 */
export function sasV1Okm(transcriptDigest: Uint8Array): Uint8Array {
  if (transcriptDigest.length !== 32) fail("transcript digest must be 32 bytes");
  const salt = remoteIdentitySha256Sync(sasV1SaltPreimage());
  const prk = hkdfExtract(salt, transcriptDigest);
  return hkdfExpand(prk, sasV1InfoPreimage(), SAS_V1_OKM_LEN);
}

/** A derived SAS-V1 code. Superset of the `{ digits, display }` contract. */
export interface SasV1 {
  /** The accepted 40-bit big-endian block value, before modulus reduction. */
  acceptedBlock: number;
  /** Zero-based index of the accepted block within the 1632-block OKM. */
  acceptedIndex: number;
  /** The ten-digit zero-padded decimal string (`n mod 10_000_000_000`). */
  digits: string;
  /** The code displayed as `12345 67890` (five digits, space, five digits). */
  display: string;
}

/**
 * Derive the SAS-V1 code from a transcript digest by reading consecutive
 * nonoverlapping five-byte blocks as unsigned 40-bit big-endian integers,
 * rejecting values `>= 1_090_000_000_000`, and returning the first accepted
 * value reduced mod `10_000_000_000` zero-padded to ten digits.
 *
 * Exhausting all 1632 blocks without an accepted value throws
 * {@link EnrollmentProtocolError} (Rust `SasError::DerivationFailed`).
 */
export function deriveSasV1(transcriptDigest: Uint8Array): SasV1 {
  const okm = sasV1Okm(transcriptDigest);
  for (let index = 0; index < SAS_V1_BLOCK_COUNT; index++) {
    let value = 0;
    for (let byte = 0; byte < 5; byte++) {
      value = value * 256 + okm[index * 5 + byte]!;
    }
    if (value < SAS_V1_REJECT_THRESHOLD) {
      const reduced = value % SAS_V1_MODULUS;
      const digits = String(reduced).padStart(SAS_V1_DIGITS, "0");
      return {
        acceptedBlock: value,
        acceptedIndex: index,
        digits,
        display: `${digits.slice(0, 5)} ${digits.slice(5)}`,
      };
    }
  }
  return fail("sas derivation failed: no accepted block within 1632 five-byte blocks");
}

// ─────────────────────────────────────────────────────────────────────────
// Enrollment discovery links
// ─────────────────────────────────────────────────────────────────────────

/** Enrollment link protocol version query value. */
export const ENROLLMENT_LINK_VERSION = 1;
/** Length of the random enrollment ID: 16 bytes, base64url-22. */
export const ENROLLMENT_ID_LEN = 16;
/** Length of the random discovery capability: 32 bytes, base64url-43. */
export const DISCOVERY_CAPABILITY_LEN = 32;
/** Lowercase discovery path shared by both link kinds. */
export const ENROLLMENT_LINK_PATH = "/remote/enroll";

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function encodeBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64URL_ALPHABET[(n >> 18) & 63]! + B64URL_ALPHABET[(n >> 12) & 63]!;
    if (i + 1 < bytes.length) out += B64URL_ALPHABET[(n >> 6) & 63]!;
    if (i + 2 < bytes.length) out += B64URL_ALPHABET[n & 63]!;
  }
  return out;
}

/** Decode strict unpadded canonical base64url, requiring an exact byte length. */
function decodeBase64UrlFixed(value: string, length: number, field: string): Uint8Array {
  if (value.length === 0 || value.includes("=")) fail(`${field} must be unpadded base64url`);
  if (!/^[A-Za-z0-9_-]+$/.test(value)) fail(`${field} is not valid base64url`);
  const out: number[] = [];
  let bits = 0;
  let accumulator = 0;
  for (const char of value) {
    accumulator = (accumulator << 6) | B64URL_ALPHABET.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((accumulator >> bits) & 0xff);
    }
  }
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) {
    fail(`${field} is noncanonical base64url`);
  }
  const bytes = Uint8Array.from(out);
  if (encodeBase64Url(bytes) !== value) fail(`${field} is noncanonical base64url`);
  if (bytes.length !== length) fail(`${field} has wrong length`);
  return bytes;
}

/** A parsed single-use enrollment discovery link. */
export interface EnrollmentDiscoveryLink {
  /** Normalized HTTPS origin, or `""` for a deep link (which carries none). */
  publicOrigin: string;
  /** Random 16-byte enrollment ID. */
  enrollmentId: Uint8Array;
  /** Random 32-byte discovery capability. */
  discoveryCapability: Uint8Array;
}

/**
 * Validate a normalized HTTPS public origin (lowercase, no trailing slash, no
 * path/query/fragment, no `:443`). Ports Rust `validate_link_origin`.
 */
function validateLinkOrigin(originValue: string): void {
  if (!originValue.startsWith("https://")) {
    fail("origin must be a normalized HTTPS origin");
  }
  const authority = originValue.slice("https://".length);
  const authorityBytes = TE.encode(authority);
  const hasForbiddenByte = authorityBytes.some(
    (b) =>
      b === 0x20 ||
      b === 0x09 ||
      b === 0x0a ||
      b === 0x0c ||
      b === 0x0d ||
      (b >= 0x41 && b <= 0x5a),
  );
  if (
    TE.encode(originValue).length < 1 ||
    TE.encode(originValue).length > 255 ||
    authority.length === 0 ||
    hasForbiddenByte ||
    /[/?#@]/.test(authority) ||
    authority.endsWith(":443")
  ) {
    fail("origin must be a normalized HTTPS origin");
  }
  const colon = authority.indexOf(":");
  let host: string;
  if (colon === -1) {
    host = authority;
  } else {
    const hostPart = authority.slice(0, colon);
    const port = authority.slice(colon + 1);
    if (
      port.length === 0 ||
      port.startsWith("0") ||
      !/^[0-9]+$/.test(port) ||
      Number(port) > 65535
    ) {
      host = "";
    } else {
      host = hostPart;
    }
  }
  if (
    host.length === 0 ||
    host.startsWith(".") ||
    host.endsWith(".") ||
    host
      .split(".")
      .some(
        (label) =>
          label.length === 0 ||
          label.startsWith("-") ||
          label.endsWith("-") ||
          !/^[a-z0-9-]+$/.test(label),
      )
  ) {
    fail("origin host is noncanonical");
  }
}

/**
 * Construct a discovery link from its parts, validating the origin and ID
 * lengths. The enrollment ID and capability MUST be random and nonzero.
 */
export function buildEnrollmentDiscoveryLink(
  publicOrigin: string,
  enrollmentId: Uint8Array,
  discoveryCapability: Uint8Array,
): EnrollmentDiscoveryLink {
  validateLinkOrigin(publicOrigin);
  if (enrollmentId.length !== ENROLLMENT_ID_LEN) fail("enrollmentId must be 16 bytes");
  if (discoveryCapability.length !== DISCOVERY_CAPABILITY_LEN) fail("capability must be 32 bytes");
  if (enrollmentId.every((b) => b === 0)) fail("enrollmentId is zero");
  if (discoveryCapability.every((b) => b === 0)) fail("discovery capability is zero");
  return { publicOrigin, enrollmentId, discoveryCapability };
}

/**
 * Build the exact HTTPS QR/universal link:
 * `https://<origin>/remote/enroll?v=1&id=<base64url-16>&cap=<base64url-32>`.
 */
export function formatEnrollmentHttpsUrl(link: EnrollmentDiscoveryLink): string {
  if (!link.publicOrigin.startsWith("https://")) fail("link origin must start with https://");
  const authority = link.publicOrigin.slice("https://".length);
  const id = encodeBase64Url(link.enrollmentId);
  const cap = encodeBase64Url(link.discoveryCapability);
  return `https://${authority}${ENROLLMENT_LINK_PATH}?v=${ENROLLMENT_LINK_VERSION}&id=${id}&cap=${cap}`;
}

/**
 * Build the exact typed deep link:
 * `flycockpit://remote/enroll?v=1&id=<base64url-16>&cap=<base64url-32>`.
 */
export function formatEnrollmentDeepLink(link: EnrollmentDiscoveryLink): string {
  const id = encodeBase64Url(link.enrollmentId);
  const cap = encodeBase64Url(link.discoveryCapability);
  return `flycockpit://remote/enroll?v=${ENROLLMENT_LINK_VERSION}&id=${id}&cap=${cap}`;
}

/** Strictly parse an HTTPS enrollment discovery link. */
export function parseEnrollmentHttpsUrl(url: string): EnrollmentDiscoveryLink {
  const pathIndex = url.indexOf(ENROLLMENT_LINK_PATH);
  if (pathIndex === -1) fail("missing lowercase /remote/enroll path");
  const originPart = url.slice(0, pathIndex);
  const query = url.slice(pathIndex + ENROLLMENT_LINK_PATH.length);
  if (!originPart.startsWith("https://")) fail("link must use https");
  const originRest = originPart.slice("https://".length);
  if (originRest.length === 0) fail("empty origin");
  const fullOrigin = `https://${originRest}`;
  validateLinkOrigin(fullOrigin);
  if (!query.startsWith("?")) fail("query must begin with '?' immediately after path");
  const rawQuery = query.slice(1);
  if (rawQuery.includes("#")) fail("fragment rejected");
  const link = parseLinkQuery(rawQuery);
  return { ...link, publicOrigin: fullOrigin };
}

/** Strictly parse a typed deep link `flycockpit://remote/enroll?v=1&id=...&cap=...`. */
export function parseEnrollmentDeepLink(url: string): EnrollmentDiscoveryLink {
  const prefix = "flycockpit://remote/enroll";
  if (!url.startsWith(prefix)) fail("deep link must start with flycockpit://remote/enroll");
  const rest = url.slice(prefix.length);
  if (!rest.startsWith("?")) fail("deep link query must begin with '?'");
  const rawQuery = rest.slice(1);
  if (rawQuery.includes("#")) fail("fragment rejected");
  return parseLinkQuery(rawQuery);
}

/** Shared strict query parser: exact `v=1`, `id=…`, `cap=…` order, no extras. */
function parseLinkQuery(rawQuery: string): EnrollmentDiscoveryLink {
  const parts = rawQuery.split("&");
  if (parts[0] !== "v=1") fail("v must be 1");
  const idPart = parts[1];
  if (idPart === undefined || !idPart.startsWith("id=")) fail("id parameter malformed");
  const capPart = parts[2];
  if (capPart === undefined || !capPart.startsWith("cap=")) fail("cap parameter malformed");
  if (parts.length > 3) fail("extra query parameters rejected");
  const enrollmentId = decodeBase64UrlFixed(
    idPart.slice("id=".length),
    ENROLLMENT_ID_LEN,
    "enrollmentId",
  );
  const discoveryCapability = decodeBase64UrlFixed(
    capPart.slice("cap=".length),
    DISCOVERY_CAPABILITY_LEN,
    "capability",
  );
  if (enrollmentId.every((b) => b === 0)) fail("enrollmentId is zero");
  if (discoveryCapability.every((b) => b === 0)) fail("capability is zero");
  return { publicOrigin: "", enrollmentId, discoveryCapability };
}

// ─────────────────────────────────────────────────────────────────────────
// Closed enrollment/certificate-lifecycle/revocation enums
// ─────────────────────────────────────────────────────────────────────────

/** Enrollment ceremony state machine (12 states). Mirrors Rust `EnrollmentState::name`. */
export const ENROLLMENT_STATES = [
  "reserved",
  "awaiting_redemption",
  "awaiting_contributions",
  "code_ready",
  "awaiting_confirmations",
  "authorization_pending",
  "issuance_pending",
  "issued",
  "rejected",
  "expired",
  "cancelled",
  "superseded",
] as const;
export type EnrollmentState = (typeof ENROLLMENT_STATES)[number];

/** Terminal reason for an unsuccessful enrollment ceremony (7). */
export const ENROLLMENT_TERMINAL_REASONS = [
  "explicit_reject",
  "mismatch_limit",
  "policy_denied",
  "issuance_failed",
  "expired",
  "cancelled",
  "superseded",
] as const;
export type EnrollmentTerminalReason = (typeof ENROLLMENT_TERMINAL_REASONS)[number];

/** FCEN participant roles surfaced in the enrollment projection (3). */
export const ENROLLMENT_PARTICIPANT_ROLES = [
  "proposed_subject",
  "enrolled_counterpart",
  "control_plane_authorizer",
] as const;
export type EnrollmentParticipantRole = (typeof ENROLLMENT_PARTICIPANT_ROLES)[number];

/** Closed certificate-lifecycle action reducer: `enroll | renew | rotate` (3). */
export const CERTIFICATE_LIFECYCLE_ACTIONS = ["enroll", "renew", "rotate"] as const;
export type CertificateLifecycleAction = (typeof CERTIFICATE_LIFECYCLE_ACTIONS)[number];

/** Certificate operation state machine (7). */
export const CERTIFICATE_OPERATION_STATES = [
  "reserved",
  "proof_pending",
  "signer_pending",
  "issued",
  "denied",
  "expired",
  "cancelled",
] as const;
export type CertificateOperationState = (typeof CERTIFICATE_OPERATION_STATES)[number];

/** Terminal reason for a denied/expired/cancelled certificate operation (7). */
export const CERTIFICATE_OPERATION_TERMINAL_REASONS = [
  "invalid_current",
  "invalid_proof",
  "revoked",
  "policy_denied",
  "signer_unavailable",
  "expired",
  "cancelled",
] as const;
export type CertificateOperationTerminalReason =
  (typeof CERTIFICATE_OPERATION_TERMINAL_REASONS)[number];

/** Revocation operation state machine (8). */
export const REVOCATION_STATES = [
  "proof_pending",
  "approval_pending",
  "signer_pending",
  "pending_reconciliation",
  "revoked",
  "denied",
  "expired",
  "cancelled",
] as const;
export type RevocationState = (typeof REVOCATION_STATES)[number];

/** Revocation terminal reason (7). */
export const REVOCATION_TERMINAL_REASONS = [
  "invalid_current",
  "invalid_proof",
  "invalid_approval",
  "policy_denied",
  "signer_unavailable",
  "expired",
  "cancelled",
] as const;
export type RevocationTerminalReason = (typeof REVOCATION_TERMINAL_REASONS)[number];

/** Closed revocation actor mode derived from authenticated state (4). */
export const REVOCATION_ACTOR_MODES = [
  "public_self_account",
  "public_instance_owner",
  "self_client",
  "security_admin",
] as const;
export type RevocationActorMode = (typeof REVOCATION_ACTOR_MODES)[number];

/** Enrolled device lifecycle (7). */
export const REMOTE_DEVICE_LIFECYCLE = [
  "reserved",
  "pending",
  "active",
  "rotation_pending",
  "revoked",
  "deleted",
  "abandoned",
] as const;
export type RemoteDeviceLifecycle = (typeof REMOTE_DEVICE_LIFECYCLE)[number];

const ENROLLMENT_TERMINAL_STATES: ReadonlySet<EnrollmentState> = new Set([
  "rejected",
  "expired",
  "cancelled",
  "superseded",
]);
const CERTIFICATE_OPERATION_TERMINAL_STATES: ReadonlySet<CertificateOperationState> = new Set([
  "denied",
  "expired",
  "cancelled",
]);
const REVOCATION_TERMINAL_STATES: ReadonlySet<RevocationState> = new Set([
  "denied",
  "expired",
  "cancelled",
]);

/** True for enrollment states whose projection requires a `terminalReason`. */
export function enrollmentStateRequiresTerminalReason(state: EnrollmentState): boolean {
  return ENROLLMENT_TERMINAL_STATES.has(state);
}
/** True for certificate-operation states whose projection requires a `terminalReason`. */
export function certificateOperationStateRequiresTerminalReason(
  state: CertificateOperationState,
): boolean {
  return CERTIFICATE_OPERATION_TERMINAL_STATES.has(state);
}
/** True for revocation states whose projection requires a `terminalReason`. */
export function revocationStateRequiresTerminalReason(state: RevocationState): boolean {
  return REVOCATION_TERMINAL_STATES.has(state);
}

/**
 * Validate the exact enrollment state/terminal-reason pair. Throws
 * {@link EnrollmentProtocolError} for any illegal pair.
 */
export function validateEnrollmentStateTerminalReasonPair(
  state: EnrollmentState,
  reason: EnrollmentTerminalReason,
): void {
  const legal =
    (state === "rejected" &&
      (reason === "explicit_reject" ||
        reason === "mismatch_limit" ||
        reason === "policy_denied" ||
        reason === "issuance_failed")) ||
    (state === "expired" && reason === "expired") ||
    (state === "cancelled" && reason === "cancelled") ||
    (state === "superseded" && reason === "superseded");
  if (!legal) fail("illegal enrollment state/terminal-reason pair");
}

/** Validate the exact certificate-operation state/terminal-reason pair. */
export function validateCertificateOperationStateTerminalReasonPair(
  state: CertificateOperationState,
  reason: CertificateOperationTerminalReason,
): void {
  const legal =
    (state === "denied" &&
      (reason === "invalid_current" ||
        reason === "invalid_proof" ||
        reason === "revoked" ||
        reason === "policy_denied" ||
        reason === "signer_unavailable")) ||
    (state === "expired" && reason === "expired") ||
    (state === "cancelled" && reason === "cancelled");
  if (!legal) fail("illegal certificate-operation state/terminal-reason pair");
}

/** Validate the exact revocation state/terminal-reason pair. */
export function validateRevocationStateTerminalReasonPair(
  state: RevocationState,
  reason: RevocationTerminalReason,
): void {
  const legal =
    (state === "denied" &&
      (reason === "invalid_current" ||
        reason === "invalid_proof" ||
        reason === "invalid_approval" ||
        reason === "policy_denied" ||
        reason === "signer_unavailable")) ||
    (state === "expired" && reason === "expired") ||
    (state === "cancelled" && reason === "cancelled");
  if (!legal) fail("illegal revocation state/terminal-reason pair");
}

// ─────────────────────────────────────────────────────────────────────────
// Strict JSON wire projections
// ─────────────────────────────────────────────────────────────────────────

const enrollmentStateSchema = z.enum(ENROLLMENT_STATES);
const enrollmentTerminalReasonSchema = z.enum(ENROLLMENT_TERMINAL_REASONS);
const enrollmentParticipantRoleSchema = z.enum(ENROLLMENT_PARTICIPANT_ROLES);

/** A 16-byte operation/entity ID as its 22-character canonical base64url text. */
const enrollmentIdSchema = z.string().superRefine((value, ctx) => {
  try {
    decodeProtocolIdBase64Url(value);
  } catch (error) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : "invalid protocol id",
    });
  }
});

/** An opaque nullable base64url/JWS byte artifact carried as text. */
const nullableArtifactSchema = z.string().min(1).nullable();

/**
 * The common successful enrollment projection, mirroring Rust
 * `RemoteEnrollmentProgressV1`. `terminalReason` is null for non-terminal
 * states and a legal reason for terminal states;
 * proposal/transcript/issuerStatus move together.
 */
export const remoteEnrollmentProgressV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    enrollmentRequestId: enrollmentIdSchema,
    enrollmentId: enrollmentIdSchema,
    deviceId: enrollmentIdSchema,
    certificateId: enrollmentIdSchema,
    generation: canonicalU64DecimalStringSchema,
    state: enrollmentStateSchema,
    participantRole: enrollmentParticipantRoleSchema,
    expiresAt: canonicalU64DecimalStringSchema,
    proposal: nullableArtifactSchema,
    transcript: nullableArtifactSchema,
    issuerStatus: nullableArtifactSchema,
    authorizationRequestDigest: nullableArtifactSchema,
    certificate: nullableArtifactSchema,
    terminalReason: enrollmentTerminalReasonSchema.nullable(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (enrollmentStateRequiresTerminalReason(value.state)) {
      if (value.terminalReason === null) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "terminal state requires a terminalReason",
          path: ["terminalReason"],
        });
      } else {
        try {
          validateEnrollmentStateTerminalReasonPair(value.state, value.terminalReason);
        } catch {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "illegal enrollment state/terminal-reason pair",
            path: ["terminalReason"],
          });
        }
      }
    } else if (value.terminalReason !== null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "non-terminal state requires a null terminalReason",
        path: ["terminalReason"],
      });
    }
    const boundCount = [value.proposal, value.transcript, value.issuerStatus].filter(
      (field) => field !== null,
    ).length;
    if (boundCount !== 0 && boundCount !== 3) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "proposal, transcript and issuerStatus must be null or nonnull together",
      });
    }
  });
export type RemoteEnrollmentProgressV1 = z.infer<typeof remoteEnrollmentProgressV1Schema>;

/** Strict parser for {@link RemoteEnrollmentProgressV1}. */
export function parseRemoteEnrollmentProgressV1(value: unknown): RemoteEnrollmentProgressV1 {
  return remoteEnrollmentProgressV1Schema.parse(value);
}

/**
 * Every enrollment mutation other than create returns this, mirroring Rust
 * `RemoteEnrollmentMutationResultV1 = {schemaVersion:1,requestId,progress}`.
 */
export const remoteEnrollmentMutationResultV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    requestId: enrollmentIdSchema,
    progress: remoteEnrollmentProgressV1Schema,
  })
  .strict();
export type RemoteEnrollmentMutationResultV1 = z.infer<
  typeof remoteEnrollmentMutationResultV1Schema
>;

/** Strict parser for {@link RemoteEnrollmentMutationResultV1}. */
export function parseRemoteEnrollmentMutationResultV1(
  value: unknown,
): RemoteEnrollmentMutationResultV1 {
  return remoteEnrollmentMutationResultV1Schema.parse(value);
}

/**
 * The create-enrollment `201`/`200` result, mirroring the exact link-bearing
 * shape: `generation` is `"1"`, `participantRole` is `proposed_subject`, and
 * `proposedSubjectCapability` is null for a client or the daemon-only
 * unpadded base64url-32 continuation.
 */
export const remoteEnrollmentCreateResultV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    requestId: enrollmentIdSchema,
    enrollmentId: enrollmentIdSchema,
    deviceId: enrollmentIdSchema,
    certificateId: enrollmentIdSchema,
    generation: z.literal("1"),
    expiresAt: canonicalU64DecimalStringSchema,
    participantRole: z.literal("proposed_subject"),
    httpsUrl: z.string().min(1),
    deepLink: z.string().min(1),
    proposedSubjectCapability: z.string().min(1).nullable(),
  })
  .strict()
  .superRefine((value, ctx) => {
    try {
      parseEnrollmentHttpsUrl(value.httpsUrl);
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "httpsUrl is not a canonical enrollment discovery link",
        path: ["httpsUrl"],
      });
    }
    try {
      parseEnrollmentDeepLink(value.deepLink);
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "deepLink is not a canonical enrollment deep link",
        path: ["deepLink"],
      });
    }
    if (value.proposedSubjectCapability !== null) {
      try {
        decodeBase64UrlFixed(
          value.proposedSubjectCapability,
          DISCOVERY_CAPABILITY_LEN,
          "capability",
        );
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "proposedSubjectCapability must be unpadded base64url-32",
          path: ["proposedSubjectCapability"],
        });
      }
    }
  });
export type RemoteEnrollmentCreateResultV1 = z.infer<typeof remoteEnrollmentCreateResultV1Schema>;

/** Strict parser for {@link RemoteEnrollmentCreateResultV1}. */
export function parseRemoteEnrollmentCreateResultV1(
  value: unknown,
): RemoteEnrollmentCreateResultV1 {
  return remoteEnrollmentCreateResultV1Schema.parse(value);
}

/**
 * The common typed error envelope, mirroring `{schemaVersion:1,error:{code,
 * requestId,retryable}}`. `requestId` is null when no request was bound (e.g. a
 * non-enumerating `not_found`).
 */
export const remoteEnrollmentErrorEnvelopeV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    error: z
      .object({
        code: z.string().regex(/^[a-z][a-z0-9_]*$/, "error code must be snake_case"),
        requestId: enrollmentIdSchema.nullable(),
        retryable: z.boolean(),
      })
      .strict(),
  })
  .strict();
export type RemoteEnrollmentErrorEnvelopeV1 = z.infer<typeof remoteEnrollmentErrorEnvelopeV1Schema>;

/** Strict parser for {@link RemoteEnrollmentErrorEnvelopeV1}. */
export function parseRemoteEnrollmentErrorEnvelopeV1(
  value: unknown,
): RemoteEnrollmentErrorEnvelopeV1 {
  return remoteEnrollmentErrorEnvelopeV1Schema.parse(value);
}
