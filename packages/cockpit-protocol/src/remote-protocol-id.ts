/**
 * Opaque 16-byte remote protocol identifiers and CanonicalU64DecimalStringV1.
 * @see remote-protocol-identifier-foundation
 */
import { z } from "zod";

export const REMOTE_PROTOCOL_ID_BYTES = 16;
export const REMOTE_PROTOCOL_ID_B64URL_LEN = 22;
export const U64_MAX = 18446744073709551615n;

/**
 * Kinds of *persisted* protocol identifier. This set is mirrored by the
 * `RemoteProtocolIdentifierKind` Prisma enum, so it must not grow for
 * process-local uses.
 *
 * The ephemeral transport identifiers (`frameId`, `transferId`) reuse this
 * module's byte/base64url codec but are deliberately not kinds here: they are
 * never stored, never authorized, and never reach the database. Rust brands
 * them with marker types for compile-time separation; TypeScript carries them
 * as raw `Uint8Array`.
 */
export type RemoteProtocolIdKind = "tenant" | "account" | "instance" | "project";

export const REMOTE_PROTOCOL_ID_KINDS: readonly RemoteProtocolIdKind[] = [
  "tenant",
  "account",
  "instance",
  "project",
] as const;

const KIND_BRAND = Symbol("RemoteProtocolIdKind");

/** Kind-branded 16-byte protocol id (nominal; wrong-kind is a type error). */
export type RemoteProtocolIdBytes<K extends RemoteProtocolIdKind = RemoteProtocolIdKind> =
  Uint8Array & { readonly [KIND_BRAND]: K };

/** Brand for canonical u64 decimal string spelling. */
export type CanonicalU64DecimalStringV1 = string & {
  readonly __canonicalU64DecimalStringV1: unique symbol;
};

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

export function isRemoteProtocolIdKind(value: unknown): value is RemoteProtocolIdKind {
  return (REMOTE_PROTOCOL_ID_KINDS as readonly unknown[]).includes(value);
}

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Pure JS base64url (no Node Buffer / no btoa) for web and native. */
function encodeBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    const triple = (a << 16) | (b << 8) | c;
    out += B64URL_ALPHABET[(triple >> 18) & 63];
    out += B64URL_ALPHABET[(triple >> 12) & 63];
    if (i + 1 < bytes.length) out += B64URL_ALPHABET[(triple >> 6) & 63];
    if (i + 2 < bytes.length) out += B64URL_ALPHABET[triple & 63];
  }
  return out;
}

function decodeBase64UrlExact(text: string, expectedLen: number): Uint8Array {
  const lookup = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL_ALPHABET.length; i++) {
    lookup[B64URL_ALPHABET.charCodeAt(i)] = i;
  }
  const out = new Uint8Array(expectedLen);
  let outIdx = 0;
  let bits = 0;
  let value = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const v = code < 128 ? lookup[code]! : -1;
    if (v < 0) {
      throw new Error("protocol id text invalid alphabet");
    }
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (outIdx >= expectedLen) {
        throw new Error("protocol id decoded length mismatch");
      }
      out[outIdx++] = (value >> bits) & 0xff;
    }
  }
  if (outIdx !== expectedLen || bits >= 6) {
    // leftover significant bits indicate noncanonical padding-free encoding
    if (outIdx !== expectedLen) {
      throw new Error("protocol id decoded length mismatch");
    }
  }
  return out;
}

/** Encode raw 16 bytes as unpadded base64url (exactly 22 chars). */
export function encodeProtocolIdBase64Url(bytes: Uint8Array): string {
  if (bytes.length !== REMOTE_PROTOCOL_ID_BYTES) {
    throw new Error(`protocol id must be ${REMOTE_PROTOCOL_ID_BYTES} bytes, got ${bytes.length}`);
  }
  if (isAllZero(bytes)) {
    throw new Error("all-zero protocol id rejected");
  }
  const text = encodeBase64Url(bytes);
  if (text.length !== REMOTE_PROTOCOL_ID_B64URL_LEN || text.includes("=")) {
    throw new Error("internal: noncanonical protocol id encoding");
  }
  return text;
}

/** Decode unpadded base64url protocol id; rejects padding, noncanonical, all-zero. */
export function decodeProtocolIdBase64Url(text: string): Uint8Array {
  if (typeof text !== "string") {
    throw new Error("protocol id text must be a string");
  }
  if (text.length !== REMOTE_PROTOCOL_ID_B64URL_LEN) {
    throw new Error(`protocol id text must be ${REMOTE_PROTOCOL_ID_B64URL_LEN} chars`);
  }
  if (text.includes("=") || /[+/]/.test(text) || /\s/.test(text)) {
    throw new Error("protocol id text noncanonical base64url");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(text)) {
    throw new Error("protocol id text invalid alphabet");
  }
  let out: Uint8Array;
  try {
    out = decodeBase64UrlExact(text, REMOTE_PROTOCOL_ID_BYTES);
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("protocol id")) throw e;
    throw new Error("protocol id text decode failed");
  }
  if (isAllZero(out)) {
    throw new Error("all-zero protocol id rejected");
  }
  if (encodeProtocolIdBase64Url(out) !== text) {
    throw new Error("protocol id text noncanonical re-encoding");
  }
  return out;
}

/** Tag raw 16 bytes with a nominal kind (no DB work). Fails before any lookup. */
export function tagProtocolIdBytes<K extends RemoteProtocolIdKind>(
  kind: K,
  bytes: Uint8Array,
): RemoteProtocolIdBytes<K> {
  if (!isRemoteProtocolIdKind(kind)) {
    throw new Error("invalid protocol id kind");
  }
  if (bytes.length !== REMOTE_PROTOCOL_ID_BYTES || isAllZero(bytes)) {
    throw new Error("invalid protocol id bytes for kind tag");
  }
  const tagged = new Uint8Array(bytes) as RemoteProtocolIdBytes<K>;
  Object.defineProperty(tagged, KIND_BRAND, {
    value: kind,
    enumerable: false,
    configurable: false,
  });
  return tagged;
}

export function protocolIdKindOf<K extends RemoteProtocolIdKind>(
  bytes: RemoteProtocolIdBytes<K>,
): K {
  const kind = (bytes as RemoteProtocolIdBytes)[KIND_BRAND];
  if (!isRemoteProtocolIdKind(kind)) {
    throw new Error("protocol id missing or invalid kind brand");
  }
  return kind as K;
}

/** Decode wire text and brand with the expected kind (kind confusion fails before DB). */
export function decodeProtocolIdBase64UrlAsKind<K extends RemoteProtocolIdKind>(
  kind: K,
  text: string,
): RemoteProtocolIdBytes<K> {
  return tagProtocolIdBytes(kind, decodeProtocolIdBase64Url(text));
}

const U64_DECIMAL_RE = /^(0|[1-9][0-9]{0,19})$/;

/**
 * CanonicalU64DecimalStringV1: only `0` or `[1-9][0-9]{0,19}` ≤ u64::MAX.
 * Never accepts JSON numbers or TypeScript `number` inputs.
 */
export function parseCanonicalU64DecimalString(input: unknown): bigint {
  if (typeof input !== "string") {
    throw new Error("u64 decimal must be a string");
  }
  if (!U64_DECIMAL_RE.test(input)) {
    throw new Error("u64 decimal spelling invalid");
  }
  const v = BigInt(input);
  if (v < 0n || v > U64_MAX) {
    throw new Error("u64 decimal overflow");
  }
  if (v.toString() !== input) {
    throw new Error("u64 decimal noncanonical");
  }
  return v;
}

export function formatCanonicalU64DecimalString(value: bigint): CanonicalU64DecimalStringV1 {
  if (typeof value !== "bigint") {
    throw new Error("u64 format requires bigint");
  }
  if (value < 0n || value > U64_MAX) {
    throw new Error("u64 out of range");
  }
  return value.toString() as CanonicalU64DecimalStringV1;
}

/** Brand a string already known to be canonical (re-validates). */
export function asCanonicalU64DecimalString(input: unknown): CanonicalU64DecimalStringV1 {
  const v = parseCanonicalU64DecimalString(input);
  return formatCanonicalU64DecimalString(v);
}

/** Reject TypeScript number for exact integer protocol fields. */
export function rejectNumberForExactInteger(value: unknown): void {
  if (typeof value === "number") {
    throw new Error("exact integer must not be a number");
  }
}

/**
 * Unix timestamp fields as exact checked decimal strings.
 * Per foundation: nonnegative range with CanonicalU64DecimalStringV1 spelling
 * (signed timestamps that may be negative are out of this foundation's nonnegative rule).
 */
export function parseSignedUnixTimestampDecimalString(input: unknown): bigint {
  return parseCanonicalU64DecimalString(input);
}

/** Zod schema for wire CanonicalU64DecimalStringV1 (rejects numbers). */
export const canonicalU64DecimalStringSchema = z
  .string()
  .superRefine((val, ctx) => {
    try {
      parseCanonicalU64DecimalString(val);
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "invalid CanonicalU64DecimalStringV1",
      });
    }
  })
  .transform((val) => asCanonicalU64DecimalString(val));

/**
 * Strict-enough RFC 8785 (JCS) for remote protocol documents whose values are
 * only strings, bools, nulls, finite safe numbers, arrays, or plain objects.
 * Object keys are sorted lexicographically; no insignificant whitespace.
 * Rejects bigint, Date/Map/etc., undefined members, and unpaired surrogates.
 */
export function canonicalizeRfc8785(value: unknown): string {
  return canonicalizeValue(value);
}

function assertValidUnicodeString(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      if (i + 1 >= s.length) {
        throw new Error("RFC8785 rejects unpaired UTF-16 surrogates");
      }
      const next = s.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new Error("RFC8785 rejects unpaired UTF-16 surrogates");
      }
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new Error("RFC8785 rejects unpaired UTF-16 surrogates");
    }
  }
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function canonicalizeValue(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") {
    assertValidUnicodeString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("RFC8785 rejects non-finite numbers");
    }
    // Exact integers above 2^53-1 must never arrive as number.
    if (
      Number.isInteger(value) &&
      (value > Number.MAX_SAFE_INTEGER || value < Number.MIN_SAFE_INTEGER)
    ) {
      throw new Error("RFC8785 exact integer out of safe number range");
    }
    // ECMAScript number serialization for JCS (no exponent for integers in range).
    return JSON.stringify(value);
  }
  if (typeof value === "bigint") {
    throw new Error("RFC8785 bigint must be encoded as decimal string first");
  }
  if (typeof value === "undefined") {
    throw new Error("RFC8785 rejects undefined");
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      if (!(i in value) || value[i] === undefined) {
        throw new Error("RFC8785 rejects sparse arrays / undefined elements");
      }
      parts.push(canonicalizeValue(value[i]));
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    if (!isPlainObject(value)) {
      throw new Error("RFC8785 rejects non-plain objects");
    }
    const keys = Object.keys(value).sort();
    const parts: string[] = [];
    for (const k of keys) {
      assertValidUnicodeString(k);
      if (value[k] === undefined) {
        throw new Error("RFC8785 rejects undefined object members");
      }
      parts.push(`${JSON.stringify(k)}:${canonicalizeValue(value[k])}`);
    }
    return `{${parts.join(",")}}`;
  }
  throw new Error("RFC8785 unsupported value type");
}

/** u64be encode/decode for binary protocols. */
export function encodeU64Be(value: bigint): Uint8Array {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
    throw new Error("u64be out of range");
  }
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function decodeU64Be(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) {
    throw new Error("u64be requires 8 bytes");
  }
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v = (v << 8n) | BigInt(bytes[i]!);
  }
  return v;
}
