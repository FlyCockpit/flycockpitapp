/** Transport-neutral remote identity wire codecs (v1). No trust or policy decisions live here. */
import {
  canonicalizeRfc8785,
  decodeProtocolIdBase64Url,
  parseCanonicalU64DecimalString,
} from "./remote-protocol-id";

export const REMOTE_IDENTITY_MAGICS = {
  proposal: "FCIP",
  enrollment: "FCEN",
  custody: "FCCE",
  context: "FCPC",
  possession: "FCPP",
  confirmation: "FCCF",
} as const;
export const SubjectKind = { client: 1, daemon: 2 } as const;
export const CustodyClass = {
  origin_protected: 1,
  os_protected: 2,
  hardware_or_external: 3,
} as const;
export const PresenceMode = {
  unattended: 1,
  unattended_after_first_unlock: 2,
  unattended_unlocked_device: 3,
  user_presence_required: 4,
} as const;
export const EnrollmentRole = {
  proposed_subject: 1,
  enrolled_counterpart: 2,
  control_plane_authorizer: 3,
} as const;
export const PossessionPurpose = {
  enroll_proposed: 1,
  renew_current: 2,
  rotate_current: 3,
  rotate_proposed: 4,
  attempt_client: 5,
  attempt_daemon: 6,
  revoke_current: 7,
} as const;
export type SubjectKindV1 = 1 | 2;
export type EnrollmentRoleV1 = 1 | 2 | 3;
export type PossessionPurposeV1 = 1 | 2 | 3 | 4 | 5 | 6 | 7;

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const MAX_BINARY = 4096;
const domains = [
  "",
  "enroll-proposed",
  "renew-current",
  "rotate-current",
  "rotate-proposed",
  "attempt-client",
  "attempt-daemon",
  "revoke-current",
] as const;

export class RemoteIdentityProtocolError extends Error {}
function fail(message: string): never {
  throw new RemoteIdentityProtocolError(message);
}
function utf8(bytes: Uint8Array, name: string) {
  try {
    return td.decode(bytes);
  } catch {
    return fail(`invalid ${name} UTF-8`);
  }
}
function enumValue(value: number, max: number, name: string): void {
  if (!Number.isInteger(value) || value < 1 || value > max) fail(`unknown ${name}`);
}
function exact(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) fail(`${name} must be ${length} bytes`);
}
function nonzero(bytes: Uint8Array, name: string): void {
  exact(bytes, 16, name);
  if (bytes.every((b) => b === 0)) fail(`${name} must be nonzero`);
}
function origin(value: string): Uint8Array {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return fail("invalid origin");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.origin !== value
  )
    fail("origin must be a normalized HTTPS origin");
  const authority = value.slice("https://".length);
  const [host, port, extra] = authority.split(":");
  if (extra !== undefined || !host || host.startsWith(".") || host.endsWith("."))
    fail("origin host is noncanonical");
  if (host.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)))
    fail("origin host is noncanonical");
  if (port !== undefined && (!/^[1-9][0-9]*$/.test(port) || Number(port) > 65535 || port === "443"))
    fail("origin port is noncanonical");
  const bytes = te.encode(value);
  if (bytes.length < 1 || bytes.length > 255) fail("origin length");
  return bytes;
}
class Writer {
  parts: Uint8Array[] = [];
  length = 0;
  put(value: Uint8Array) {
    this.parts.push(value);
    this.length += value.length;
  }
  u8(v: number) {
    this.put(Uint8Array.of(v));
  }
  u16(v: number) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v);
    this.put(b);
  }
  u64(v: bigint) {
    if (v < 0n || v > 0xffffffffffffffffn) fail("u64 out of range");
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, v);
    this.put(b);
  }
  i64(v: bigint) {
    if (v < -0x8000000000000000n || v > 0x7fffffffffffffffn) fail("i64 out of range");
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, v);
    this.put(b);
  }
  done(max: number) {
    if (this.length > max) fail("wire value exceeds limit");
    const out = new Uint8Array(this.length);
    let n = 0;
    for (const p of this.parts) {
      out.set(p, n);
      n += p.length;
    }
    return out;
  }
}
class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  take(n: number) {
    if (n < 0 || this.offset + n > this.bytes.length) fail("truncated wire value");
    const x = this.bytes.slice(this.offset, this.offset + n);
    this.offset += n;
    return x;
  }
  u8() {
    return this.take(1)[0]!;
  }
  u16() {
    return new DataView(this.take(2).buffer).getUint16(0);
  }
  u64() {
    return new DataView(this.take(8).buffer).getBigUint64(0);
  }
  i64() {
    return new DataView(this.take(8).buffer).getBigInt64(0);
  }
  finish() {
    if (this.offset !== this.bytes.length) fail("trailing bytes");
  }
}
function preamble(w: Writer, magic: string) {
  w.put(te.encode(magic));
  w.u8(1);
}
function readPreamble(r: Reader, magic: string, max: number) {
  if (r.bytes.length > max) fail("wire value exceeds limit");
  const expected = te.encode(magic),
    actual = r.take(4);
  if (!actual.every((b, i) => b === expected[i]) || r.u8() !== 1) fail("wrong magic or version");
}
function account(w: Writer, kind: SubjectKindV1, id?: Uint8Array) {
  enumValue(kind, 2, "subject kind");
  if (kind === 1) {
    if (!id) fail("client account missing");
    nonzero(id, "accountId");
    w.u8(1);
    w.put(id);
  } else {
    if (id) fail("daemon account present");
    w.u8(0);
  }
}
function readAccount(r: Reader, kind: SubjectKindV1) {
  const p = r.u8();
  if (p > 1) fail("invalid account presence");
  if (kind === 1 && p !== 1) fail("client account missing");
  if (kind === 2 && p !== 0) fail("daemon account present");
  return p === 1 ? r.take(16) : undefined;
}
function keyCheck(x: Uint8Array, y: Uint8Array, thumbprint: Uint8Array) {
  exact(x, 32, "p256 x");
  exact(y, 32, "p256 y");
  exact(thumbprint, 32, "thumbprint");
}
const P256_N = Uint8Array.from([
  255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173, 167,
  23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
]);
const P256_HALF_N = Uint8Array.from([
  127, 255, 255, 255, 128, 0, 0, 0, 127, 255, 255, 255, 255, 255, 255, 255, 222, 115, 125, 86, 211,
  139, 207, 66, 121, 220, 229, 97, 126, 49, 146, 168,
]);
function compareBytes(a: Uint8Array, b: Uint8Array) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1;
  }
  return 0;
}
function validateLowSP1363(signature: Uint8Array) {
  exact(signature, 64, "signature");
  const r = signature.slice(0, 32),
    s = signature.slice(32);
  if (
    r.every((x) => x === 0) ||
    s.every((x) => x === 0) ||
    compareBytes(r, P256_N) >= 0 ||
    compareBytes(s, P256_HALF_N) > 0
  )
    fail("invalid or high-S P1363 signature");
}
export function remoteIdentitySha256Sync(input: Uint8Array) {
  const k = Uint32Array.from([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const bit = input.length * 8,
    padded = new Uint8Array(((input.length + 9 + 63) >> 6) << 6);
  padded.set(input);
  padded[input.length] = 128;
  new DataView(padded.buffer).setBigUint64(padded.length - 8, BigInt(bit));
  const h = Uint32Array.from([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
      0x5be0cd19,
    ]),
    w = new Uint32Array(64),
    rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    const d = new DataView(padded.buffer, off, 64);
    for (let i = 0; i < 16; i++) w[i] = d.getUint32(i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!,
        b = w[i - 2]!;
      w[i] =
        (w[i - 16]! +
          (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) +
          w[i - 7]! +
          (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) >>>
        0;
    }
    let [a, b, c, d0, e, f, g, h0] = h;
    for (let i = 0; i < 64; i++) {
      const t1 =
          (h0! +
            (rotr(e!, 6) ^ rotr(e!, 11) ^ rotr(e!, 25)) +
            ((e! & f!) ^ (~e! & g!)) +
            k[i]! +
            w[i]!) >>>
          0,
        t2 =
          ((rotr(a!, 2) ^ rotr(a!, 13) ^ rotr(a!, 22)) + ((a! & b!) ^ (a! & c!) ^ (b! & c!))) >>> 0;
      h0 = g;
      g = f;
      f = e;
      e = (d0! + t1) >>> 0;
      d0 = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    for (const [i, v] of [a, b, c, d0, e, f, g, h0].entries()) h[i] = (h[i]! + v!) >>> 0;
  }
  const out = new Uint8Array(32),
    view = new DataView(out.buffer);
  h.forEach((v, i) => {
    view.setUint32(i * 4, v);
  });
  return out;
}
function b64url(bytes: Uint8Array) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += a[(n >> 18) & 63]! + a[(n >> 12) & 63]!;
    if (i + 1 < bytes.length) out += a[(n >> 6) & 63]!;
    if (i + 2 < bytes.length) out += a[n & 63]!;
  }
  return out;
}
function validateThumbprint(x: Uint8Array, y: Uint8Array, thumbprint: Uint8Array) {
  const json = te.encode(`{"crv":"P-256","kty":"EC","x":"${b64url(x)}","y":"${b64url(y)}"}`),
    actual = remoteIdentitySha256Sync(json);
  if (!actual.every((b, i) => b === thumbprint[i])) fail("thumbprint mismatch");
}

export interface RemoteIdentityProposalV1 {
  subjectKind: SubjectKindV1;
  subjectId: Uint8Array;
  tenantId: Uint8Array;
  accountId?: Uint8Array;
  instanceId: Uint8Array;
  certificateId: Uint8Array;
  generation: bigint;
  p256X: Uint8Array;
  p256Y: Uint8Array;
  thumbprint: Uint8Array;
  custodyClass: number;
  presenceMode: number;
  issuer: string;
  serviceVersion: bigint;
  policyEpoch: bigint;
  policyDigest: Uint8Array;
  authorityEpoch: bigint;
  issuedAt: bigint;
  expiresAt: bigint;
}
export function encodeRemoteIdentityProposal(v: RemoteIdentityProposalV1) {
  nonzero(v.subjectId, "subjectId");
  nonzero(v.tenantId, "tenantId");
  nonzero(v.instanceId, "instanceId");
  nonzero(v.certificateId, "certificateId");
  keyCheck(v.p256X, v.p256Y, v.thumbprint);
  validateThumbprint(v.p256X, v.p256Y, v.thumbprint);
  enumValue(v.custodyClass, 3, "custody class");
  enumValue(v.presenceMode, 4, "presence mode");
  exact(v.policyDigest, 32, "policy digest");
  const o = origin(v.issuer),
    w = new Writer();
  preamble(w, "FCIP");
  w.u8(v.subjectKind);
  w.put(v.subjectId);
  w.put(v.tenantId);
  account(w, v.subjectKind, v.accountId);
  w.put(v.instanceId);
  w.put(v.certificateId);
  w.u64(v.generation);
  w.put(v.p256X);
  w.put(v.p256Y);
  w.put(v.thumbprint);
  w.u8(v.custodyClass);
  w.u8(v.presenceMode);
  w.u16(o.length);
  w.put(o);
  w.u64(v.serviceVersion);
  w.u64(v.policyEpoch);
  w.put(v.policyDigest);
  w.u64(v.authorityEpoch);
  w.i64(v.issuedAt);
  w.i64(v.expiresAt);
  return w.done(MAX_BINARY);
}
export function decodeRemoteIdentityProposal(bytes: Uint8Array): RemoteIdentityProposalV1 {
  const r = new Reader(bytes);
  readPreamble(r, "FCIP", MAX_BINARY);
  const subjectKind = r.u8() as SubjectKindV1;
  enumValue(subjectKind, 2, "subject kind");
  const subjectId = r.take(16),
    tenantId = r.take(16),
    accountId = readAccount(r, subjectKind),
    instanceId = r.take(16),
    certificateId = r.take(16),
    generation = r.u64(),
    p256X = r.take(32),
    p256Y = r.take(32),
    thumbprint = r.take(32),
    custodyClass = r.u8(),
    presenceMode = r.u8(),
    issuer = utf8(r.take(r.u16()), "issuer"),
    serviceVersion = r.u64(),
    policyEpoch = r.u64(),
    policyDigest = r.take(32),
    authorityEpoch = r.u64(),
    issuedAt = r.i64(),
    expiresAt = r.i64();
  r.finish();
  return decodeRemoteIdentityProposalChecked({
    subjectKind,
    subjectId,
    tenantId,
    accountId,
    instanceId,
    certificateId,
    generation,
    p256X,
    p256Y,
    thumbprint,
    custodyClass,
    presenceMode,
    issuer,
    serviceVersion,
    policyEpoch,
    policyDigest,
    authorityEpoch,
    issuedAt,
    expiresAt,
  });
}
function decodeRemoteIdentityProposalChecked(v: RemoteIdentityProposalV1) {
  encodeRemoteIdentityProposal(v);
  return v;
}

export interface EnrollmentTranscriptV1 {
  enrollmentId: Uint8Array;
  tenantId: Uint8Array;
  accountId?: Uint8Array;
  instanceId: Uint8Array;
  subjectKind: SubjectKindV1;
  subjectId: Uint8Array;
  generation: bigint;
  p256X: Uint8Array;
  p256Y: Uint8Array;
  thumbprint: Uint8Array;
  custodyClass: number;
  presenceMode: number;
  publicOrigin: string;
  initiatorRole: EnrollmentRoleV1;
  confirmerRole: EnrollmentRoleV1;
  initiatorNonce: Uint8Array;
  confirmerNonce: Uint8Array;
  createdAt: bigint;
  expiresAt: bigint;
  serviceVersion: bigint;
  policyEpoch: bigint;
  policyDigest: Uint8Array;
  authorityEpoch: bigint;
}
function roles(a: EnrollmentRoleV1, b: EnrollmentRoleV1) {
  enumValue(a, 3, "enrollment role");
  enumValue(b, 3, "enrollment role");
  if (a === b || !(a === 1 || b === 1))
    fail("roles require one proposed subject and one authorizer");
}
export function encodeEnrollmentTranscript(v: EnrollmentTranscriptV1) {
  for (const value of [v.enrollmentId, v.tenantId, v.instanceId, v.subjectId]) nonzero(value, "id");
  keyCheck(v.p256X, v.p256Y, v.thumbprint);
  validateThumbprint(v.p256X, v.p256Y, v.thumbprint);
  enumValue(v.custodyClass, 3, "custody class");
  enumValue(v.presenceMode, 4, "presence mode");
  roles(v.initiatorRole, v.confirmerRole);
  exact(v.initiatorNonce, 32, "nonce");
  exact(v.confirmerNonce, 32, "nonce");
  exact(v.policyDigest, 32, "policy digest");
  if (v.expiresAt <= v.createdAt || v.expiresAt - v.createdAt > 300n) fail("transcript lifetime");
  const o = origin(v.publicOrigin),
    w = new Writer();
  preamble(w, "FCEN");
  w.put(v.enrollmentId);
  w.put(v.tenantId);
  account(w, v.subjectKind, v.accountId);
  w.put(v.instanceId);
  w.u8(v.subjectKind);
  w.put(v.subjectId);
  w.u64(v.generation);
  w.put(v.p256X);
  w.put(v.p256Y);
  w.put(v.thumbprint);
  w.u8(v.custodyClass);
  w.u8(v.presenceMode);
  w.u16(o.length);
  w.put(o);
  w.u8(v.initiatorRole);
  w.u8(v.confirmerRole);
  w.put(v.initiatorNonce);
  w.put(v.confirmerNonce);
  w.i64(v.createdAt);
  w.i64(v.expiresAt);
  w.u64(v.serviceVersion);
  w.u64(v.policyEpoch);
  w.put(v.policyDigest);
  w.u64(v.authorityEpoch);
  return w.done(1024);
}
export function decodeEnrollmentTranscript(bytes: Uint8Array): EnrollmentTranscriptV1 {
  const r = new Reader(bytes);
  readPreamble(r, "FCEN", 1024);
  const enrollmentId = r.take(16),
    tenantId =
      r.take(16); /* subject kind follows instance, so inspect branch by trying canonical offsets */
  const present = r.u8();
  if (present > 1) fail("invalid account presence");
  const accountId = present ? r.take(16) : undefined,
    instanceId = r.take(16),
    subjectKind = r.u8() as SubjectKindV1;
  enumValue(subjectKind, 2, "subject kind");
  if (subjectKind === 1 && !accountId) fail("client account missing");
  if (subjectKind === 2 && accountId) fail("daemon account present");
  const v = {
    enrollmentId,
    tenantId,
    accountId,
    instanceId,
    subjectKind,
    subjectId: r.take(16),
    generation: r.u64(),
    p256X: r.take(32),
    p256Y: r.take(32),
    thumbprint: r.take(32),
    custodyClass: r.u8(),
    presenceMode: r.u8(),
    publicOrigin: utf8(r.take(r.u16()), "origin"),
    initiatorRole: r.u8() as EnrollmentRoleV1,
    confirmerRole: r.u8() as EnrollmentRoleV1,
    initiatorNonce: r.take(32),
    confirmerNonce: r.take(32),
    createdAt: r.i64(),
    expiresAt: r.i64(),
    serviceVersion: r.u64(),
    policyEpoch: r.u64(),
    policyDigest: r.take(32),
    authorityEpoch: r.u64(),
  };
  r.finish();
  encodeEnrollmentTranscript(v);
  return v;
}

export interface CustodyEvidenceV1 {
  subjectKind: SubjectKindV1;
  subjectId: Uint8Array;
  generation: bigint;
  custodyClass: number;
  presenceMode: number;
  providerEvidence: Uint8Array;
  evidenceDigest: Uint8Array;
  observedAt: bigint;
}
export function encodeCustodyEvidence(v: CustodyEvidenceV1) {
  enumValue(v.subjectKind, 2, "subject kind");
  nonzero(v.subjectId, "subjectId");
  enumValue(v.custodyClass, 3, "custody class");
  enumValue(v.presenceMode, 4, "presence mode");
  if (v.providerEvidence.length > 65000) fail("provider evidence too long");
  exact(v.evidenceDigest, 32, "evidence digest");
  if (!remoteIdentitySha256Sync(v.providerEvidence).every((b, i) => b === v.evidenceDigest[i]))
    fail("evidence digest mismatch");
  const w = new Writer();
  preamble(w, "FCCE");
  w.u8(v.subjectKind);
  w.put(v.subjectId);
  w.u64(v.generation);
  w.u8(v.custodyClass);
  w.u8(v.presenceMode);
  w.u16(v.providerEvidence.length);
  w.put(v.providerEvidence);
  w.put(v.evidenceDigest);
  w.i64(v.observedAt);
  return w.done(65536);
}
export function decodeCustodyEvidence(bytes: Uint8Array): CustodyEvidenceV1 {
  const r = new Reader(bytes);
  readPreamble(r, "FCCE", 65536);
  const v = {
    subjectKind: r.u8() as SubjectKindV1,
    subjectId: r.take(16),
    generation: r.u64(),
    custodyClass: r.u8(),
    presenceMode: r.u8(),
    providerEvidence: r.take(r.u16()),
    evidenceDigest: r.take(32),
    observedAt: r.i64(),
  };
  r.finish();
  encodeCustodyEvidence(v);
  return v;
}
export async function validateCustodyEvidenceDigest(v: CustodyEvidenceV1) {
  const actual = await remoteIdentitySha256(v.providerEvidence);
  if (!actual.every((b, i) => b === v.evidenceDigest[i])) fail("evidence digest mismatch");
}

export interface PossessionContextV1 {
  purpose: PossessionPurposeV1;
  currentCertificateDigest?: Uint8Array;
  proposedIdentityDigest?: Uint8Array;
  enrollmentTranscriptDigest?: Uint8Array;
  attemptRequestDigest?: Uint8Array;
  revocationRequestDigest?: Uint8Array;
}
const matrix: Record<number, readonly boolean[]> = {
  1: [false, true, true, false, false],
  2: [true, true, false, false, false],
  3: [true, true, false, false, false],
  4: [true, true, false, false, false],
  5: [true, false, false, true, false],
  6: [true, false, false, true, false],
  7: [true, false, false, false, true],
};
export function encodePossessionContext(v: PossessionContextV1) {
  enumValue(v.purpose, 7, "possession purpose");
  const values = [
      v.currentCertificateDigest,
      v.proposedIdentityDigest,
      v.enrollmentTranscriptDigest,
      v.attemptRequestDigest,
      v.revocationRequestDigest,
    ],
    w = new Writer();
  preamble(w, "FCPC");
  w.u8(v.purpose);
  values.forEach((x, i) => {
    if (Boolean(x) !== matrix[v.purpose]![i]) fail("purpose context mismatch");
    w.u8(x ? 1 : 0);
    if (x) {
      exact(x, 32, "context digest");
      w.put(x);
    }
  });
  return w.done(171);
}
export function decodePossessionContext(bytes: Uint8Array): PossessionContextV1 {
  const r = new Reader(bytes);
  readPreamble(r, "FCPC", 171);
  const purpose = r.u8() as PossessionPurposeV1;
  enumValue(purpose, 7, "possession purpose");
  const vals: (Uint8Array | undefined)[] = [];
  for (let i = 0; i < 5; i++) {
    const p = r.u8();
    if (p > 1) fail("invalid digest presence");
    vals.push(p ? r.take(32) : undefined);
  }
  r.finish();
  const v = {
    purpose,
    currentCertificateDigest: vals[0],
    proposedIdentityDigest: vals[1],
    enrollmentTranscriptDigest: vals[2],
    attemptRequestDigest: vals[3],
    revocationRequestDigest: vals[4],
  };
  encodePossessionContext(v);
  return v;
}
export function possessionChallengeDomain(p: PossessionPurposeV1) {
  enumValue(p, 7, "possession purpose");
  return te.encode(`flycockpit.remote.identity-possession-challenge.${domains[p]}.v1\0`);
}
export function possessionSignatureDomain(p: PossessionPurposeV1) {
  enumValue(p, 7, "possession purpose");
  return te.encode(`flycockpit.remote.identity-possession-proof.${domains[p]}.v1\0`);
}
export async function remoteIdentitySha256(bytes: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer));
}
export async function derivePossessionChallenge(
  p: PossessionPurposeV1,
  status: Uint8Array,
  requestId: Uint8Array,
  contextBytes: Uint8Array,
) {
  if (decodePossessionContext(contextBytes).purpose !== p) fail("context purpose mismatch");
  exact(status, 32, "status digest");
  nonzero(requestId, "requestId");
  const digest = await remoteIdentitySha256(contextBytes);
  const d = possessionChallengeDomain(p),
    all = new Uint8Array(d.length + 80);
  all.set(d);
  all.set(status, d.length);
  all.set(requestId, d.length + 32);
  all.set(digest, d.length + 48);
  return remoteIdentitySha256(all);
}
export async function possessionProofSigningDigest(
  unsignedProof: Uint8Array,
  p: PossessionPurposeV1,
) {
  if (
    unsignedProof.length !== 175 ||
    !unsignedProof.slice(0, 4).every((b, i) => b === te.encode("FCPP")[i]) ||
    unsignedProof[5] !== p
  )
    fail("invalid unsigned possession proof");
  const checked = new Uint8Array(239);
  checked.set(unsignedProof);
  checked[206] = 1;
  checked[238] = 1;
  decodePossessionProof(checked);
  const d = possessionSignatureDomain(p),
    all = new Uint8Array(d.length + unsignedProof.length);
  all.set(d);
  all.set(unsignedProof, d.length);
  return remoteIdentitySha256(all);
}

export interface PossessionProofV1 {
  purpose: PossessionPurposeV1;
  subjectKind: SubjectKindV1;
  subjectId: Uint8Array;
  certificateId: Uint8Array;
  generation: bigint;
  requestId: Uint8Array;
  issuerStatusDigest: Uint8Array;
  challenge: Uint8Array;
  transcriptDigest: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
  signatureP1363: Uint8Array;
}
export function encodePossessionProof(v: PossessionProofV1) {
  enumValue(v.purpose, 7, "purpose");
  enumValue(v.subjectKind, 2, "subject kind");
  if (
    (v.purpose === 5 && v.subjectKind !== 1) ||
    (v.purpose === 6 && v.subjectKind !== 2) ||
    (v.purpose === 7 && v.subjectKind !== 1)
  )
    fail("purpose subject mismatch");
  nonzero(v.subjectId, "subjectId");
  nonzero(v.certificateId, "certificateId");
  nonzero(v.requestId, "requestId");
  for (const digest of [v.issuerStatusDigest, v.challenge, v.transcriptDigest])
    exact(digest, 32, "digest");
  validateLowSP1363(v.signatureP1363);
  if (v.expiresAt !== v.issuedAt + 60n) fail("proof lifetime must be 60 seconds");
  const w = new Writer();
  preamble(w, "FCPP");
  w.u8(v.purpose);
  w.u8(v.subjectKind);
  w.put(v.subjectId);
  w.put(v.certificateId);
  w.u64(v.generation);
  w.put(v.requestId);
  w.put(v.issuerStatusDigest);
  w.put(v.challenge);
  w.put(v.transcriptDigest);
  w.i64(v.issuedAt);
  w.i64(v.expiresAt);
  w.put(v.signatureP1363);
  return w.done(239);
}
export function decodePossessionProof(bytes: Uint8Array): PossessionProofV1 {
  const r = new Reader(bytes);
  readPreamble(r, "FCPP", 239);
  const v = {
    purpose: r.u8() as PossessionPurposeV1,
    subjectKind: r.u8() as SubjectKindV1,
    subjectId: r.take(16),
    certificateId: r.take(16),
    generation: r.u64(),
    requestId: r.take(16),
    issuerStatusDigest: r.take(32),
    challenge: r.take(32),
    transcriptDigest: r.take(32),
    issuedAt: r.i64(),
    expiresAt: r.i64(),
    signatureP1363: r.take(64),
  };
  r.finish();
  encodePossessionProof(v);
  return v;
}

export interface EnrollmentConfirmationV1 {
  role: EnrollmentRoleV1;
  decision: 1 | 2;
  enrollmentId: Uint8Array;
  transcriptDigest: Uint8Array;
  sasVersion: 1;
  confirmationNonce: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
  signatureP1363: Uint8Array;
}
export function enrollmentConfirmationDomain(role: EnrollmentRoleV1) {
  enumValue(role, 3, "role");
  return te.encode(
    `flycockpit.remote.enrollment-confirmation.${["", "proposed-subject", "enrolled-counterpart", "control-plane-authorizer"][role]}.v1\0`,
  );
}
export function encodeEnrollmentConfirmation(v: EnrollmentConfirmationV1) {
  enumValue(v.role, 3, "role");
  enumValue(v.decision, 2, "decision");
  nonzero(v.enrollmentId, "enrollmentId");
  exact(v.transcriptDigest, 32, "transcript digest");
  if (v.sasVersion !== 1) fail("unknown SAS version");
  exact(v.confirmationNonce, 32, "nonce");
  if (v.expiresAt <= v.issuedAt || v.expiresAt - v.issuedAt > 60n) fail("confirmation lifetime");
  validateLowSP1363(v.signatureP1363);
  const w = new Writer();
  preamble(w, "FCCF");
  w.u8(v.role);
  w.u8(v.decision);
  w.put(v.enrollmentId);
  w.put(v.transcriptDigest);
  w.u8(1);
  w.put(v.confirmationNonce);
  w.i64(v.issuedAt);
  w.i64(v.expiresAt);
  w.put(v.signatureP1363);
  return w.done(168);
}
export function decodeEnrollmentConfirmation(bytes: Uint8Array): EnrollmentConfirmationV1 {
  const r = new Reader(bytes);
  readPreamble(r, "FCCF", 168);
  const v = {
    role: r.u8() as EnrollmentRoleV1,
    decision: r.u8() as 1 | 2,
    enrollmentId: r.take(16),
    transcriptDigest: r.take(32),
    sasVersion: r.u8() as 1,
    confirmationNonce: r.take(32),
    issuedAt: r.i64(),
    expiresAt: r.i64(),
    signatureP1363: r.take(64),
  };
  r.finish();
  encodeEnrollmentConfirmation(v);
  return v;
}
export async function enrollmentConfirmationSigningDigest(
  unsignedConfirmation: Uint8Array,
  role: EnrollmentRoleV1,
) {
  if (
    unsignedConfirmation.length !== 104 ||
    !unsignedConfirmation.slice(0, 4).every((b, i) => b === te.encode("FCCF")[i]) ||
    unsignedConfirmation[5] !== role
  )
    fail("invalid unsigned enrollment confirmation");
  const checked = new Uint8Array(168);
  checked.set(unsignedConfirmation);
  checked[135] = 1;
  checked[167] = 1;
  decodeEnrollmentConfirmation(checked);
  const d = enrollmentConfirmationDomain(role),
    all = new Uint8Array(d.length + unsignedConfirmation.length);
  all.set(d);
  all.set(unsignedConfirmation, d.length);
  return remoteIdentitySha256(all);
}

/** Exact JWS structural parser. Signature verification/trust is deliberately caller-owned. */
export function parseRemoteIdentityCertificateJws(compact: string) {
  const raw = te.encode(compact);
  if (raw.length > 4096) fail("certificate exceeds 4096 bytes");
  const parts = compact.split(".");
  if (parts.length !== 3 || parts.some((x) => !x || x.includes("="))) fail("invalid compact JWS");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const decode = (s: string) => {
    if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) fail("noncanonical base64url");
    const out: number[] = [];
    let bits = 0,
      value = 0;
    for (const char of s) {
      value = (value << 6) | alphabet.indexOf(char);
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out.push((value >> bits) & 255);
      }
    }
    if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) fail("noncanonical base64url trailing bits");
    const bytes = Uint8Array.from(out);
    let encoded = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
      encoded += alphabet[(n >> 18) & 63]! + alphabet[(n >> 12) & 63]!;
      if (i + 1 < bytes.length) encoded += alphabet[(n >> 6) & 63]!;
      if (i + 2 < bytes.length) encoded += alphabet[n & 63]!;
    }
    if (encoded !== s) fail("noncanonical base64url");
    return bytes;
  };
  let header: unknown, payload: unknown;
  const headerBytes = decode(parts[0]!),
    payloadBytes = decode(parts[1]!);
  try {
    header = JSON.parse(utf8(headerBytes, "header")) as unknown;
    payload = JSON.parse(utf8(payloadBytes, "payload")) as unknown;
  } catch (error) {
    if (error instanceof RemoteIdentityProtocolError) throw error;
    fail("invalid JWS JSON or UTF-8");
  }
  if (
    te.encode(canonicalizeRfc8785(header)).some((b, i) => b !== headerBytes[i]) ||
    te.encode(canonicalizeRfc8785(header)).length !== headerBytes.length ||
    te.encode(canonicalizeRfc8785(payload)).some((b, i) => b !== payloadBytes[i]) ||
    te.encode(canonicalizeRfc8785(payload)).length !== payloadBytes.length
  )
    fail("noncanonical JWS JSON");
  const sig = decode(parts[2]!);
  validateLowSP1363(sig);
  if (!header || typeof header !== "object" || Array.isArray(header)) fail("invalid header");
  const h = header as Record<string, unknown>;
  if (
    Object.keys(h).sort().join(",") !== "alg,kid,typ" ||
    h.alg !== "ES256" ||
    h.typ !== "flycockpit-remote-identity-certificate+jws" ||
    typeof h.kid !== "string"
  )
    fail("invalid protected header");
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) fail("invalid payload");
  const p = payload as Record<string, unknown>;
  const keys = [
    "schemaVersion",
    "iss",
    "aud",
    "sub",
    "tenantId",
    "accountId",
    "instanceId",
    "subjectKind",
    "certificateId",
    "generation",
    "publicKey",
    "thumbprint",
    "custody",
    "presenceMode",
    "authorityEpoch",
    "iat",
    "exp",
  ]
    .sort()
    .join(",");
  if (
    Object.keys(p).sort().join(",") !== keys ||
    p.schemaVersion !== 1 ||
    p.aud !== "flycockpit-remote-peer-v1"
  )
    fail("invalid certificate payload members");
  for (const k of ["sub", "tenantId", "instanceId", "certificateId"]) {
    if (typeof p[k] !== "string") fail(`invalid ${k}`);
    decodeProtocolIdBase64Url(p[k] as string);
  }
  if (p.subjectKind !== 1 && p.subjectKind !== 2) fail("invalid subjectKind");
  enumValue(p.custody as number, 3, "custody class");
  enumValue(p.presenceMode as number, 4, "presence mode");
  if (typeof p.iss !== "string") fail("invalid iss");
  origin(p.iss);
  if (
    (p.subjectKind === 1 && typeof p.accountId !== "string") ||
    (p.subjectKind === 2 && p.accountId !== null)
  )
    fail("invalid certificate account branch");
  if (typeof p.accountId === "string") decodeProtocolIdBase64Url(p.accountId);
  for (const k of ["generation", "authorityEpoch", "iat", "exp"])
    parseCanonicalU64DecimalString(p[k]);
  if (parseCanonicalU64DecimalString(p.exp) <= parseCanonicalU64DecimalString(p.iat))
    fail("invalid certificate lifetime");
  if (!p.publicKey || typeof p.publicKey !== "object" || Array.isArray(p.publicKey))
    fail("invalid publicKey");
  const key = p.publicKey as Record<string, unknown>;
  if (
    Object.keys(key).sort().join(",") !== "crv,kty,x,y" ||
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    typeof key.x !== "string" ||
    typeof key.y !== "string" ||
    typeof p.thumbprint !== "string"
  )
    fail("invalid publicKey or thumbprint");
  const x = decode(key.x),
    y = decode(key.y),
    thumbprint = decode(p.thumbprint);
  keyCheck(x, y, thumbprint);
  validateThumbprint(x, y, thumbprint);
  return {
    protectedHeader: h,
    payload: p,
    signatureP1363: sig,
    signingInput: te.encode(`${parts[0]}.${parts[1]}`),
  };
}
