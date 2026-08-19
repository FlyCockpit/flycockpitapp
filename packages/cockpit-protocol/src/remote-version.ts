/**
 * Compatible remote protocol tuple negotiation.
 *
 * Owns the code-enabled compatible-tuple registry, the
 * `RemoteNegotiationTranscriptV1` binary codec, the SHA-256 transcript and
 * enabled-registry digest helpers, and the pure selection / upgrade-required
 * function. Paired with `crates/cockpit-proto/src/remote_version.rs`.
 *
 * The `application` component of every registry tuple is sourced from the
 * single `PROTOCOL_VERSION` constant — never hardcoded in the registry, in any
 * fixture, or in any test. Pre-release bumps of that constant update tuple
 * `0x0001`'s recorded application component in place; `proto-version-reset-at-tag`
 * renumbers it to 1 at tag time without editing this registry.
 *
 * New negotiation code never sniffs, aliases, or falls back: this module
 * contains no legacy-envelope parsing, no environment-defined tuples, no
 * permissive default tuple, and no import of `relay-protocol`.
 */
import { createHash } from "node:crypto";
import { PROTOCOL_VERSION } from "./index";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const TRANSCRIPT_MAGIC = "FCRN";
export const TRANSCRIPT_MAGIC_BYTES = new Uint8Array([0x46, 0x43, 0x52, 0x4e]) as Uint8Array & {
  readonly __magic: unique symbol;
};

export const TRANSCRIPT_VERSION = 1;
/** 4+1+1+16+16+32+32+32 = 134 bytes through policyDigest, plus three count
 * bytes, selectedTupleId:u16, and featureCount:u8 = 140 bytes. */
export const TRANSCRIPT_FIXED_BYTES = 140;
/** 140 + 3*16*2 + 32*4 = 364 bytes. */
export const TRANSCRIPT_MAX_BYTES = 364;
/** Minimum well-formed transcript (three one-entry lists, zero features) = 146
 * bytes. Also the exact V1 instance size. */
export const TRANSCRIPT_MIN_BYTES = 146;

export const TRANSPORT_WEBRTC = 1;
export const TRANSPORT_WEBSOCKET_DATA = 2;

export const TUPLE_LIST_MIN = 1;
export const TUPLE_LIST_MAX = 16;
export const FEATURE_LIST_MAX = 32;

export const V1_TUPLE_ID = 0x0001;
export const V1_SIGNALING = 1;
export const V1_AUTHORIZATION = 1;
export const V1_TRANSPORT = 1;
export const V1_SECURITY_RANK = 100;

export const REGISTRY_DIGEST_DOMAIN = "flycockpit.remote.version-registry.v1\0";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type RemoteVersionErrorKind =
  | "length"
  | "preamble"
  | "discriminant"
  | "combination"
  | "invalid";

export class RemoteVersionError extends Error {
  readonly kind: RemoteVersionErrorKind;
  constructor(kind: RemoteVersionErrorKind, message: string) {
    super(message);
    this.name = "RemoteVersionError";
    this.kind = kind;
  }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export interface CriticalFeature {
  id: number;
  version: number;
}

export interface CompatibleTuple {
  tupleId: number;
  signaling: number;
  authorization: number;
  transport: number;
  /** Sourced from PROTOCOL_VERSION; never hardcoded. */
  application: number;
  securityRank: number;
  criticalFeatures: readonly CriticalFeature[];
}

/** The single code-enabled V1 tuple. Its `application` component is sourced
 * from PROTOCOL_VERSION at construction time. */
export function v1Tuple(): CompatibleTuple {
  return {
    tupleId: V1_TUPLE_ID,
    signaling: V1_SIGNALING,
    authorization: V1_AUTHORIZATION,
    transport: V1_TRANSPORT,
    application: PROTOCOL_VERSION,
    securityRank: V1_SECURITY_RANK,
    criticalFeatures: [],
  };
}

/** The enabled compatible-tuple registry: currently exactly one entry (V1). */
export function enabledRegistry(): CompatibleTuple[] {
  return [v1Tuple()];
}

/** Look up a tuple by ID in the enabled registry. */
export function registryTuple(tupleId: number): CompatibleTuple | undefined {
  return enabledRegistry().find((t) => t.tupleId === tupleId);
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

function validateTupleList(ids: readonly number[]): void {
  if (ids.length < TUPLE_LIST_MIN || ids.length > TUPLE_LIST_MAX) {
    throw new RemoteVersionError("length", "tuple list length out of range");
  }
  let previous = 0;
  for (const id of ids) {
    if (!Number.isInteger(id) || id < 0 || id > 0xffff) {
      throw new RemoteVersionError("invalid", "tuple id not u16");
    }
    if (id === 0) {
      throw new RemoteVersionError("invalid", "zero tuple id");
    }
    if (id <= previous) {
      throw new RemoteVersionError("combination", "tuple list not strictly ascending");
    }
    previous = id;
  }
}

function enabledIds(revoked: readonly number[]): number[] {
  return enabledRegistry()
    .filter((t) => !revoked.includes(t.tupleId))
    .map((t) => t.tupleId);
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

export interface SelectionInputs {
  client: readonly number[];
  daemon: readonly number[];
  /** Grant claim `compatibleTupleIds` — the server-allowed list. */
  serverAllowed: readonly number[];
  /** Revoked tuple IDs (policy revocation). */
  revoked: readonly number[];
}

export interface SelectedTuple {
  tupleId: number;
  securityRank: number;
  criticalFeatures: readonly CriticalFeature[];
}

/** Pure selection function over validated lists.
 *
 * Intersects client, daemon, server-allowed, registry-enabled, and nonrevoked
 * IDs; chooses highest securityRank, then lowest numeric tuple ID.
 * Returns `null` when no overlap exists (caller then builds the upgrade error
 * via `upgradeRequired`). */
export function select(inputs: SelectionInputs): SelectedTuple | null {
  validateTupleList(inputs.client);
  validateTupleList(inputs.daemon);
  validateTupleList(inputs.serverAllowed);
  if (inputs.revoked.some((id) => id === 0)) {
    throw new RemoteVersionError("invalid", "zero revoked tuple id");
  }

  const enabled = enabledIds(inputs.revoked);
  const registry = enabledRegistry();

  const candidates = inputs.client.filter(
    (id) => inputs.daemon.includes(id) && inputs.serverAllowed.includes(id) && enabled.includes(id),
  );

  if (candidates.length === 0) return null;

  // Choose highest security rank, then lowest tuple ID.
  let best: { id: number; rank: number } | null = null;
  for (const id of candidates) {
    const entry = registry.find((t) => t.tupleId === id);
    if (!entry) continue;
    if (
      best === null ||
      entry.securityRank > best.rank ||
      (entry.securityRank === best.rank && id < best.id)
    ) {
      best = { id, rank: entry.securityRank };
    }
  }
  if (!best) return null;

  const entry = registry.find((t) => t.tupleId === best!.id)!;
  return {
    tupleId: best.id,
    securityRank: best.rank,
    criticalFeatures: entry.criticalFeatures,
  };
}

// ---------------------------------------------------------------------------
// Upgrade-required error
// ---------------------------------------------------------------------------

export type UpgradeSide = "client" | "daemon" | "server_policy" | "multiple";

export interface UpgradeRequired {
  code: "remote_upgrade_required" | "remote_protocol_invalid";
  protocolVersion: number;
  upgradeSide: UpgradeSide;
  clientSupported: number[];
  daemonSupported: number[];
  serverAllowed: number[];
  recommendedTupleId: number | null;
}

/** The exact upgrade-required algorithm. See the prompt for the normative
 * specification. */
export function upgradeRequired(inputs: SelectionInputs): UpgradeRequired {
  validateTupleList(inputs.client);
  validateTupleList(inputs.daemon);
  validateTupleList(inputs.serverAllowed);
  if (inputs.revoked.some((id) => id === 0)) {
    throw new RemoteVersionError("invalid", "zero revoked tuple id");
  }

  const registry = enabledRegistry();
  const enabled = enabledIds(inputs.revoked);

  const rankOf = (id: number): number => registry.find((t) => t.tupleId === id)?.securityRank ?? 0;

  const bestIn = (ids: readonly number[]): number | null => {
    let best: number | null = null;
    for (const id of ids) {
      if (
        best === null ||
        rankOf(id) > rankOf(best) ||
        (rankOf(id) === rankOf(best) && id < best)
      ) {
        best = id;
      }
    }
    return best;
  };

  // P = client ∩ daemon ∩ E
  const p = inputs.client.filter((id) => inputs.daemon.includes(id) && enabled.includes(id));
  // S = server_allowed ∩ E
  const s = inputs.serverAllowed.filter((id) => enabled.includes(id));

  let upgradeSide: UpgradeSide;
  let recommended: number | null;

  if (p.length > 0 && p.every((id) => !inputs.serverAllowed.includes(id))) {
    upgradeSide = "server_policy";
    recommended = bestIn(p);
  } else if (s.length === 0) {
    upgradeSide = "server_policy";
    recommended = null;
  } else {
    // S nonempty: recommend by support count, then rank, then lowest ID.
    let best = s[0]!;
    for (const id of s) {
      const supportA = (inputs.client.includes(id) ? 1 : 0) + (inputs.daemon.includes(id) ? 1 : 0);
      const supportB =
        (inputs.client.includes(best) ? 1 : 0) + (inputs.daemon.includes(best) ? 1 : 0);
      if (
        supportA > supportB ||
        (supportA === supportB && rankOf(id) > rankOf(best)) ||
        (supportA === supportB && rankOf(id) === rankOf(best) && id < best)
      ) {
        best = id;
      }
    }
    const clientHas = inputs.client.includes(best);
    const daemonHas = inputs.daemon.includes(best);
    if (clientHas && daemonHas) {
      // Both contain it — normal selection would have succeeded.
      throw new RemoteVersionError("combination", "invariant: both endpoints have recommended");
    }
    if (!clientHas && daemonHas) {
      upgradeSide = "client";
    } else if (clientHas && !daemonHas) {
      upgradeSide = "daemon";
    } else {
      upgradeSide = "multiple";
    }
    recommended = best;
  }

  const filterSort = (ids: readonly number[]): number[] => {
    const out = Array.from(new Set(ids.filter((id) => enabled.includes(id))));
    out.sort((a, b) => a - b);
    return out;
  };

  return {
    code: "remote_upgrade_required",
    // Envelope/transcript protocol version class — never the application
    // constant. Disclosing PROTOCOL_VERSION would leak the daemon's
    // application version to an unauthenticated pre-negotiation peer (and
    // disagree with the Rust pair, which also emits 1).
    protocolVersion: TRANSCRIPT_VERSION,
    upgradeSide,
    clientSupported: filterSort(inputs.client),
    daemonSupported: filterSort(inputs.daemon),
    serverAllowed: filterSort(inputs.serverAllowed),
    recommendedTupleId: recommended,
  };
}

/** Non-enumerating invalid-input error. Returns a fixed shape with no
 * supported-set disclosure. */
export function invalidInputError(): UpgradeRequired {
  return {
    code: "remote_protocol_invalid",
    // Envelope/transcript protocol version class — never the application
    // constant.
    protocolVersion: TRANSCRIPT_VERSION,
    upgradeSide: "server_policy",
    clientSupported: [],
    daemonSupported: [],
    serverAllowed: [],
    recommendedTupleId: null,
  };
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

export interface RemoteNegotiationTranscriptV1 {
  transport: number;
  childAttemptId: Uint8Array;
  grantJti: Uint8Array;
  serverNonce: Uint8Array;
  clientNonce: Uint8Array;
  policyDigest: Uint8Array;
  clientTupleIds: number[];
  daemonTupleIds: number[];
  serverAllowedTupleIds: number[];
  selectedTupleId: number;
  criticalFeatures: CriticalFeature[];
}

function checkU16(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RemoteVersionError("invalid", "value not u16");
  }
}

function writeU16Be(out: number[], value: number): void {
  checkU16(value);
  out.push((value >> 8) & 0xff, value & 0xff);
}

function readU16Be(bytes: Uint8Array, offset: number): number {
  return (bytes[offset]! << 8) | bytes[offset + 1]!;
}

function readTupleList(bytes: Uint8Array, offset: number): { values: number[]; next: number } {
  const count = bytes[offset]!;
  if (count < TUPLE_LIST_MIN || count > TUPLE_LIST_MAX) {
    throw new RemoteVersionError("length", "tuple list count out of range");
  }
  const values: number[] = [];
  let pos = offset + 1;
  for (let i = 0; i < count; i++) {
    const value = readU16Be(bytes, pos);
    if (value === 0) {
      throw new RemoteVersionError("invalid", "zero tuple id");
    }
    if (values.length > 0 && value <= values[values.length - 1]!) {
      throw new RemoteVersionError("combination", "tuple list not strictly ascending");
    }
    values.push(value);
    pos += 2;
  }
  return { values, next: pos };
}

function readFeatureList(
  bytes: Uint8Array,
  offset: number,
): { features: CriticalFeature[]; next: number } {
  const count = bytes[offset]!;
  if (count > FEATURE_LIST_MAX) {
    throw new RemoteVersionError("length", "feature list count out of range");
  }
  const features: CriticalFeature[] = [];
  let pos = offset + 1;
  for (let i = 0; i < count; i++) {
    const id = readU16Be(bytes, pos);
    const version = readU16Be(bytes, pos + 2);
    if (id === 0) {
      throw new RemoteVersionError("invalid", "zero feature id");
    }
    if (features.length > 0 && id <= features[features.length - 1]!.id) {
      throw new RemoteVersionError("combination", "feature list not strictly ascending");
    }
    features.push({ id, version });
    pos += 4;
  }
  return { features, next: pos };
}

export function encodeTranscript(transcript: RemoteNegotiationTranscriptV1): Uint8Array {
  // Validate transport.
  if (
    transcript.transport !== TRANSPORT_WEBRTC &&
    transcript.transport !== TRANSPORT_WEBSOCKET_DATA
  ) {
    throw new RemoteVersionError("discriminant", "reserved transport");
  }
  validateTupleList(transcript.clientTupleIds);
  validateTupleList(transcript.daemonTupleIds);
  validateTupleList(transcript.serverAllowedTupleIds);
  if (transcript.selectedTupleId === 0) {
    throw new RemoteVersionError("invalid", "zero selected tuple id");
  }
  if (
    !transcript.clientTupleIds.includes(transcript.selectedTupleId) ||
    !transcript.daemonTupleIds.includes(transcript.selectedTupleId) ||
    !transcript.serverAllowedTupleIds.includes(transcript.selectedTupleId)
  ) {
    throw new RemoteVersionError("combination", "selected id absent from a list");
  }
  if (transcript.criticalFeatures.length > FEATURE_LIST_MAX) {
    throw new RemoteVersionError("length", "too many features");
  }
  for (let i = 1; i < transcript.criticalFeatures.length; i++) {
    if (transcript.criticalFeatures[i]!.id <= transcript.criticalFeatures[i - 1]!.id) {
      throw new RemoteVersionError("combination", "features not sorted");
    }
  }
  for (const f of transcript.criticalFeatures) {
    if (f.id === 0) {
      throw new RemoteVersionError("invalid", "zero feature id");
    }
  }

  // Check the selected tuple's features match the registry.
  const entry = registryTuple(transcript.selectedTupleId);
  if (!entry) {
    throw new RemoteVersionError("invalid", "selected tuple not in registry");
  }
  if (
    entry.criticalFeatures.length !== transcript.criticalFeatures.length ||
    !entry.criticalFeatures.every(
      (f, i) =>
        f.id === transcript.criticalFeatures[i]!.id &&
        f.version === transcript.criticalFeatures[i]!.version,
    )
  ) {
    throw new RemoteVersionError("combination", "feature mismatch with registry");
  }

  const total =
    TRANSCRIPT_FIXED_BYTES +
    transcript.clientTupleIds.length * 2 +
    transcript.daemonTupleIds.length * 2 +
    transcript.serverAllowedTupleIds.length * 2 +
    transcript.criticalFeatures.length * 4;
  if (total > TRANSCRIPT_MAX_BYTES) {
    throw new RemoteVersionError("length", "transcript exceeds max size");
  }

  const out: number[] = [];
  out.push(0x46, 0x43, 0x52, 0x4e); // "FCRN"
  out.push(TRANSCRIPT_VERSION);
  out.push(transcript.transport);
  if (transcript.childAttemptId.length !== 16) {
    throw new RemoteVersionError("length", "childAttemptId must be 16 bytes");
  }
  for (const b of transcript.childAttemptId) out.push(b);
  if (transcript.grantJti.length !== 16) {
    throw new RemoteVersionError("length", "grantJti must be 16 bytes");
  }
  for (const b of transcript.grantJti) out.push(b);
  if (transcript.serverNonce.length !== 32) {
    throw new RemoteVersionError("length", "serverNonce must be 32 bytes");
  }
  for (const b of transcript.serverNonce) out.push(b);
  if (transcript.clientNonce.length !== 32) {
    throw new RemoteVersionError("length", "clientNonce must be 32 bytes");
  }
  for (const b of transcript.clientNonce) out.push(b);
  if (transcript.policyDigest.length !== 32) {
    throw new RemoteVersionError("length", "policyDigest must be 32 bytes");
  }
  for (const b of transcript.policyDigest) out.push(b);

  out.push(transcript.clientTupleIds.length);
  for (const id of transcript.clientTupleIds) writeU16Be(out, id);
  out.push(transcript.daemonTupleIds.length);
  for (const id of transcript.daemonTupleIds) writeU16Be(out, id);
  out.push(transcript.serverAllowedTupleIds.length);
  for (const id of transcript.serverAllowedTupleIds) writeU16Be(out, id);

  writeU16Be(out, transcript.selectedTupleId);
  out.push(transcript.criticalFeatures.length);
  for (const f of transcript.criticalFeatures) {
    writeU16Be(out, f.id);
    writeU16Be(out, f.version);
  }

  if (out.length !== total) {
    throw new RemoteVersionError("length", "internal: encoded length mismatch");
  }
  return new Uint8Array(out);
}

export function decodeTranscript(bytes: Uint8Array): RemoteNegotiationTranscriptV1 {
  if (bytes.length < TRANSCRIPT_MIN_BYTES || bytes.length > TRANSCRIPT_MAX_BYTES) {
    throw new RemoteVersionError("length", "transcript length out of range");
  }
  if (bytes[0] !== 0x46 || bytes[1] !== 0x43 || bytes[2] !== 0x52 || bytes[3] !== 0x4e) {
    throw new RemoteVersionError("preamble", "bad magic");
  }
  let o = 4;
  if (bytes[o] !== TRANSCRIPT_VERSION) {
    throw new RemoteVersionError("preamble", "bad version");
  }
  o++;
  const transport = bytes[o]!;
  if (transport !== TRANSPORT_WEBRTC && transport !== TRANSPORT_WEBSOCKET_DATA) {
    throw new RemoteVersionError("discriminant", "reserved transport");
  }
  o++;

  const childAttemptId = bytes.slice(o, o + 16);
  o += 16;
  const grantJti = bytes.slice(o, o + 16);
  o += 16;
  const serverNonce = bytes.slice(o, o + 32);
  o += 32;
  const clientNonce = bytes.slice(o, o + 32);
  o += 32;
  const policyDigest = bytes.slice(o, o + 32);
  o += 32;

  const clientResult = readTupleList(bytes, o);
  o = clientResult.next;
  const daemonResult = readTupleList(bytes, o);
  o = daemonResult.next;
  const serverResult = readTupleList(bytes, o);
  o = serverResult.next;

  const selectedTupleId = readU16Be(bytes, o);
  o += 2;
  if (selectedTupleId === 0) {
    throw new RemoteVersionError("invalid", "zero selected tuple id");
  }
  if (
    !clientResult.values.includes(selectedTupleId) ||
    !daemonResult.values.includes(selectedTupleId) ||
    !serverResult.values.includes(selectedTupleId)
  ) {
    throw new RemoteVersionError("combination", "selected id absent from a list");
  }

  const featureResult = readFeatureList(bytes, o);
  o = featureResult.next;

  if (o !== bytes.length) {
    throw new RemoteVersionError("length", "trailing bytes");
  }

  // Selected tuple must be a known registry tuple.
  const entry = registryTuple(selectedTupleId);
  if (!entry) {
    throw new RemoteVersionError("invalid", "selected tuple not in registry");
  }
  if (
    entry.criticalFeatures.length !== featureResult.features.length ||
    !entry.criticalFeatures.every(
      (f, i) =>
        f.id === featureResult.features[i]!.id && f.version === featureResult.features[i]!.version,
    )
  ) {
    throw new RemoteVersionError("combination", "feature mismatch with registry");
  }

  // All tuple IDs must be known registry tuples.
  for (const id of [...clientResult.values, ...daemonResult.values, ...serverResult.values]) {
    if (!registryTuple(id)) {
      throw new RemoteVersionError("invalid", "unknown tuple id");
    }
  }

  return {
    transport,
    childAttemptId,
    grantJti,
    serverNonce,
    clientNonce,
    policyDigest,
    clientTupleIds: clientResult.values,
    daemonTupleIds: daemonResult.values,
    serverAllowedTupleIds: serverResult.values,
    selectedTupleId,
    criticalFeatures: featureResult.features,
  };
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/** SHA-256(transcriptBytes) — the only negotiation digest. */
export function transcriptDigest(bytes: Uint8Array): Uint8Array {
  // Validate first so we never digest malformed bytes.
  decodeTranscript(bytes);
  return createHash("sha256").update(bytes).digest();
}

/** Canonical enabled-registry digest.
 *
 * SHA-256(UTF8("flycockpit.remote.version-registry.v1\0") || count:u8 ||
 * per enabled tuple in ascending ID order: tupleId:u16be | signaling:u16be |
 * authorization:u16be | transport:u16be | application:u16be | securityRank:u16be
 * | featureCount:u8 | (featureId:u16be | featureVersion:u16be)*) */
export function enabledRegistryDigest(): Uint8Array {
  const registry = enabledRegistry()
    .slice()
    .sort((a, b) => a.tupleId - b.tupleId);
  const hash = createHash("sha256");
  hash.update(REGISTRY_DIGEST_DOMAIN, "utf8");
  hash.update(Buffer.from([registry.length]));
  for (const tuple of registry) {
    const buf = Buffer.alloc(12 + 1);
    buf.writeUInt16BE(tuple.tupleId, 0);
    buf.writeUInt16BE(tuple.signaling, 2);
    buf.writeUInt16BE(tuple.authorization, 4);
    buf.writeUInt16BE(tuple.transport, 6);
    buf.writeUInt16BE(tuple.application, 8);
    buf.writeUInt16BE(tuple.securityRank, 10);
    buf.writeUInt8(tuple.criticalFeatures.length, 12);
    hash.update(buf);
    for (const f of tuple.criticalFeatures) {
      const fbuf = Buffer.alloc(4);
      fbuf.writeUInt16BE(f.id, 0);
      fbuf.writeUInt16BE(f.version, 2);
      hash.update(fbuf);
    }
  }
  return new Uint8Array(hash.digest());
}

/** Verify that a proof/prologue `negotiationDigest` matches the locally
 * reconstructed transcript. Both endpoints reconstruct the transcript locally
 * and reject a proof whose digest differs. */
export function verifyTranscriptDigest(
  transcriptBytes: Uint8Array,
  expectedDigest: Uint8Array,
): void {
  const computed = transcriptDigest(transcriptBytes);
  if (computed.length !== expectedDigest.length) {
    throw new RemoteVersionError("combination", "digest length mismatch");
  }
  for (let i = 0; i < computed.length; i++) {
    if (computed[i] !== expectedDigest[i]) {
      throw new RemoteVersionError("combination", "digest mismatch");
    }
  }
}
