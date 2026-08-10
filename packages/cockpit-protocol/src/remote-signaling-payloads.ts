import { remoteIdentitySha256Sync } from "./remote-identity-protocol";

export class RemoteSignalingPayloadError extends Error {}
const te = new TextEncoder();
const fail = (message: string): never => {
  throw new RemoteSignalingPayloadError(message);
};
const id16 = (value: Uint8Array, name: string) => {
  if (value.length !== 16 || value.every((byte) => byte === 0))
    fail(`${name} must be nonzero 16 bytes`);
};
class Writer {
  parts: Uint8Array[] = [];
  put(value: Uint8Array) {
    this.parts.push(value);
  }
  u8(value: number) {
    this.put(Uint8Array.of(value));
  }
  u16(value: number) {
    const out = new Uint8Array(2);
    new DataView(out.buffer).setUint16(0, value);
    this.put(out);
  }
  u64(value: bigint) {
    if (value < 0n || value > 0xffffffffffffffffn) fail("u64 range");
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, value);
    this.put(out);
  }
  i64(value: bigint) {
    if (value < -0x8000000000000000n || value > 0x7fffffffffffffffn) fail("i64 range");
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigInt64(0, value);
    this.put(out);
  }
  done() {
    const size = this.parts.reduce((sum, part) => sum + part.length, 0),
      out = new Uint8Array(size);
    let offset = 0;
    for (const part of this.parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }
}
class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  take(size: number) {
    if (size < 0 || this.offset + size > this.bytes.length) fail("truncated payload");
    const value = this.bytes.slice(this.offset, this.offset + size);
    this.offset += size;
    return value;
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
const preamble = (writer: Writer, magic: string) => {
  writer.put(te.encode(magic));
  writer.u8(1);
};
const readPreamble = (reader: Reader, magic: string) => {
  if (String.fromCharCode(...reader.take(4)) !== magic || reader.u8() !== 1)
    fail(`wrong ${magic} magic/version`);
};
const counted = (writer: Writer, value: Uint8Array, cap: number, name: string) => {
  if (!value.length || value.length > cap) fail(`${name} length`);
  writer.u16(value.length);
  writer.put(value);
};
const readCounted = (reader: Reader, cap: number, name: string) => {
  const length = reader.u16();
  if (!length || length > cap) fail(`${name} length`);
  return reader.take(length);
};

export interface RemoteChildAuthenticationBundleV1 {
  childAttemptId: Uint8Array;
  grantJws: Uint8Array;
  clientCertificateJws: Uint8Array;
  daemonCertificateJws: Uint8Array;
  authorityStatusJws: Uint8Array;
  servicePolicyJws: Uint8Array;
  tenantStatementJws?: Uint8Array;
}
export function encodeRemoteChildAuthenticationBundleV1(value: RemoteChildAuthenticationBundleV1) {
  id16(value.childAttemptId, "childAttemptId");
  const w = new Writer();
  preamble(w, "FCAB");
  w.put(value.childAttemptId);
  counted(w, value.grantJws, 8192, "grant");
  counted(w, value.clientCertificateJws, 4096, "client certificate");
  counted(w, value.daemonCertificateJws, 4096, "daemon certificate");
  counted(w, value.authorityStatusJws, 16384, "authority status");
  counted(w, value.servicePolicyJws, 16384, "service policy");
  w.u8(value.tenantStatementJws ? 1 : 0);
  if (value.tenantStatementJws) counted(w, value.tenantStatementJws, 16384, "tenant statement");
  const out = w.done();
  if (out.length > 98304) fail("FCAB cap");
  return out;
}
export function decodeRemoteChildAuthenticationBundleV1(
  bytes: Uint8Array,
): RemoteChildAuthenticationBundleV1 {
  if (bytes.length > 98304) fail("FCAB cap");
  const r = new Reader(bytes);
  readPreamble(r, "FCAB");
  const childAttemptId = r.take(16);
  id16(childAttemptId, "childAttemptId");
  const value = {
    childAttemptId,
    grantJws: readCounted(r, 8192, "grant"),
    clientCertificateJws: readCounted(r, 4096, "client certificate"),
    daemonCertificateJws: readCounted(r, 4096, "daemon certificate"),
    authorityStatusJws: readCounted(r, 16384, "authority status"),
    servicePolicyJws: readCounted(r, 16384, "service policy"),
    tenantStatementJws: undefined as Uint8Array | undefined,
  };
  const present = r.u8();
  if (present > 1) fail("tenant presence");
  if (present) value.tenantStatementJws = readCounted(r, 16384, "tenant statement");
  r.finish();
  return value;
}
export function remoteChildAuthenticationDigests(bytes: Uint8Array) {
  const bundle = decodeRemoteChildAuthenticationBundleV1(bytes);
  return {
    grantDigest: remoteIdentitySha256Sync(bundle.grantJws),
    authBundleDigest: remoteIdentitySha256Sync(bytes),
  };
}

const tupleList = (writer: Writer, tuples: readonly number[]) => {
  if (tuples.length < 1 || tuples.length > 16) fail("tuple count");
  writer.u8(tuples.length);
  let prior = -1;
  for (const tuple of tuples) {
    if (!Number.isInteger(tuple) || tuple < 0 || tuple > 0xffff || tuple <= prior)
      fail("tuples must be strictly increasing u16 values");
    writer.u16(tuple);
    prior = tuple;
  }
};
const readTupleList = (reader: Reader) => {
  const count = reader.u8();
  if (count < 1 || count > 16) fail("tuple count");
  const tuples: number[] = [];
  for (let i = 0; i < count; i++) {
    const tuple = reader.u16();
    if (i && tuple <= tuples[i - 1]!) fail("tuples must be strictly increasing");
    tuples.push(tuple);
  }
  return tuples;
};
const signedEnvelope = (
  body: Uint8Array,
  signature: Uint8Array,
  bodyCap: number,
  totalCap: number,
) => {
  if (body.length > bodyCap || signature.length !== 64) fail("signed envelope cap/signature");
  const writer = new Writer();
  writer.u16(body.length);
  writer.put(body);
  writer.put(signature);
  const out = writer.done();
  if (out.length > totalCap) fail("signed envelope cap");
  return out;
};
const readSignedEnvelope = (bytes: Uint8Array, bodyCap: number, totalCap: number) => {
  if (bytes.length > totalCap || bytes.length < 66) fail("signed envelope length");
  const reader = new Reader(bytes),
    bodyLength = reader.u16();
  if (bodyLength > bodyCap || bodyLength + 66 !== bytes.length) fail("signed body length");
  const body = reader.take(bodyLength),
    signature = reader.take(64);
  reader.finish();
  return { body, signature };
};

export interface DaemonAdmissionOfferV1 {
  instanceId: Uint8Array;
  daemonDeviceId: Uint8Array;
  daemonDeviceGeneration: bigint;
  daemonCertificateId: Uint8Array;
  daemonCertificateGeneration: bigint;
  logicalAttachmentId: Uint8Array;
  childAttemptId: Uint8Array;
  grantJti: Uint8Array;
  grantDigest: Uint8Array;
  serverNonce: Uint8Array;
  serviceVersion: bigint;
  policyEpoch: bigint;
  policyDigest: Uint8Array;
  tenantAuthorizationDigest?: Uint8Array;
  authorizedTransportBits: number;
  daemonTupleIds: readonly number[];
  offerJti: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
  signature: Uint8Array;
}
export function encodeDaemonAdmissionOfferV1(value: DaemonAdmissionOfferV1) {
  for (const [name, id] of [
    ["instanceId", value.instanceId],
    ["daemonDeviceId", value.daemonDeviceId],
    ["daemonCertificateId", value.daemonCertificateId],
    ["logicalAttachmentId", value.logicalAttachmentId],
    ["childAttemptId", value.childAttemptId],
    ["grantJti", value.grantJti],
    ["offerJti", value.offerJti],
  ] as const)
    id16(id, name);
  if (
    !value.daemonDeviceGeneration ||
    !value.daemonCertificateGeneration ||
    !value.serviceVersion ||
    !value.policyEpoch ||
    value.grantDigest.length !== 32 ||
    value.serverNonce.length !== 32 ||
    value.policyDigest.length !== 32 ||
    (value.tenantAuthorizationDigest && value.tenantAuthorizationDigest.length !== 32) ||
    value.authorizedTransportBits < 1 ||
    value.authorizedTransportBits > 3 ||
    value.issuedAt >= value.expiresAt
  )
    fail("FCDO field");
  const w = new Writer();
  preamble(w, "FCDO");
  w.put(value.instanceId);
  w.put(value.daemonDeviceId);
  w.u64(value.daemonDeviceGeneration);
  w.put(value.daemonCertificateId);
  w.u64(value.daemonCertificateGeneration);
  w.put(value.logicalAttachmentId);
  w.put(value.childAttemptId);
  w.put(value.grantJti);
  w.put(value.grantDigest);
  w.put(value.serverNonce);
  w.u64(value.serviceVersion);
  w.u64(value.policyEpoch);
  w.put(value.policyDigest);
  w.u8(value.tenantAuthorizationDigest ? 1 : 0);
  if (value.tenantAuthorizationDigest) w.put(value.tenantAuthorizationDigest);
  w.u8(value.authorizedTransportBits);
  tupleList(w, value.daemonTupleIds);
  w.put(value.offerJti);
  w.i64(value.issuedAt);
  w.i64(value.expiresAt);
  return signedEnvelope(w.done(), value.signature, 328, 394);
}
export function decodeDaemonAdmissionOfferV1(bytes: Uint8Array): DaemonAdmissionOfferV1 {
  const { body, signature } = readSignedEnvelope(bytes, 328, 394),
    r = new Reader(body);
  readPreamble(r, "FCDO");
  const instanceId = r.take(16),
    daemonDeviceId = r.take(16),
    daemonDeviceGeneration = r.u64(),
    daemonCertificateId = r.take(16),
    daemonCertificateGeneration = r.u64(),
    logicalAttachmentId = r.take(16),
    childAttemptId = r.take(16),
    grantJti = r.take(16),
    grantDigest = r.take(32),
    serverNonce = r.take(32),
    serviceVersion = r.u64(),
    policyEpoch = r.u64(),
    policyDigest = r.take(32);
  const present = r.u8();
  if (present > 1) fail("tenant presence");
  const tenantAuthorizationDigest = present ? r.take(32) : undefined,
    authorizedTransportBits = r.u8();
  if (authorizedTransportBits < 1 || authorizedTransportBits > 3) fail("transport bits");
  const daemonTupleIds = readTupleList(r),
    offerJti = r.take(16),
    issuedAt = r.i64(),
    expiresAt = r.i64();
  r.finish();
  const value = {
    instanceId,
    daemonDeviceId,
    daemonDeviceGeneration,
    daemonCertificateId,
    daemonCertificateGeneration,
    logicalAttachmentId,
    childAttemptId,
    grantJti,
    grantDigest,
    serverNonce,
    serviceVersion,
    policyEpoch,
    policyDigest,
    tenantAuthorizationDigest,
    authorizedTransportBits,
    daemonTupleIds,
    offerJti,
    issuedAt,
    expiresAt,
    signature,
  };
  encodeDaemonAdmissionOfferV1(value);
  return value;
}
/** Digest authority is the exact complete length-prefixed signed FCDO envelope. */
export function daemonAdmissionOfferDigest(bytes: Uint8Array) {
  decodeDaemonAdmissionOfferV1(bytes);
  return remoteIdentitySha256Sync(bytes);
}

export interface ClientAdmissionProofV1 {
  tenantId: Uint8Array;
  accountId: Uint8Array;
  clientDeviceId: Uint8Array;
  clientDeviceGeneration: bigint;
  clientCertificateId: Uint8Array;
  clientCertificateGeneration: bigint;
  logicalAttachmentId: Uint8Array;
  childAttemptId: Uint8Array;
  grantJti: Uint8Array;
  grantDigest: Uint8Array;
  daemonOfferDigest: Uint8Array;
  daemonOfferJti: Uint8Array;
  chosenTransport: 1 | 2;
  clientTupleIds: readonly number[];
  daemonTupleIds: readonly number[];
  selectedTupleId: number;
  policyDigest: Uint8Array;
  tenantAuthorizationDigest?: Uint8Array;
  serverNonce: Uint8Array;
  clientNonce: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
  proofJti: Uint8Array;
  signature: Uint8Array;
}
export function encodeClientAdmissionProofV1(value: ClientAdmissionProofV1) {
  for (const [name, id] of [
    ["tenantId", value.tenantId],
    ["accountId", value.accountId],
    ["clientDeviceId", value.clientDeviceId],
    ["clientCertificateId", value.clientCertificateId],
    ["logicalAttachmentId", value.logicalAttachmentId],
    ["childAttemptId", value.childAttemptId],
    ["grantJti", value.grantJti],
    ["daemonOfferJti", value.daemonOfferJti],
    ["proofJti", value.proofJti],
  ] as const)
    id16(id, name);
  if (
    !value.clientDeviceGeneration ||
    !value.clientCertificateGeneration ||
    ![1, 2].includes(value.chosenTransport) ||
    value.grantDigest.length !== 32 ||
    value.daemonOfferDigest.length !== 32 ||
    value.policyDigest.length !== 32 ||
    value.serverNonce.length !== 32 ||
    value.clientNonce.length !== 32 ||
    (value.tenantAuthorizationDigest && value.tenantAuthorizationDigest.length !== 32) ||
    !value.clientTupleIds.includes(value.selectedTupleId) ||
    !value.daemonTupleIds.includes(value.selectedTupleId) ||
    value.issuedAt >= value.expiresAt
  )
    fail("FCCP field");
  const w = new Writer();
  preamble(w, "FCCP");
  w.put(value.tenantId);
  w.put(value.accountId);
  w.put(value.clientDeviceId);
  w.u64(value.clientDeviceGeneration);
  w.put(value.clientCertificateId);
  w.u64(value.clientCertificateGeneration);
  w.put(value.logicalAttachmentId);
  w.put(value.childAttemptId);
  w.put(value.grantJti);
  w.put(value.grantDigest);
  w.put(value.daemonOfferDigest);
  w.put(value.daemonOfferJti);
  w.u8(value.chosenTransport);
  tupleList(w, value.clientTupleIds);
  tupleList(w, value.daemonTupleIds);
  w.u16(value.selectedTupleId);
  w.put(value.policyDigest);
  w.u8(value.tenantAuthorizationDigest ? 1 : 0);
  if (value.tenantAuthorizationDigest) w.put(value.tenantAuthorizationDigest);
  w.put(value.serverNonce);
  w.put(value.clientNonce);
  w.i64(value.issuedAt);
  w.i64(value.expiresAt);
  w.put(value.proofJti);
  return signedEnvelope(w.done(), value.signature, 443, 509);
}
export function decodeClientAdmissionProofV1(bytes: Uint8Array): ClientAdmissionProofV1 {
  const { body, signature } = readSignedEnvelope(bytes, 443, 509),
    r = new Reader(body);
  readPreamble(r, "FCCP");
  const tenantId = r.take(16),
    accountId = r.take(16),
    clientDeviceId = r.take(16),
    clientDeviceGeneration = r.u64(),
    clientCertificateId = r.take(16),
    clientCertificateGeneration = r.u64(),
    logicalAttachmentId = r.take(16),
    childAttemptId = r.take(16),
    grantJti = r.take(16),
    grantDigest = r.take(32),
    daemonOfferDigest = r.take(32),
    daemonOfferJti = r.take(16),
    chosenTransport = r.u8() as 1 | 2,
    clientTupleIds = readTupleList(r),
    daemonTupleIds = readTupleList(r),
    selectedTupleId = r.u16(),
    policyDigest = r.take(32),
    present = r.u8();
  if (present > 1) fail("tenant presence");
  const tenantAuthorizationDigest = present ? r.take(32) : undefined,
    serverNonce = r.take(32),
    clientNonce = r.take(32),
    issuedAt = r.i64(),
    expiresAt = r.i64(),
    proofJti = r.take(16);
  r.finish();
  const value = {
    tenantId,
    accountId,
    clientDeviceId,
    clientDeviceGeneration,
    clientCertificateId,
    clientCertificateGeneration,
    logicalAttachmentId,
    childAttemptId,
    grantJti,
    grantDigest,
    daemonOfferDigest,
    daemonOfferJti,
    chosenTransport,
    clientTupleIds,
    daemonTupleIds,
    selectedTupleId,
    policyDigest,
    tenantAuthorizationDigest,
    serverNonce,
    clientNonce,
    issuedAt,
    expiresAt,
    proofJti,
    signature,
  };
  encodeClientAdmissionProofV1(value);
  return value;
}

export interface RemoteFallbackPairAuthenticatedV1 {
  pairId: Uint8Array;
  pairGeneration: bigint;
  routeGeneration: bigint;
  clientSocketGeneration: bigint;
  daemonSocketGeneration: bigint;
  admissionSequence: bigint;
  pairAuthorizationDigest: Uint8Array;
}
export function encodeRemoteFallbackPairAuthenticatedV1(value: RemoteFallbackPairAuthenticatedV1) {
  id16(value.pairId, "pairId");
  if (
    !value.pairGeneration ||
    !value.routeGeneration ||
    !value.clientSocketGeneration ||
    !value.daemonSocketGeneration ||
    !value.admissionSequence
  )
    fail("zero fallback generation");
  if (value.pairAuthorizationDigest.length !== 32) fail("pair authorization digest");
  const w = new Writer();
  w.put(value.pairId);
  w.u64(value.pairGeneration);
  w.u64(value.routeGeneration);
  w.u64(value.clientSocketGeneration);
  w.u64(value.daemonSocketGeneration);
  w.u64(value.admissionSequence);
  w.put(value.pairAuthorizationDigest);
  return w.done();
}
export function decodeRemoteFallbackPairAuthenticatedV1(
  bytes: Uint8Array,
): RemoteFallbackPairAuthenticatedV1 {
  if (bytes.length !== 88) fail("fallback pair length");
  const r = new Reader(bytes),
    pairId = r.take(16);
  id16(pairId, "pairId");
  const value = {
    pairId,
    pairGeneration: r.u64(),
    routeGeneration: r.u64(),
    clientSocketGeneration: r.u64(),
    daemonSocketGeneration: r.u64(),
    admissionSequence: r.u64(),
    pairAuthorizationDigest: r.take(32),
  };
  if (
    !value.pairGeneration ||
    !value.routeGeneration ||
    !value.clientSocketGeneration ||
    !value.daemonSocketGeneration ||
    !value.admissionSequence
  )
    fail("zero fallback generation");
  r.finish();
  return value;
}
export interface RemoteFallbackNoiseCompleteV1 {
  role: 1 | 2;
  pairId: Uint8Array;
  socketGeneration: bigint;
  noiseHandshakeHash: Uint8Array;
  prologueDigest: Uint8Array;
  connectionNonce: Uint8Array;
}
export function encodeRemoteFallbackNoiseCompleteV1(value: RemoteFallbackNoiseCompleteV1) {
  if (value.role !== 1 && value.role !== 2) fail("Noise role");
  id16(value.pairId, "pairId");
  if (!value.socketGeneration) fail("zero socket generation");
  if (
    value.noiseHandshakeHash.length !== 32 ||
    value.prologueDigest.length !== 32 ||
    value.connectionNonce.length !== 32
  )
    fail("Noise digest width");
  const w = new Writer();
  w.u8(value.role);
  w.put(value.pairId);
  w.u64(value.socketGeneration);
  w.put(value.noiseHandshakeHash);
  w.put(value.prologueDigest);
  w.put(value.connectionNonce);
  return w.done();
}
export function decodeRemoteFallbackNoiseCompleteV1(
  bytes: Uint8Array,
): RemoteFallbackNoiseCompleteV1 {
  if (bytes.length !== 121) fail("Noise length");
  const r = new Reader(bytes),
    role = r.u8() as 1 | 2;
  if (role !== 1 && role !== 2) fail("Noise role");
  const pairId = r.take(16);
  id16(pairId, "pairId");
  const value = {
    role,
    pairId,
    socketGeneration: r.u64(),
    noiseHandshakeHash: r.take(32),
    prologueDigest: r.take(32),
    connectionNonce: r.take(32),
  };
  if (!value.socketGeneration) fail("zero socket generation");
  r.finish();
  return value;
}

export interface RemoteEndpointFinalProofV1 {
  role: 1 | 2;
  transport: 1 | 2;
  childAttemptId: Uint8Array;
  transportEpoch: Uint8Array;
  admissionSequence: bigint;
  grantDigest: Uint8Array;
  negotiationDigest: Uint8Array;
  binding: Uint8Array;
  proofJti: Uint8Array;
  certificateId: Uint8Array;
  certificateGeneration: bigint;
  signature: Uint8Array;
}
export function encodeRemoteEndpointFinalProofV1(value: RemoteEndpointFinalProofV1) {
  if (![1, 2].includes(value.role) || ![1, 2].includes(value.transport)) fail("FCFP enum");
  id16(value.childAttemptId, "childAttemptId");
  id16(value.transportEpoch, "transportEpoch");
  id16(value.proofJti, "proofJti");
  id16(value.certificateId, "certificateId");
  if (
    value.grantDigest.length !== 32 ||
    value.negotiationDigest.length !== 32 ||
    value.binding.length !== 96 ||
    value.signature.length !== 64 ||
    !value.admissionSequence ||
    !value.certificateGeneration
  )
    fail("FCFP field width");
  const w = new Writer();
  preamble(w, "FCFP");
  w.u8(value.role);
  w.u8(value.transport);
  w.put(value.childAttemptId);
  w.put(value.transportEpoch);
  w.u64(value.admissionSequence);
  w.put(value.grantDigest);
  w.put(value.negotiationDigest);
  w.u16(value.binding.length);
  w.put(value.binding);
  w.put(value.proofJti);
  w.put(value.certificateId);
  w.u64(value.certificateGeneration);
  w.put(value.signature);
  const out = w.done();
  if (out.length > 512) fail("FCFP cap");
  return out;
}
export function decodeRemoteEndpointFinalProofV1(bytes: Uint8Array): RemoteEndpointFinalProofV1 {
  if (bytes.length > 512) fail("FCFP cap");
  const r = new Reader(bytes);
  readPreamble(r, "FCFP");
  const role = r.u8() as 1 | 2,
    transport = r.u8() as 1 | 2;
  if (![1, 2].includes(role) || ![1, 2].includes(transport)) fail("FCFP enum");
  const childAttemptId = r.take(16),
    transportEpoch = r.take(16);
  id16(childAttemptId, "childAttemptId");
  id16(transportEpoch, "transportEpoch");
  const admissionSequence = r.u64(),
    grantDigest = r.take(32),
    negotiationDigest = r.take(32),
    binding = readCounted(r, 96, "binding"),
    proofJti = r.take(16),
    certificateId = r.take(16),
    certificateGeneration = r.u64(),
    signature = r.take(64);
  id16(proofJti, "proofJti");
  id16(certificateId, "certificateId");
  if (!admissionSequence || !certificateGeneration || binding.length !== 96) fail("FCFP field");
  r.finish();
  return {
    role,
    transport,
    childAttemptId,
    transportEpoch,
    admissionSequence,
    grantDigest,
    negotiationDigest,
    binding,
    proofJti,
    certificateId,
    certificateGeneration,
    signature,
  };
}
export function remoteEndpointFinalProofAgreementBytes(value: RemoteEndpointFinalProofV1) {
  const w = new Writer();
  w.u8(value.transport);
  w.put(value.childAttemptId);
  w.put(value.transportEpoch);
  w.u64(value.admissionSequence);
  w.put(value.grantDigest);
  w.put(value.negotiationDigest);
  w.put(value.binding);
  return w.done();
}

export interface RemoteSignalingReadyV1 {
  verifiedPeerProofJti: Uint8Array;
  finalProofSetDigest: Uint8Array;
}
export function encodeRemoteSignalingReadyV1(value: RemoteSignalingReadyV1) {
  id16(value.verifiedPeerProofJti, "verifiedPeerProofJti");
  if (value.finalProofSetDigest.length !== 32) fail("proof set digest");
  const out = new Uint8Array(48);
  out.set(value.verifiedPeerProofJti);
  out.set(value.finalProofSetDigest, 16);
  return out;
}
export function decodeRemoteSignalingReadyV1(bytes: Uint8Array): RemoteSignalingReadyV1 {
  if (bytes.length !== 48) fail("ready length");
  const verifiedPeerProofJti = bytes.slice(0, 16);
  id16(verifiedPeerProofJti, "verifiedPeerProofJti");
  return { verifiedPeerProofJti, finalProofSetDigest: bytes.slice(16) };
}
