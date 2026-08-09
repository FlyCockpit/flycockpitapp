import type {
  RemoteAdminApprovalEvidenceV1,
  RemoteCredentialRegistryEntryV1,
} from "@flycockpit/cockpit-protocol";

export const REMOTE_ADMIN_CEREMONY_TTL_MS = 5 * 60 * 1000;
export const REMOTE_ADMIN_APPROVAL_TTL_MS = 15 * 60 * 1000;
const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_N = P256_N >> 1n;
const text = new TextEncoder();
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const equal = (left: Uint8Array, right: Uint8Array) =>
  left.length === right.length && left.every((value, index) => value === right[index]);
const webCryptoBytes = (value: Uint8Array): Uint8Array<ArrayBuffer> => {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
};

export type WebAuthnPolicy = { rpId: string; origin: string };
export type AssertionInput = {
  credentialIdHash: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  signatureDer: Uint8Array;
};

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", webCryptoBytes(value)));
}
function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function unsignedInteger(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0 || (bytes[0]! & 0x80) !== 0) throw new Error("webauthn_der_negative");
  if (bytes.length > 1 && bytes[0] === 0 && (bytes[1]! & 0x80) === 0)
    throw new Error("webauthn_der_noncanonical");
  const value = bytes[0] === 0 ? bytes.slice(1) : bytes;
  if (value.length > 32) throw new Error("webauthn_der_integer_too_large");
  return value;
}
function bigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) result = (result << 8n) | BigInt(byte);
  return result;
}
export function normalizeCanonicalLowSDerSignature(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2 || der[2] !== 0x02)
    throw new Error("webauthn_der_invalid");
  const rLength = der[3]!;
  const rEnd = 4 + rLength;
  if (rEnd + 2 > der.length || der[rEnd] !== 0x02) throw new Error("webauthn_der_invalid");
  const sLength = der[rEnd + 1]!;
  if (rEnd + 2 + sLength !== der.length) throw new Error("webauthn_der_invalid");
  const r = unsignedInteger(der.slice(4, rEnd));
  const s = unsignedInteger(der.slice(rEnd + 2));
  const rNumber = bigint(r),
    sNumber = bigint(s);
  if (rNumber === 0n || rNumber >= P256_N || sNumber === 0n || sNumber > P256_HALF_N)
    throw new Error("webauthn_signature_not_canonical_low_s");
  const result = new Uint8Array(64);
  result.set(r, 32 - r.length);
  result.set(s, 64 - s.length);
  return result;
}

function strictClientData(bytes: Uint8Array): { type: string; challenge: string; origin: string } {
  const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  // JSON.parse is last-member-wins. Scan top-level keys and decode escapes
  // before comparison without rejecting names reused inside nested values.
  const keys: string[] = [];
  let depth = 0;
  for (let index = 0; index < source.length; index++) {
    const character = source[index]!;
    if (character === '"') {
      const start = index;
      for (index += 1; index < source.length; index++) {
        if (source[index] === "\\") index += 1;
        else if (source[index] === '"') break;
      }
      if (index >= source.length) throw new Error("webauthn_client_data_invalid");
      if (depth === 1) {
        let next = index + 1;
        while (/\s/.test(source[next] ?? "")) next += 1;
        if (source[next] === ":") keys.push(JSON.parse(source.slice(start, index + 1)));
      }
      continue;
    }
    if (character === "{") depth += 1;
    else if (character === "}") depth -= 1;
  }
  if (new Set(keys).size !== keys.length) throw new Error("webauthn_client_data_duplicate_member");
  const value: unknown = JSON.parse(source);
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("webauthn_client_data_invalid");
  const record = value as Record<string, unknown>;
  if (
    typeof record.type !== "string" ||
    typeof record.challenge !== "string" ||
    typeof record.origin !== "string"
  )
    throw new Error("webauthn_client_data_invalid");
  if (record.crossOrigin === true) throw new Error("webauthn_cross_origin_rejected");
  return { type: record.type, challenge: record.challenge, origin: record.origin };
}

function readCborInteger(bytes: Uint8Array, offset: { value: number }): number {
  const initial = bytes[offset.value++]!;
  const major = initial >> 5;
  const additional = initial & 31;
  let value: number;
  if (additional < 24) value = additional;
  else if (additional === 24) value = bytes[offset.value++]!;
  else throw new Error("webauthn_cose_noncanonical");
  if (major === 0) return value;
  if (major === 1) return -1 - value;
  throw new Error("webauthn_cose_integer_required");
}
function readCborBytes(bytes: Uint8Array, offset: { value: number }): Uint8Array {
  const initial = bytes[offset.value++]!;
  if (initial >> 5 !== 2) throw new Error("webauthn_cose_bytes_required");
  const additional = initial & 31;
  const length = additional < 24 ? additional : additional === 24 ? bytes[offset.value++]! : -1;
  if (length < 24 || offset.value + length > bytes.length)
    throw new Error("webauthn_cose_noncanonical");
  const value = bytes.slice(offset.value, offset.value + length);
  offset.value += length;
  return value;
}
export async function verifyRemoteAdminRegistration(input: {
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  rawCredentialId: Uint8Array;
  expectedChallenge: Uint8Array;
  policy: WebAuthnPolicy;
  expectedP256X: Uint8Array;
  expectedP256Y: Uint8Array;
}) {
  const data = input.authenticatorData;
  if (data.length < 55 || !equal(data.slice(0, 32), await sha256(text.encode(input.policy.rpId))))
    throw new Error("webauthn_registration_rp_id_mismatch");
  if ((data[32]! & 0x45) !== 0x45) throw new Error("webauthn_registration_uv_at_required");
  const client = strictClientData(input.clientDataJson);
  if (
    client.type !== "webauthn.create" ||
    client.origin !== input.policy.origin ||
    client.challenge !== b64url(input.expectedChallenge)
  )
    throw new Error("webauthn_registration_client_data_mismatch");
  const credentialLength = new DataView(data.buffer, data.byteOffset + 53, 2).getUint16(0);
  const credentialStart = 55;
  const credentialEnd = credentialStart + credentialLength;
  if (
    credentialLength < 1 ||
    credentialEnd >= data.length ||
    !equal(data.slice(credentialStart, credentialEnd), input.rawCredentialId)
  )
    throw new Error("webauthn_registration_credential_mismatch");
  const offset = { value: credentialEnd };
  const map = data[offset.value++]!;
  if (map >> 5 !== 5 || (map & 31) !== 5) throw new Error("webauthn_cose_map_invalid");
  const values = new Map<number, number | Uint8Array>();
  for (let index = 0; index < 5; index++) {
    const key = readCborInteger(data, offset);
    if (values.has(key)) throw new Error("webauthn_cose_duplicate_member");
    values.set(
      key,
      key === -2 || key === -3 ? readCborBytes(data, offset) : readCborInteger(data, offset),
    );
  }
  if (
    values.get(1) !== 2 ||
    values.get(3) !== -7 ||
    values.get(-1) !== 1 ||
    !equal(values.get(-2) as Uint8Array, input.expectedP256X) ||
    !equal(values.get(-3) as Uint8Array, input.expectedP256Y) ||
    offset.value !== data.length
  )
    throw new Error("webauthn_registration_cose_invalid");
}

export async function approvalChallenge(canonicalOperationBytes: Uint8Array, nonce32: Uint8Array) {
  if (nonce32.length !== 32) throw new Error("remote_admin_nonce_length");
  return sha256(
    concat(text.encode("flycockpit-remote-admin-approval-v1\0"), canonicalOperationBytes, nonce32),
  );
}

export async function verifyRemoteAdminAssertion(input: {
  assertion: AssertionInput;
  credential: RemoteCredentialRegistryEntryV1;
  policy: WebAuthnPolicy;
  expectedChallenge: Uint8Array;
}): Promise<{ signatureP1363: Uint8Array; signCount: number }> {
  const { assertion, credential, policy } = input;
  if (!equal(assertion.credentialIdHash, credential.credentialIdHash) || credential.state !== 1)
    throw new Error("remote_admin_credential_not_active");
  if (assertion.authenticatorData.length < 37 || assertion.authenticatorData.length > 1024)
    throw new Error("webauthn_authenticator_data_length");
  const rpHash = assertion.authenticatorData.slice(0, 32);
  if (!equal(rpHash, await sha256(text.encode(policy.rpId))))
    throw new Error("webauthn_rp_id_mismatch");
  const flags = assertion.authenticatorData[32]!;
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0)
    throw new Error("webauthn_user_verification_required");
  if (credential.declaredCustody === 2 && (flags & 0x08) !== 0)
    throw new Error("webauthn_external_key_custody_conflict");
  const client = strictClientData(assertion.clientDataJson);
  if (
    client.type !== "webauthn.get" ||
    client.origin !== policy.origin ||
    client.challenge !== b64url(input.expectedChallenge)
  )
    throw new Error("webauthn_client_data_mismatch");
  const signatureP1363 = normalizeCanonicalLowSDerSignature(assertion.signatureDer);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: b64url(credential.p256X),
      y: b64url(credential.p256Y),
      ext: true,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signed = concat(assertion.authenticatorData, await sha256(assertion.clientDataJson));
  if (
    !(await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      webCryptoBytes(signatureP1363),
      webCryptoBytes(signed),
    ))
  )
    throw new Error("webauthn_signature_invalid");
  const view = new DataView(
    assertion.authenticatorData.buffer,
    assertion.authenticatorData.byteOffset + 33,
    4,
  );
  return { signatureP1363, signCount: view.getUint32(0) };
}

export function assertPortableApprovalCurrent(input: {
  evidence: RemoteAdminApprovalEvidenceV1;
  nowSeconds: bigint;
  expectedTenant: Uint8Array;
  expectedDigest: Uint8Array;
  expectedEpoch: bigint;
  expectedOperation: number;
  registryGeneration: bigint;
  credential: RemoteCredentialRegistryEntryV1;
}) {
  const { evidence } = input;
  if (
    !equal(evidence.tenantId, input.expectedTenant) ||
    !equal(evidence.canonicalRequestDigest, input.expectedDigest) ||
    evidence.operationEpoch !== input.expectedEpoch ||
    evidence.operation !== input.expectedOperation
  )
    throw new Error("remote_admin_approval_scope_mismatch");
  if (
    evidence.registryGeneration !== input.registryGeneration ||
    input.credential.state !== 1 ||
    !equal(evidence.credentialIdHash, input.credential.credentialIdHash) ||
    !equal(evidence.principalId, input.credential.principalId) ||
    evidence.role !== input.credential.role
  )
    throw new Error("remote_admin_approval_registry_stale");
  if (
    evidence.issuedAt > input.nowSeconds ||
    evidence.expiresAt < input.nowSeconds ||
    evidence.expiresAt - evidence.issuedAt > 900n
  )
    throw new Error("remote_admin_approval_expired");
}

export async function verifyPortableRemoteAdminApproval(input: {
  evidence: RemoteAdminApprovalEvidenceV1;
  credential: RemoteCredentialRegistryEntryV1;
  policy: WebAuthnPolicy;
  expectedChallenge: Uint8Array;
}): Promise<{ signCount: bigint }> {
  const { evidence, credential, policy } = input;
  if (evidence.coseAlg !== -7 || credential.coseAlg !== -7 || credential.state !== 1)
    throw new Error("remote_admin_credential_not_active");
  if (
    evidence.role !== credential.role ||
    !equal(evidence.principalId, credential.principalId) ||
    !equal(evidence.credentialIdHash, credential.credentialIdHash)
  )
    throw new Error("remote_admin_approval_credential_mismatch");
  if (evidence.rpId !== policy.rpId || evidence.origin !== policy.origin)
    throw new Error("remote_admin_approval_rp_origin_mismatch");
  if (!equal(evidence.challengeHash, await sha256(input.expectedChallenge)))
    throw new Error("remote_admin_approval_challenge_hash_mismatch");
  const client = strictClientData(evidence.clientDataJson);
  if (
    client.type !== "webauthn.get" ||
    client.origin !== policy.origin ||
    client.challenge !== b64url(input.expectedChallenge)
  )
    throw new Error("remote_admin_approval_client_data_mismatch");
  if (
    evidence.authenticatorData.length < 37 ||
    evidence.authenticatorData.length > 1024 ||
    !equal(evidence.authenticatorData.slice(0, 32), await sha256(text.encode(policy.rpId)))
  )
    throw new Error("remote_admin_approval_authenticator_data_invalid");
  const flags = evidence.authenticatorData[32]!;
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0)
    throw new Error("webauthn_user_verification_required");
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: b64url(credential.p256X),
      y: b64url(credential.p256Y),
      ext: true,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signed = concat(evidence.authenticatorData, await sha256(evidence.clientDataJson));
  if (
    !(await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      webCryptoBytes(evidence.signatureP1363),
      webCryptoBytes(signed),
    ))
  )
    throw new Error("webauthn_signature_invalid");
  return {
    signCount: BigInt(
      new DataView(
        evidence.authenticatorData.buffer,
        evidence.authenticatorData.byteOffset + 33,
        4,
      ).getUint32(0),
    ),
  };
}
