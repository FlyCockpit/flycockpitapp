import { writeFileSync } from "node:fs";
import {
  CustodyClass,
  derivePossessionChallenge,
  EnrollmentRole,
  encodeCustodyEvidence,
  encodeEnrollmentConfirmation,
  encodeEnrollmentTranscript,
  encodePossessionContext,
  encodePossessionProof,
  encodeRemoteIdentityProposal,
  enrollmentConfirmationSigningDigest,
  PossessionPurpose,
  PresenceMode,
  possessionProofSigningDigest,
  remoteIdentitySha256,
  SubjectKind,
} from "../src/remote-identity-protocol";
import { canonicalizeRfc8785 } from "../src/remote-protocol-id";

const enc = new TextEncoder(),
  hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""),
  b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const id = (n: number) => new Uint8Array(16).fill(n),
  bytes = (n: number) => new Uint8Array(32).fill(n),
  sig = (() => {
    const x = new Uint8Array(64);
    x[31] = 1;
    x[63] = 1;
    return x;
  })();
const x = bytes(17),
  y = bytes(34),
  thumb = await remoteIdentitySha256(
    enc.encode(`{"crv":"P-256","kty":"EC","x":"${b64(x)}","y":"${b64(y)}"}`),
  );
const base = {
  subjectId: id(1),
  tenantId: id(2),
  instanceId: id(3),
  certificateId: id(4),
  generation: 1n,
  p256X: x,
  p256Y: y,
  thumbprint: thumb,
  custodyClass: CustodyClass.os_protected,
  presenceMode: PresenceMode.unattended,
  issuer: "https://example.com",
  serviceVersion: 1n,
  policyEpoch: 2n,
  policyDigest: bytes(5),
  authorityEpoch: 3n,
  issuedAt: 1000n,
  expiresAt: 2000n,
};
const valid: { name: string; codec: string; hex: string }[] = [];
const derivations: { name: string; hex: string }[] = [];
const add = (name: string, codec: string, value: Uint8Array) =>
  valid.push({ name, codec, hex: hex(value) });
add(
  "proposal_client",
  "FCIP",
  encodeRemoteIdentityProposal({ ...base, subjectKind: SubjectKind.client, accountId: id(6) }),
);
add(
  "proposal_daemon",
  "FCIP",
  encodeRemoteIdentityProposal({ ...base, subjectKind: SubjectKind.daemon }),
);
const transcript = {
  enrollmentId: id(7),
  tenantId: id(2),
  instanceId: id(3),
  subjectId: id(1),
  generation: 1n,
  p256X: x,
  p256Y: y,
  thumbprint: thumb,
  custodyClass: CustodyClass.os_protected,
  presenceMode: PresenceMode.unattended,
  publicOrigin: "https://example.com",
  initiatorRole: EnrollmentRole.proposed_subject,
  confirmerRole: EnrollmentRole.enrolled_counterpart,
  initiatorNonce: bytes(8),
  confirmerNonce: bytes(9),
  createdAt: 1000n,
  expiresAt: 1200n,
  serviceVersion: 1n,
  policyEpoch: 2n,
  policyDigest: bytes(5),
  authorityEpoch: 3n,
};
add(
  "transcript_client",
  "FCEN",
  encodeEnrollmentTranscript({ ...transcript, subjectKind: SubjectKind.client, accountId: id(6) }),
);
add(
  "transcript_daemon",
  "FCEN",
  encodeEnrollmentTranscript({
    ...transcript,
    subjectKind: SubjectKind.daemon,
    confirmerRole: EnrollmentRole.control_plane_authorizer,
  }),
);
const evidence = Uint8Array.of(1, 2, 3);
add(
  "custody_nonempty",
  "FCCE",
  encodeCustodyEvidence({
    subjectKind: SubjectKind.client,
    subjectId: id(1),
    generation: 1n,
    custodyClass: CustodyClass.os_protected,
    presenceMode: PresenceMode.unattended,
    providerEvidence: evidence,
    evidenceDigest: await remoteIdentitySha256(evidence),
    observedAt: 1000n,
  }),
);
for (const [name, purpose] of Object.entries(PossessionPurpose)) {
  const p = purpose;
  const context =
    p === 1
      ? { purpose: p, proposedIdentityDigest: bytes(10), enrollmentTranscriptDigest: bytes(11) }
      : p <= 4
        ? { purpose: p, currentCertificateDigest: bytes(12), proposedIdentityDigest: bytes(10) }
        : p <= 6
          ? { purpose: p, currentCertificateDigest: bytes(12), attemptRequestDigest: bytes(13) }
          : { purpose: p, currentCertificateDigest: bytes(12), revocationRequestDigest: bytes(14) };
  const contextBytes = encodePossessionContext(context);
  add(`context_${name}`, "FCPC", contextBytes);
  const proofBytes = encodePossessionProof({
    purpose: p,
    subjectKind: p === 6 ? SubjectKind.daemon : SubjectKind.client,
    subjectId: id(1),
    certificateId: id(4),
    generation: 1n,
    requestId: id(15),
    issuerStatusDigest: bytes(16),
    challenge: bytes(17),
    transcriptDigest: await remoteIdentitySha256(contextBytes),
    issuedAt: 1000n,
    expiresAt: 1060n,
    signatureP1363: sig,
  });
  add(`proof_${name}`, "FCPP", proofBytes);
  derivations.push(
    {
      name: `challenge_${name}`,
      hex: hex(await derivePossessionChallenge(p, bytes(16), id(15), contextBytes)),
    },
    {
      name: `proof_signature_${name}`,
      hex: hex(await possessionProofSigningDigest(proofBytes.slice(0, 175), p)),
    },
  );
}
for (const [name, role] of Object.entries(EnrollmentRole)) {
  const confirmation = encodeEnrollmentConfirmation({
    role,
    decision: role === EnrollmentRole.control_plane_authorizer ? 2 : 1,
    enrollmentId: id(7),
    transcriptDigest: bytes(18),
    sasVersion: 1,
    confirmationNonce: bytes(19 + role),
    issuedAt: 1000n,
    expiresAt: 1060n,
    signatureP1363: sig,
  });
  add(`confirmation_${name}`, "FCCF", confirmation);
  derivations.push({
    name: `confirmation_signature_${name}`,
    hex: hex(await enrollmentConfirmationSigningDigest(confirmation.slice(0, 104), role)),
  });
}
for (const [name, kind, account] of [
  ["client", 1, b64(id(6))],
  ["daemon", 2, null],
] as const) {
  const payload = {
    accountId: account,
    aud: "flycockpit-remote-peer-v1",
    authorityEpoch: "3",
    certificateId: b64(id(4)),
    custody: 2,
    exp: "2000",
    generation: "1",
    iat: "1000",
    instanceId: b64(id(3)),
    iss: "https://example.com",
    presenceMode: 1,
    publicKey: { crv: "P-256", kty: "EC", x: b64(x), y: b64(y) },
    schemaVersion: 1,
    sub: b64(id(1)),
    subjectKind: kind,
    tenantId: b64(id(2)),
    thumbprint: b64(thumb),
  };
  const header = {
    alg: "ES256",
    kid: "fixture-key",
    typ: "flycockpit-remote-identity-certificate+jws",
  };
  add(
    `certificate_${name}`,
    "JWS",
    enc.encode(
      `${b64(enc.encode(canonicalizeRfc8785(header)))}.${b64(enc.encode(canonicalizeRfc8785(payload)))}.${b64(sig)}`,
    ),
  );
}
const malformed = valid
  .filter((value) => value.codec !== "JWS")
  .map((value, index) => ({
    name: `truncated_${index}`,
    codec: value.codec,
    hex: value.hex.slice(0, -2),
  }));
for (const codec of ["FCIP", "FCEN", "FCCE", "FCPC", "FCPP", "FCCF"]) {
  const value = valid.find((v) => v.codec === codec)!;
  const wrong = Uint8Array.from(Buffer.from(value.hex, "hex"));
  wrong[4] = 2;
  malformed.push(
    { name: `wrong_version_${codec}`, codec, hex: hex(wrong) },
    { name: `trailing_${codec}`, codec, hex: `${value.hex}00` },
  );
}
const high = Uint8Array.from(Buffer.from(valid.find((v) => v.codec === "FCPP")!.hex, "hex"));
high[207] = 128;
malformed.push(
  { name: "high_s_proof", codec: "FCPP", hex: hex(high) },
  { name: "invalid_jws", codec: "JWS", hex: hex(enc.encode("x.y.z")) },
);
const certificateText = new TextDecoder().decode(
    Buffer.from(valid.find((v) => v.codec === "JWS")!.hex, "hex"),
  ),
  certificateParts = certificateText.split(".");
const reorderedHeader = b64(
  enc.encode(
    JSON.stringify({
      typ: "flycockpit-remote-identity-certificate+jws",
      alg: "ES256",
      kid: "fixture-key",
    }),
  ),
);
malformed.push({
  name: "noncanonical_jws_member_order",
  codec: "JWS",
  hex: hex(enc.encode(`${reorderedHeader}.${certificateParts[1]}.${certificateParts[2]}`)),
});
const badPayload = JSON.parse(
  Buffer.from(certificateParts[1]!, "base64url").toString("utf8"),
) as Record<string, unknown>;
badPayload.custody = 9;
malformed.push({
  name: "unknown_certificate_custody",
  codec: "JWS",
  hex: hex(
    enc.encode(
      `${certificateParts[0]}.${b64(enc.encode(canonicalizeRfc8785(badPayload)))}.${certificateParts[2]}`,
    ),
  ),
});
// ---------------------------------------------------------------------------
// Semantic corpus extensions (identity-protocol-vector-corpus-completion)
// ---------------------------------------------------------------------------
// All additions are appended so the existing vectors — and every derivation
// hash computed above — stay byte-identical.

// (1) Empty-providerEvidence custody codec: valid iff digest == sha256("").
const emptyEvidence = new Uint8Array(0);
add(
  "custody_empty",
  "FCCE",
  encodeCustodyEvidence({
    subjectKind: SubjectKind.client,
    subjectId: id(1),
    generation: 1n,
    custodyClass: CustodyClass.os_protected,
    presenceMode: PresenceMode.unattended,
    providerEvidence: emptyEvidence,
    evidenceDigest: await remoteIdentitySha256(emptyEvidence),
    observedAt: 1000n,
  }),
);

const validHex = (name: string) => valid.find((v) => v.name === name)!.hex;
const mutateByte = (hexStr: string, index: number, value: number) => {
  const buf = Buffer.from(hexStr, "hex");
  buf[index] = value;
  return hex(Uint8Array.from(buf));
};

// Custody digest-mismatch: FCCE empty evidence with a corrupted digest byte.
// Layout: magic4 ver1 kind1 subject16 gen8 custody1 presence1 len2 => digest@34.
malformed.push({
  name: "custody_digest_mismatch",
  codec: "FCCE",
  hex: mutateByte(validHex("custody_empty"), 34, 0xff),
});

// (2) Account-branch rejection vectors (client-with-account daemon-without).
// Each is a byte-relabel of a valid vector's subjectKind discriminant so the
// closed (kind, account-presence) pair becomes illegal. The codecs reject with
// a "…account…" error in both languages.
const CLIENT = 1;
const DAEMON = 2;
malformed.push(
  {
    // FCIP subjectKind@5; daemon layout (presence=0) relabeled client.
    name: "account_branch_fcip_client_missing",
    codec: "FCIP",
    hex: mutateByte(validHex("proposal_daemon"), 5, CLIENT),
  },
  {
    // FCIP client layout (presence=1 + id) relabeled daemon.
    name: "account_branch_fcip_daemon_present",
    codec: "FCIP",
    hex: mutateByte(validHex("proposal_client"), 5, DAEMON),
  },
  {
    // FCEN daemon layout: subjectKind@54 (magic4 ver1 enroll16 tenant16 presence1 instance16).
    name: "account_branch_fcen_client_missing",
    codec: "FCEN",
    hex: mutateByte(validHex("transcript_daemon"), 54, CLIENT),
  },
  {
    // FCEN client layout: subjectKind@70 (…presence1 account16 instance16).
    name: "account_branch_fcen_daemon_present",
    codec: "FCEN",
    hex: mutateByte(validHex("transcript_client"), 70, DAEMON),
  },
);

// (3) Certificate JWS header/payload/signature abuse vectors.
const jwsB64 = (s: string) => b64(enc.encode(s));
const assembleJws = (headerJson: string, payloadJson: string, signature: Uint8Array) =>
  `${jwsB64(headerJson)}.${jwsB64(payloadJson)}.${b64(signature)}`;
const jwsMalformed = (name: string, compact: string) =>
  malformed.push({ name, codec: "JWS", hex: hex(enc.encode(compact)) });
const TYP = "flycockpit-remote-identity-certificate+jws";
const clientPayload = {
  accountId: b64(id(6)),
  aud: "flycockpit-remote-peer-v1",
  authorityEpoch: "3",
  certificateId: b64(id(4)),
  custody: 2,
  exp: "2000",
  generation: "1",
  iat: "1000",
  instanceId: b64(id(3)),
  iss: "https://example.com",
  presenceMode: 1,
  publicKey: { crv: "P-256", kty: "EC", x: b64(x), y: b64(y) },
  schemaVersion: 1,
  sub: b64(id(1)),
  subjectKind: 1,
  tenantId: b64(id(2)),
  thumbprint: b64(thumb),
};
const canonHeader = canonicalizeRfc8785({ alg: "ES256", kid: "fixture-key", typ: TYP });
const canonPayload = canonicalizeRfc8785(clientPayload);

// duplicate-member: hand-rolled header JSON with a repeated key (never canonical).
jwsMalformed(
  "jws_duplicate_member",
  assembleJws(
    `{"alg":"ES256","alg":"ES256","kid":"fixture-key","typ":"${TYP}"}`,
    canonPayload,
    sig,
  ),
);
// unknown-member: extra canonical header member (structural member-count check).
jwsMalformed(
  "jws_unknown_member",
  assembleJws(
    canonicalizeRfc8785({ alg: "ES256", extra: "x", kid: "fixture-key", typ: TYP }),
    canonPayload,
    sig,
  ),
);
// crit: a "crit" header member is rejected (present as a 4th member).
jwsMalformed(
  "jws_crit",
  assembleJws(
    canonicalizeRfc8785({ alg: "ES256", crit: ["b64"], kid: "fixture-key", typ: TYP }),
    canonPayload,
    sig,
  ),
);
// alg substitution: canonical, well-formed header whose alg is not ES256.
jwsMalformed(
  "jws_alg_substitution",
  assembleJws(
    canonicalizeRfc8785({ alg: "ES384", kid: "fixture-key", typ: TYP }),
    canonPayload,
    sig,
  ),
);
// size cap: compact serialization exceeds the 4,096-byte ceiling.
jwsMalformed(
  "jws_size_cap",
  assembleJws(
    canonicalizeRfc8785({ alg: "ES256", kid: "A".repeat(5000), typ: TYP }),
    canonPayload,
    sig,
  ),
);
// thumbprint mismatch: valid structure, RFC 7638 thumbprint does not match x/y.
jwsMalformed(
  "jws_thumbprint_mismatch",
  assembleJws(
    canonHeader,
    canonicalizeRfc8785({ ...clientPayload, thumbprint: b64(bytes(0)) }),
    sig,
  ),
);
// high-S signature: s-component above n/2 is rejected (malleability).
const highS = Uint8Array.from(sig);
highS[32] = 0x80;
jwsMalformed("jws_high_s", assembleJws(canonHeader, canonPayload, highS));
// zero-r: r-component all zero is rejected.
const zeroR = Uint8Array.from(sig);
zeroR.fill(0, 0, 32);
jwsMalformed("jws_zero_r", assembleJws(canonHeader, canonPayload, zeroR));
// zero-s: s-component all zero is rejected.
const zeroS = Uint8Array.from(sig);
zeroS.fill(0, 32, 64);
jwsMalformed("jws_zero_s", assembleJws(canonHeader, canonPayload, zeroS));

writeFileSync(
  new URL("../fixtures/remote-identity-protocol-v1.json", import.meta.url),
  `${JSON.stringify({ schemaVersion: 1, valid, malformed, derivations }, null, 2)}\n`,
);
