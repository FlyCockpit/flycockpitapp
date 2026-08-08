import { writeFileSync } from "node:fs";
import {
  CustodyClass,
  EnrollmentRole,
  encodeCustodyEvidence,
  encodeEnrollmentConfirmation,
  encodeEnrollmentTranscript,
  encodePossessionContext,
  encodePossessionProof,
  encodeRemoteIdentityProposal,
  PossessionPurpose,
  PresenceMode,
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
  add(
    `proof_${name}`,
    "FCPP",
    encodePossessionProof({
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
    }),
  );
}
for (const [name, role] of Object.entries(EnrollmentRole))
  add(
    `confirmation_${name}`,
    "FCCF",
    encodeEnrollmentConfirmation({
      role,
      decision: role === EnrollmentRole.control_plane_authorizer ? 2 : 1,
      enrollmentId: id(7),
      transcriptDigest: bytes(18),
      sasVersion: 1,
      confirmationNonce: bytes(19 + role),
      issuedAt: 1000n,
      expiresAt: 1060n,
      signatureP1363: sig,
    }),
  );
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
  .slice(0, 12)
  .map((value, index) => ({
    name: `truncated_${index}`,
    codec: value.codec,
    hex: value.hex.slice(0, -2),
  }));
writeFileSync(
  new URL("../fixtures/remote-identity-protocol-v1.json", import.meta.url),
  `${JSON.stringify({ schemaVersion: 1, valid, malformed }, null, 2)}\n`,
);
