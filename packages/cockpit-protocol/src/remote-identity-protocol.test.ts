import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import vectors from "../fixtures/remote-identity-protocol-v1.json";
import {
  decodeCustodyEvidence,
  decodeEnrollmentConfirmation,
  decodeEnrollmentTranscript,
  decodePossessionContext,
  decodePossessionProof,
  decodeRemoteIdentityProposal,
  derivePossessionChallenge,
  type EnrollmentConfirmationV1,
  EnrollmentRole,
  encodeCustodyEvidence,
  encodeEnrollmentConfirmation,
  encodeEnrollmentTranscript,
  encodePossessionContext,
  encodePossessionProof,
  encodeRemoteIdentityProposal,
  enrollmentConfirmationSigningDigest,
  type PossessionContextV1,
  type PossessionProofV1,
  PossessionPurpose,
  type PossessionPurposeV1,
  parseRemoteIdentityCertificateJws,
  possessionChallengeDomain,
  possessionProofSigningDigest,
  possessionSignatureDomain,
  remoteIdentitySha256,
  remoteIdentitySha256Sync,
  SubjectKind,
} from "./remote-identity-protocol";

const fromHex = (value: string) =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
function reconstruct(codec: string, bytes: Uint8Array): Uint8Array {
  switch (codec) {
    case "FCIP":
      return encodeRemoteIdentityProposal(decodeRemoteIdentityProposal(bytes));
    case "FCEN":
      return encodeEnrollmentTranscript(decodeEnrollmentTranscript(bytes));
    case "FCCE":
      return encodeCustodyEvidence(decodeCustodyEvidence(bytes));
    case "FCPC":
      return encodePossessionContext(decodePossessionContext(bytes));
    case "FCPP":
      return encodePossessionProof(decodePossessionProof(bytes));
    case "FCCF":
      return encodeEnrollmentConfirmation(decodeEnrollmentConfirmation(bytes));
    case "JWS":
      parseRemoteIdentityCertificateJws(new TextDecoder().decode(bytes));
      return bytes;
    default:
      throw new Error("unknown fixture codec");
  }
}

describe("remote_identity_protocol_cross_language_vectors", () => {
  it("reconstructs and rejects the shared byte corpus", () => {
    expect(vectors.valid.length).toBeGreaterThan(0);
    expect(vectors.malformed.length).toBeGreaterThan(0);
    for (const vector of vectors.valid) {
      const bytes = fromHex(vector.hex);
      expect(bytes.length).toBeGreaterThan(0);
      expect(reconstruct(vector.codec, bytes)).toEqual(bytes);
    }
    for (const vector of vectors.malformed) {
      expect(() => reconstruct(vector.codec, fromHex(vector.hex))).toThrow();
    }
  });
  it("exhausts purpose domains", () => {
    for (const purpose of Object.values(PossessionPurpose)) {
      expect(possessionChallengeDomain(purpose).at(-1)).toBe(0);
      expect(possessionSignatureDomain(purpose).at(-1)).toBe(0);
    }
  });
  it("matches the SHA-256 known-answer vector", async () => {
    const input = new TextEncoder().encode("abc"),
      expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    expect(
      Array.from(remoteIdentitySha256Sync(input), (x) => x.toString(16).padStart(2, "0")).join(""),
    ).toBe(expected);
    expect(await remoteIdentitySha256(input)).toEqual(remoteIdentitySha256Sync(input));
  });
  it("matches every checked derivation", async () => {
    const expected = new Map(vectors.derivations.map((v) => [v.name, v.hex]));
    for (const [name, purpose] of Object.entries(PossessionPurpose)) {
      const context = fromHex(vectors.valid.find((v) => v.name === `context_${name}`)!.hex),
        proof = fromHex(vectors.valid.find((v) => v.name === `proof_${name}`)!.hex);
      expect(
        Array.from(
          await derivePossessionChallenge(
            purpose,
            new Uint8Array(32).fill(16),
            new Uint8Array(16).fill(15),
            context,
          ),
          (x) => x.toString(16).padStart(2, "0"),
        ).join(""),
      ).toBe(expected.get(`challenge_${name}`));
      expect(
        Array.from(await possessionProofSigningDigest(proof.slice(0, 175), purpose), (x) =>
          x.toString(16).padStart(2, "0"),
        ).join(""),
      ).toBe(expected.get(`proof_signature_${name}`));
    }
    for (const [name, role] of Object.entries({
      proposed_subject: 1,
      enrolled_counterpart: 2,
      control_plane_authorizer: 3,
    } as const)) {
      const confirmation = fromHex(
        vectors.valid.find((v) => v.name === `confirmation_${name}`)!.hex,
      );
      expect(
        Array.from(
          await enrollmentConfirmationSigningDigest(confirmation.slice(0, 104), role),
          (x) => x.toString(16).padStart(2, "0"),
        ).join(""),
      ).toBe(expected.get(`confirmation_signature_${name}`));
    }
  });
});

const findValid = (name: string) => vectors.valid.find((v) => v.name === name)!;
const findMalformed = (name: string) => vectors.malformed.find((v) => v.name === name)!;
const idBytes = (n: number) => new Uint8Array(16).fill(n);
const d32 = (n: number) => new Uint8Array(32).fill(n);
const lowSSig = () => {
  const s = new Uint8Array(64);
  s[31] = 1;
  s[63] = 1;
  return s;
};

describe("remote_identity_account_branch_rejections", () => {
  it("rejects closed (subjectKind, account) pairs for FCIP and FCEN", () => {
    const names = [
      ["account_branch_fcip_client_missing", "FCIP"],
      ["account_branch_fcip_daemon_present", "FCIP"],
      ["account_branch_fcen_client_missing", "FCEN"],
      ["account_branch_fcen_daemon_present", "FCEN"],
    ] as const;
    expect(names.length).toBeGreaterThan(0);
    for (const [name, codec] of names) {
      const v = findMalformed(name);
      expect(v.codec).toBe(codec);
      expect(() => reconstruct(codec, fromHex(v.hex))).toThrow(/account/);
    }
  });
});

describe("remote_identity_certificate_jws_vectors", () => {
  it("parses valid certificates and fails each abuse vector on its own check", () => {
    for (const name of ["certificate_client", "certificate_daemon"]) {
      const v = findValid(name);
      expect(() => reconstruct("JWS", fromHex(v.hex))).not.toThrow();
    }
    const abuse: [string, RegExp][] = [
      ["jws_duplicate_member", /noncanonical/],
      ["jws_unknown_member", /protected header/],
      ["jws_crit", /protected header/],
      ["jws_alg_substitution", /protected header/],
      ["jws_size_cap", /exceeds/],
      ["jws_thumbprint_mismatch", /thumbprint/],
      ["jws_high_s", /high-S/],
      ["jws_zero_r", /signature/],
      ["jws_zero_s", /signature/],
    ];
    expect(abuse.length).toBe(9);
    for (const [name, needle] of abuse) {
      const v = findMalformed(name);
      expect(() => reconstruct("JWS", fromHex(v.hex))).toThrow(needle);
    }
  });
});

describe("remote_identity_possession_purpose_matrix", () => {
  const baseProof = (
    purpose: PossessionProofV1["purpose"],
    subjectKind: PossessionProofV1["subjectKind"],
  ): PossessionProofV1 => ({
    purpose,
    subjectKind,
    subjectId: idBytes(1),
    certificateId: idBytes(4),
    generation: 1n,
    requestId: idBytes(15),
    issuerStatusDigest: d32(16),
    challenge: d32(17),
    transcriptDigest: d32(18),
    issuedAt: 1000n,
    expiresAt: 1060n,
    signatureP1363: lowSSig(),
  });
  const contextFor = (purpose: PossessionPurposeValue): PossessionContextV1 => {
    if (purpose === 1)
      return { purpose, proposedIdentityDigest: d32(10), enrollmentTranscriptDigest: d32(11) };
    if (purpose <= 4)
      return { purpose, currentCertificateDigest: d32(12), proposedIdentityDigest: d32(10) };
    if (purpose <= 6)
      return { purpose, currentCertificateDigest: d32(12), attemptRequestDigest: d32(13) };
    return { purpose, currentCertificateDigest: d32(12), revocationRequestDigest: d32(14) };
  };
  type PossessionPurposeValue = PossessionProofV1["purpose"];

  it("accepts exactly the legal purpose × subject-kind proof combinations", () => {
    let combos = 0;
    for (const purpose of Object.values(PossessionPurpose)) {
      for (const subjectKind of [SubjectKind.client, SubjectKind.daemon] as const) {
        combos += 1;
        const legal =
          (purpose === 5 && subjectKind === 1) ||
          (purpose === 7 && subjectKind === 1) ||
          (purpose === 6 && subjectKind === 2) ||
          purpose <= 4;
        const run = () => encodePossessionProof(baseProof(purpose, subjectKind));
        if (legal) expect(run).not.toThrow();
        else expect(run).toThrow(/purpose subject mismatch/);
      }
    }
    expect(combos).toBe(14);
  });

  it("enforces the purpose × context-presence matrix", () => {
    for (const purpose of Object.values(PossessionPurpose)) {
      const ctx = contextFor(purpose);
      expect(() => encodePossessionContext(ctx)).not.toThrow();
      const flipped: PossessionContextV1 = ctx.currentCertificateDigest
        ? { ...ctx, currentCertificateDigest: undefined }
        : { ...ctx, currentCertificateDigest: d32(99) };
      expect(() => encodePossessionContext(flipped)).toThrow(/purpose context mismatch/);
    }
  });
});

describe("remote_identity_possession_challenge_vectors", () => {
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const cases = Object.entries(PossessionPurpose) as [string, PossessionPurposeV1][];

  it("derives the corpus challenge and rejects cross-wired purposes", async () => {
    const expected = new Map(vectors.derivations.map((v) => [v.name, v.hex]));
    for (const [name, purpose] of cases) {
      const context = fromHex(findValid(`context_${name}`).hex);
      const challenge = await derivePossessionChallenge(purpose, d32(16), idBytes(15), context);
      expect(hex(challenge)).toBe(expected.get(`challenge_${name}`));
      for (const [, other] of cases) {
        if (other !== purpose) {
          await expect(
            derivePossessionChallenge(other, d32(16), idBytes(15), context),
          ).rejects.toThrow(/purpose/);
        }
      }
    }
  });

  it("uses seven distinct NUL-terminated domains per family", () => {
    const challenge = new Set<string>();
    const signature = new Set<string>();
    for (const [, purpose] of cases) {
      const c = possessionChallengeDomain(purpose);
      const s = possessionSignatureDomain(purpose);
      expect(c.at(-1)).toBe(0);
      expect(s.at(-1)).toBe(0);
      challenge.add(hex(c));
      signature.add(hex(s));
    }
    expect(challenge.size).toBe(7);
    expect(signature.size).toBe(7);
  });
});

describe("remote_enrollment_transcript_confirmation_vectors", () => {
  it("round-trips transcripts and fails closed on role/decision invariants", async () => {
    const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
    for (const name of ["transcript_client", "transcript_daemon"]) {
      const bytes = fromHex(findValid(name).hex);
      expect(reconstruct("FCEN", bytes)).toEqual(bytes);
    }
    // Identical initiator/confirmer roles reject.
    const transcript = decodeEnrollmentTranscript(fromHex(findValid("transcript_client").hex));
    transcript.confirmerRole = transcript.initiatorRole;
    expect(() => encodeEnrollmentTranscript(transcript)).toThrow(/roles/);

    // Confirmation signing digests match the shared corpus.
    const expected = new Map(vectors.derivations.map((v) => [v.name, v.hex]));
    for (const [name, role] of Object.entries(EnrollmentRole)) {
      const bytes = fromHex(findValid(`confirmation_${name}`).hex);
      const digest = await enrollmentConfirmationSigningDigest(bytes.slice(0, 104), role);
      expect(hex(digest)).toBe(expected.get(`confirmation_signature_${name}`));
    }
    // Out-of-range decision rejects.
    const c = decodeEnrollmentConfirmation(fromHex(findValid("confirmation_proposed_subject").hex));
    expect(() =>
      encodeEnrollmentConfirmation({ ...c, decision: 3 } as unknown as EnrollmentConfirmationV1),
    ).toThrow(/decision/);
  });
});

describe("remote_identity_custody_codec_vectors", () => {
  it("round-trips empty and nonempty FCCE and fails a digest mismatch", () => {
    for (const name of ["custody_nonempty", "custody_empty"]) {
      const bytes = fromHex(findValid(name).hex);
      expect(reconstruct("FCCE", bytes)).toEqual(bytes);
    }
    const empty = decodeCustodyEvidence(fromHex(findValid("custody_empty").hex));
    expect(empty.providerEvidence.length).toBe(0);
    expect(() =>
      reconstruct("FCCE", fromHex(findMalformed("custody_digest_mismatch").hex)),
    ).toThrow(/digest/);
    const tampered = decodeCustodyEvidence(fromHex(findValid("custody_nonempty").hex));
    tampered.evidenceDigest = d32(0);
    expect(() => encodeCustodyEvidence(tampered)).toThrow(/digest/);
  });
});

describe("remote_identity_sha256_pinned_to_audited", () => {
  it("matches createHash('sha256') and WebCrypto over empty/short/multiblock/high-bit inputs", async () => {
    const inputs = [
      new Uint8Array(0),
      new TextEncoder().encode("abc"),
      new TextEncoder().encode("a".repeat(1000)),
      Uint8Array.from({ length: 256 }, (_, i) => i),
    ];
    for (const input of inputs) {
      const expected = new Uint8Array(createHash("sha256").update(Buffer.from(input)).digest());
      expect(remoteIdentitySha256Sync(input)).toEqual(expected);
      expect(await remoteIdentitySha256(input)).toEqual(expected);
    }
  });
});

describe("remote_identity_protocol_current_ownership_guard", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const OWNER = "remote-identity-protocol.ts";
  const CODEC_FN =
    /function\s+(?:encode|decode)(?:RemoteIdentityProposal|EnrollmentTranscript|CustodyEvidence|PossessionContext|PossessionProof|EnrollmentConfirmation)\b/;
  const MAGIC_REGISTRY = /(?:const|let|var|enum)\s+REMOTE_IDENTITY_MAGICS\b/;
  const DOMAINS = [
    "flycockpit.remote.identity-possession-challenge.",
    "flycockpit.remote.identity-possession-proof.",
    "flycockpit.remote.enrollment-confirmation.",
  ];
  const scan = (candidate: string): string | null => {
    if (CODEC_FN.test(candidate)) return "foundation FCIP/…/FCCF codec definition";
    if (MAGIC_REGISTRY.test(candidate)) return "REMOTE_IDENTITY_MAGICS redefinition";
    for (const domain of DOMAINS)
      if (candidate.includes(domain)) return `signing-domain literal ${domain}`;
    return null;
  };

  it("detects planted foundation definitions (non-vacuity)", () => {
    expect(scan("export function encodePossessionProof(v: unknown) { return v; }")).not.toBeNull();
    expect(scan("const REMOTE_IDENTITY_MAGICS = { proposal: 'FCIP' };")).not.toBeNull();
    expect(
      scan('const d = "flycockpit.remote.identity-possession-proof.attempt-client.v1";'),
    ).not.toBeNull();
    // Usages/imports are not flagged.
    expect(scan("import { encodePossessionProof } from './remote-identity-protocol';")).toBeNull();
    expect(
      scan('if (REMOTE_IDENTITY_MAGICS.proposal !== "FCIP") throw new Error("x");'),
    ).toBeNull();
  });

  it("no second definition exists across the package source", () => {
    const files = readdirSync(here).filter(
      (f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && f !== OWNER,
    );
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const reason = scan(readFileSync(join(here, f), "utf8"));
      expect(reason, `${f} redefines a foundation identity definition: ${reason}`).toBeNull();
    }
    // The owner really carries the definitions — the guard is not vacuous.
    expect(scan(readFileSync(join(here, OWNER), "utf8"))).not.toBeNull();
  });
});
