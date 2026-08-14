/**
 * Pure import logic for the signed public service policy. All business rules
 * live here; the {@link PolicyStore} only executes SQL. Every fail-closed check
 * (JWKS ring, ES256 signature, schema, skew/window, previous-digest chain,
 * three-valued classification) runs BEFORE any write. `now` is an INJECTED
 * epoch-seconds clock — this module never reads a process clock.
 */
import { createHash } from "node:crypto";
import {
  canonicalizeRfc8785,
  classifyPolicyChange,
  decodePublicPolicyId,
  type ImportAcknowledgement,
  type PolicyJwk,
  parsePolicyJwks,
  parsePolicyJws,
  payloadDigestHex,
  type RemoteConnectionPolicyV1,
  RemotePublicPolicyError,
  type RemotePublicServicePolicyV1,
  remotePublicServicePolicyV1Schema,
  validateForImport,
  verifyPolicyJws,
} from "@flycockpit/cockpit-protocol";
import type { PolicyStore, StoredPolicyRow } from "./remote-public-policy-storage";

function fail(message: string): never {
  throw new RemotePublicPolicyError("invalid", message);
}

/** RFC 7638 thumbprint (base64url SHA-256 of the canonical EC JWK members). */
function rfc7638Thumbprint(jwk: PolicyJwk): string {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
  return createHash("sha256").update(canonical).digest("base64url");
}

function ringDigestHex(jwksJson: string): string {
  // Digest the canonicalized ring so the audited ring is pinned to the row.
  return createHash("sha256")
    .update(canonicalizeRfc8785(JSON.parse(jwksJson)))
    .digest("hex");
}

function decodePredecessorPolicy(row: StoredPolicyRow): RemoteConnectionPolicyV1 {
  const parsed = parsePolicyJws(row.compactJws);
  const envelope = remotePublicServicePolicyV1Schema.parse(parsed.payload);
  return envelope.policy;
}

function acknowledgement(
  envelope: RemotePublicServicePolicyV1,
  digest: string,
  row: StoredPolicyRow,
): ImportAcknowledgement {
  return {
    policyId: row.policyId,
    serviceVersion: envelope.serviceVersion,
    state: row.state,
    notBefore: envelope.notBefore,
    digest,
  };
}

export interface ImportPolicyJwsArgs {
  compactJws: string;
  jwksJson: string;
  /** Injected import time in epoch seconds — never a process clock. */
  now: bigint;
  store: PolicyStore;
}

/**
 * Verify, validate, and durably schedule a signed public service policy. On a
 * byte-identical resubmission returns the same acknowledgement without writing a
 * second row or outbox event; a same-version submission with divergent bytes
 * fails. Unsigned / tampered / next-key / unknown-kid / skew / chain / mixed /
 * claimed-class-mismatch inputs all fail closed before any write.
 */
export async function importPolicyJws(args: ImportPolicyJwsArgs): Promise<ImportAcknowledgement> {
  const { compactJws, jwksJson, now, store } = args;

  // 1. Strict JWKS ring parse (throws on any violation).
  const ring = await parsePolicyJwks(jwksJson);

  // 2. ES256 verification, fail-closed, current-key-only for import.
  const parsed = await verifyPolicyJws(compactJws, ring, "import");

  // 3. Envelope schema + import-time skew/notBefore window.
  const envelope = remotePublicServicePolicyV1Schema.parse(parsed.payload);
  validateForImport(envelope, now);
  decodePublicPolicyId(envelope.policyId); // validates the 22-char id shape.

  const version = BigInt(envelope.serviceVersion);
  const digest = await payloadDigestHex(envelope);

  // 4. Idempotency BEFORE the chain check so a valid resubmission of an already
  // stored version is not rejected as an out-of-order predecessor. The security
  // gates (steps 1-3) have already passed; a byte-identical row is safe to echo.
  const existing = await store.loadPolicyByServiceVersion(envelope.serviceVersion);
  if (existing) {
    if (existing.payloadDigest === digest && existing.compactJws === compactJws) {
      return acknowledgement(envelope, digest, existing);
    }
    fail(`serviceVersion ${envelope.serviceVersion} already imported with divergent bytes`);
  }

  // 5. Previous-digest chain + monotonic version.
  const kid = String(parsed.protectedHeader.kid);
  const jwk = ring.keys.find((k) => k.kid === kid);
  if (!jwk) fail(`ring lost the verifying kid ${kid}`); // unreachable after verify.

  if (version === 1n) {
    if (envelope.previousDigest !== null) fail("service version 1 must have previousDigest: null");
    const tip = await store.loadPolicyTip();
    if (tip) fail("service version 1 cannot follow a stored predecessor");
  } else {
    if (envelope.previousDigest === null) {
      fail(`service version ${envelope.serviceVersion} must reference a previousDigest`);
    }
    const predecessor = await store.loadPolicyByServiceVersion((version - 1n).toString());
    if (!predecessor) {
      fail(`service version ${envelope.serviceVersion} has no stored predecessor`);
    }
    if (predecessor.payloadDigest !== envelope.previousDigest) {
      fail("previousDigest does not match the stored predecessor payload digest");
    }
    // 6. Three-valued classification vs the stored predecessor.
    const computed = classifyPolicyChange(decodePredecessorPolicy(predecessor), envelope.policy);
    if (computed === "mixed") fail("a mixed widening+narrowing change cannot be imported");
    if (computed !== envelope.changeClass) {
      fail(`claimed changeClass ${envelope.changeClass} does not match computed ${computed}`);
    }
  }

  // 7. One transaction: immutable scheduled row + scheduled outbox event.
  const row = await store.insertScheduledPolicy({
    policyId: envelope.policyId,
    serviceVersion: envelope.serviceVersion,
    changeClass: envelope.changeClass,
    compactJws,
    payloadDigest: digest,
    previousDigest: envelope.previousDigest,
    issuedAt: envelope.issuedAt,
    notBefore: envelope.notBefore,
    verifiedKid: kid,
    verifiedJwk: JSON.stringify(jwk),
    thumbprint: rfc7638Thumbprint(jwk),
    ringDigest: ringDigestHex(jwksJson),
  });

  // Concurrent same-version winner (unique constraint): the loser must observe
  // the divergence rather than a partial row.
  if (row.payloadDigest !== digest || row.compactJws !== compactJws) {
    fail(`serviceVersion ${envelope.serviceVersion} already imported with divergent bytes`);
  }
  return acknowledgement(envelope, digest, row);
}
