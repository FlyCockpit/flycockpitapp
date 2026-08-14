/**
 * Daemon control-socket (FCDA) certificate verification seam.
 *
 * The gateway does not trust any structurally valid FCDA frame. A daemon is
 * authenticated only when:
 *   1. its certificate JWS parses ({@link parseRemoteIdentityCertificateJws}),
 *   2. the certificate's ES256 signature verifies against the injected
 *      **daemon identity-CA ring** for `protectedHeader.kid` (a currently-valid,
 *      non-revoked key — the grant-signing ring is deliberately NOT the trust
 *      anchor here),
 *   3. the payload binds a daemon subject (`subjectKind === 2`), the configured
 *      issuer, and a validity window covering the injected clock, and
 *   4. the FCDA P1363 signature verifies under the certificate's embedded
 *      public key over the exact domain-separated control-auth preimage.
 *
 * The verifier is injected ({@link DaemonCertificateVerifier}) so tests drive it
 * with an in-test identity-CA ring and production wires it from the identity-CA
 * env group. Verification never discloses which step failed: the gateway maps
 * any thrown {@link DaemonCertificateVerificationError} to close code 4401.
 */
import { createPublicKey, verify } from "node:crypto";
import type { RemoteAuthorityVerifier } from "@flycockpit/api/lib/remote-authority";
import {
  decodeProtocolIdBase64Url,
  parseCanonicalU64DecimalString,
  parseRemoteIdentityCertificateJws,
} from "@flycockpit/cockpit-protocol";
import { REMOTE_GATEWAY_SUBPROTOCOL } from "./close-codes";

/** Domain-separation tag for the daemon control-auth preimage (original prompt, line 54). */
const DAEMON_CONTROL_AUTH_DOMAIN = new TextEncoder().encode(
  "flycockpit.remote.daemon-control-auth.v1\0",
);

/** Thrown for any FCDA verification failure. The gateway maps this to 4401 with no state disclosed. */
export class DaemonCertificateVerificationError extends Error {}

export interface VerifiedDaemonIdentity {
  /** The certificate's `instanceId` in canonical base64url form (22 chars) — the store key. */
  instanceId: string;
  /** The decoded 16-byte protocol id of `instanceId` (preimage input). */
  instanceProtocolId: Uint8Array;
  /** The certificate's `generation` — the cross-replica generation namespace. */
  certificateGeneration: bigint;
}

export interface DaemonControlAuthContext {
  /** The exact 53 encoded FCDC challenge frame the gateway sent this socket. */
  fcdcFrame: Uint8Array;
  /** Decoded certificate JWS bytes from the FCDA frame. */
  certificateJws: Uint8Array;
  /** The FCDA P1363 signature (64 bytes). */
  fcdaSignature: Uint8Array;
  /** The FCDA bytes before the signature (preimage input). */
  fcdaBytesBeforeSignature: Uint8Array;
  /** The exact configured HTTPS origin the gateway advertises. */
  configuredOrigin: string;
  /** Current wall-clock time in seconds since the epoch (injected clock). */
  nowSeconds: bigint;
}

export interface DaemonCertificateVerifier {
  verify(context: DaemonControlAuthContext): Promise<VerifiedDaemonIdentity>;
}

/**
 * Build the exact control-auth preimage message that the daemon signs (and the
 * gateway verifies) with ES256. ES256 hashes this message with SHA-256 before
 * ECDSA, so this equals the SHA-256 preimage fixed by the original prompt.
 */
export function daemonControlAuthPreimage(input: {
  fcdcFrame: Uint8Array;
  configuredOrigin: string;
  subprotocol: string;
  instanceProtocolId: Uint8Array;
  certificateGeneration: bigint;
  fcdaBytesBeforeSignature: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  const origin = new TextEncoder().encode(input.configuredOrigin);
  const subprotocol = new TextEncoder().encode(input.subprotocol);
  if (input.instanceProtocolId.length !== 16)
    throw new DaemonCertificateVerificationError("instance protocol id");
  if (origin.length > 0xffff) throw new DaemonCertificateVerificationError("origin length");
  if (subprotocol.length > 0xff) throw new DaemonCertificateVerificationError("subprotocol length");
  const total =
    DAEMON_CONTROL_AUTH_DOMAIN.length +
    input.fcdcFrame.length +
    2 +
    origin.length +
    1 +
    subprotocol.length +
    16 +
    8 +
    input.fcdaBytesBeforeSignature.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  out.set(DAEMON_CONTROL_AUTH_DOMAIN, offset);
  offset += DAEMON_CONTROL_AUTH_DOMAIN.length;
  out.set(input.fcdcFrame, offset);
  offset += input.fcdcFrame.length;
  view.setUint16(offset, origin.length);
  offset += 2;
  out.set(origin, offset);
  offset += origin.length;
  view.setUint8(offset, subprotocol.length);
  offset += 1;
  out.set(subprotocol, offset);
  offset += subprotocol.length;
  out.set(input.instanceProtocolId, offset);
  offset += 16;
  view.setBigUint64(offset, input.certificateGeneration);
  offset += 8;
  out.set(input.fcdaBytesBeforeSignature, offset);
  return out;
}

/**
 * Identity-CA-ring-backed verifier. `ringVerifier` verifies the certificate JWS
 * signature against the daemon identity-CA ring (kid-scoped, non-revoked,
 * time-valid keys only); `issuer` is the configured, normalized authority issuer
 * the certificate must name.
 */
export class RingDaemonCertificateVerifier implements DaemonCertificateVerifier {
  constructor(
    private readonly ringVerifier: RemoteAuthorityVerifier,
    private readonly issuer: string,
  ) {}

  async verify(context: DaemonControlAuthContext): Promise<VerifiedDaemonIdentity> {
    let parsed: ReturnType<typeof parseRemoteIdentityCertificateJws>;
    try {
      const compact = new TextDecoder("utf-8", { fatal: true }).decode(context.certificateJws);
      parsed = parseRemoteIdentityCertificateJws(compact);
    } catch {
      throw new DaemonCertificateVerificationError("certificate parse");
    }

    const kid = parsed.protectedHeader.kid;
    if (typeof kid !== "string") throw new DaemonCertificateVerificationError("certificate kid");

    // 1. Certificate JWS signature must verify against the identity-CA ring.
    let certificateSignatureOk = false;
    try {
      certificateSignatureOk = await this.ringVerifier.verifyP1363(
        parsed.signingInput,
        parsed.signatureP1363,
        kid,
      );
    } catch {
      certificateSignatureOk = false;
    }
    if (!certificateSignatureOk)
      throw new DaemonCertificateVerificationError("certificate signature");

    // 2. Payload binding checks.
    const payload = parsed.payload as {
      subjectKind: number;
      iss: string;
      instanceId: string;
      generation: string;
      iat: string;
      exp: string;
      publicKey: { crv: string; kty: string; x: string; y: string };
    };
    if (payload.subjectKind !== 2) throw new DaemonCertificateVerificationError("subject kind");
    if (payload.iss !== this.issuer) throw new DaemonCertificateVerificationError("issuer");

    let iat: bigint;
    let exp: bigint;
    let certificateGeneration: bigint;
    try {
      iat = parseCanonicalU64DecimalString(payload.iat);
      exp = parseCanonicalU64DecimalString(payload.exp);
      certificateGeneration = parseCanonicalU64DecimalString(payload.generation);
    } catch {
      throw new DaemonCertificateVerificationError("certificate counters");
    }
    if (!(iat <= context.nowSeconds && context.nowSeconds < exp))
      throw new DaemonCertificateVerificationError("certificate validity window");

    // 3. FCDA signature must verify under the certificate's embedded public key
    //    over the exact domain-separated control-auth preimage.
    let instanceProtocolId: Uint8Array;
    try {
      instanceProtocolId = decodeProtocolIdBase64Url(payload.instanceId);
    } catch {
      throw new DaemonCertificateVerificationError("instance id");
    }
    const preimage = daemonControlAuthPreimage({
      fcdcFrame: context.fcdcFrame,
      configuredOrigin: context.configuredOrigin,
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
      instanceProtocolId,
      certificateGeneration,
      fcdaBytesBeforeSignature: context.fcdaBytesBeforeSignature,
    });
    let certificatePublicKey: ReturnType<typeof createPublicKey>;
    try {
      certificatePublicKey = createPublicKey({
        key: {
          kty: "EC",
          crv: payload.publicKey.crv,
          x: payload.publicKey.x,
          y: payload.publicKey.y,
        },
        format: "jwk",
      });
    } catch {
      throw new DaemonCertificateVerificationError("certificate public key");
    }
    let fcdaSignatureOk = false;
    try {
      fcdaSignatureOk =
        context.fcdaSignature.length === 64 &&
        verify(
          "sha256",
          preimage,
          { key: certificatePublicKey, dsaEncoding: "ieee-p1363" },
          context.fcdaSignature,
        );
    } catch {
      fcdaSignatureOk = false;
    }
    if (!fcdaSignatureOk) throw new DaemonCertificateVerificationError("fcda signature");

    return {
      instanceId: payload.instanceId,
      instanceProtocolId,
      certificateGeneration,
    };
  }
}
