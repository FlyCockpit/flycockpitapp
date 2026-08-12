/**
 * Browser-origin remote enrollment: assemble a production possession proof from
 * the browser custody provider and hand it to an injected transport.
 *
 * The flow proves capability before touching the transport, generates (or
 * reopens) the durable custody handle, builds the unsigned possession proof via
 * the shared codec, signs its signing message with the non-extractable durable
 * key, re-encodes the complete proof with the shared codec, and only then calls
 * `transport.send`. Any failure before the send leaves the transport untouched,
 * so a capability or custody failure can never leak a half-formed proof.
 */

import {
  encodePossessionProof,
  type PossessionProofV1,
  type PossessionPurposeV1,
  possessionProofSigningMessage,
  type RemoteIdentityCustodyPolicyRequestV1,
  type SubjectKindV1,
} from "@flycockpit/cockpit-protocol";
import {
  probeRemoteBrowserIdentityCapability,
  type RemoteBrowserIdentityCapability,
  RemoteBrowserIdentityCustodyError,
  type RemoteBrowserIdentityCustodyProvider,
} from "./remote-browser-identity-custody";

/** The injected transport that carries the codec-encoded possession proof to
 * the control plane. It receives the exact production-encoded bytes. */
export interface EnrollmentTransport<T> {
  send(encodedProof: Uint8Array): Promise<T>;
}

/** The fields required to build the possession proof carried by enrollment. */
export interface BeginBrowserRemoteEnrollmentOptions<T> {
  readonly provider: RemoteBrowserIdentityCustodyProvider;
  readonly transport: EnrollmentTransport<T>;
  readonly subjectKind: SubjectKindV1;
  readonly policy: RemoteIdentityCustodyPolicyRequestV1;
  readonly purpose: PossessionPurposeV1;
  readonly certificateId: Uint8Array;
  readonly requestId: Uint8Array;
  readonly issuerStatusDigest: Uint8Array;
  readonly challenge: Uint8Array;
  readonly transcriptDigest: Uint8Array;
  readonly issuedAt: bigint;
  /** Injected capability override (tests). When omitted, the live engine is
   * probed before any custody generation. */
  readonly capability?: RemoteBrowserIdentityCapability;
}

/** The outcome of a successful enrollment: the transport result plus the exact
 * bytes sent (the production-encoded possession proof) and the durable handle. */
export interface BeginBrowserRemoteEnrollmentResult<T> {
  readonly transportResult: T;
  readonly encodedProof: Uint8Array;
  readonly handleId: Uint8Array;
}

/** A structurally valid low-S placeholder signature used only to encode the
 * unsigned proof; the real signature replaces it before the proof is sent. */
const PLACEHOLDER_SIGNATURE = (() => {
  const sig = new Uint8Array(64);
  sig[31] = 1;
  sig[63] = 1;
  return sig;
})();

/**
 * Begin a browser remote enrollment. Order is load-bearing: capability is
 * proven first (an unsupported engine throws before the transport is touched),
 * then custody is generated, then the possession proof is signed and encoded,
 * and only a fully encoded proof is handed to the transport.
 */
export async function beginBrowserRemoteEnrollment<T>(
  options: BeginBrowserRemoteEnrollmentOptions<T>,
): Promise<BeginBrowserRemoteEnrollmentResult<T>> {
  const capability = options.capability ?? (await probeRemoteBrowserIdentityCapability());
  if (!capability.supported) {
    throw new RemoteBrowserIdentityCustodyError(
      "unsupported_engine",
      "browser engine does not support non-extractable ECDSA P-256 + IndexedDB",
    );
  }

  const generation = await options.provider.generate(options.subjectKind, options.policy);

  const unsignedTemplate: PossessionProofV1 = {
    purpose: options.purpose,
    subjectKind: options.subjectKind,
    subjectId: generation.handleId,
    certificateId: options.certificateId,
    generation: generation.evidence.generation,
    requestId: options.requestId,
    issuerStatusDigest: options.issuerStatusDigest,
    challenge: options.challenge,
    transcriptDigest: options.transcriptDigest,
    issuedAt: options.issuedAt,
    expiresAt: options.issuedAt + 60n,
    signatureP1363: PLACEHOLDER_SIGNATURE,
  };
  const unsignedProof = encodePossessionProof(unsignedTemplate).slice(0, 175);
  const signingMessage = possessionProofSigningMessage(unsignedProof, options.purpose);
  const signature = await options.provider.signPossessionProof(generation.handleId, signingMessage);

  const encodedProof = encodePossessionProof({
    ...unsignedTemplate,
    signatureP1363: signature,
  });
  const transportResult = await options.transport.send(encodedProof);
  return { transportResult, encodedProof, handleId: generation.handleId };
}
