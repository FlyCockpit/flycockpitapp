/**
 * Remote version registry readiness metadata.
 *
 * Exposes the canonical enabled-registry digest computed by the pure helper in
 * `@flycockpit/cockpit-protocol` so `/ready` can publish it for cross-replica
 * convergence enforcement (owned by `remote-public-service-policy-foundation`).
 */
import { enabledRegistryDigest } from "@flycockpit/cockpit-protocol";

export interface RemoteVersionReadiness {
  /** Canonical enabled-registry digest (SHA-256, 32 bytes, hex). */
  registryDigestHex: string;
  /** Wire magic for `RemoteNegotiationTranscriptV1`. */
  transcriptMagic: string;
  /** Transcript wire version. */
  transcriptVersion: number;
}

/** Compute readiness metadata from the live enabled registry. */
export function getRemoteVersionReadiness(): RemoteVersionReadiness {
  const digest = enabledRegistryDigest();
  const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
  return {
    registryDigestHex: hex,
    transcriptMagic: "FCRN",
    transcriptVersion: 1,
  };
}
