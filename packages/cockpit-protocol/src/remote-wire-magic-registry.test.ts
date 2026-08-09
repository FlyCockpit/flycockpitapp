import { describe, expect, it } from "vitest";
import registry from "../fixtures/remote-wire-magic-registry-v1.json";
import {
  assertRegisteredProductionMagics,
  parseRemoteWireMagicRegistry,
} from "./remote-wire-magic-registry";

describe("remote_wire_magic_registry_cross_language_vectors", () => {
  it("owns every identity magic uniquely", () => {
    const parsed = parseRemoteWireMagicRegistry(registry);
    expect(parsed.length).toBeGreaterThan(0);
    assertRegisteredProductionMagics(parsed, [
      { magic: "FCIP", symbolicType: "RemoteIdentityProposalV1" },
      { magic: "FCEN", symbolicType: "EnrollmentTranscriptV1" },
      { magic: "FCCE", symbolicType: "RemoteIdentityCustodyEvidenceV1" },
      { magic: "FCPC", symbolicType: "RemoteIdentityPossessionContextV1" },
      { magic: "FCPP", symbolicType: "RemoteIdentityPossessionProofV1" },
      { magic: "FCCF", symbolicType: "RemoteEnrollmentConfirmationV1" },
      { magic: "FCAB", symbolicType: "RemoteChildAuthenticationBundleV1" },
      { magic: "FCAK", symbolicType: "RemoteSignalingCommitAckV1" },
      { magic: "FCDO", symbolicType: "DaemonAdmissionOfferV1" },
      { magic: "FCCP", symbolicType: "ClientAdmissionProofV1" },
      { magic: "FCFP", symbolicType: "RemoteEndpointFinalProofV1" },
      { magic: "FCSE", symbolicType: "RemoteSignalingEventRequestV1" },
      { magic: "FCWO", symbolicType: "RemoteWebRtcOfferV1" },
      { magic: "FCWN", symbolicType: "RemoteWebRtcAnswerV1" },
      { magic: "FCWC", symbolicType: "RemoteWebRtcCandidateV1" },
      { magic: "FCWE", symbolicType: "RemoteWebRtcIceCompleteV1" },
    ]);
    expect(() => parseRemoteWireMagicRegistry([])).toThrow();
    expect(() => parseRemoteWireMagicRegistry([...registry, registry[0]])).toThrow();
  });
});
