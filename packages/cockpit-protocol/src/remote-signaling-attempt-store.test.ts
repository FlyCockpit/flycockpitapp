import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote/signaling-attempt-store-v1.json";
import {
  decodeRemoteSignalingCommitAckV1,
  decodeRemoteSignalingEventRequestV1,
  decodeRemoteWebRtcAnswerV1,
  decodeRemoteWebRtcCandidateV1,
  decodeRemoteWebRtcIceCompleteV1,
  decodeRemoteWebRtcOfferV1,
  encodeRemoteSignalingCommitAckV1,
  encodeRemoteSignalingEventRequestV1,
  encodeRemoteWebRtcAnswerV1,
  encodeRemoteWebRtcCandidateV1,
  encodeRemoteWebRtcIceCompleteV1,
  encodeRemoteWebRtcOfferV1,
  remoteSignalingEventDigest,
} from "./remote-signaling-attempt-store";
import {
  decodeRemoteChildAuthenticationBundleV1,
  decodeRemoteFallbackNoiseCompleteV1,
  decodeRemoteFallbackPairAuthenticatedV1,
  decodeRemoteSignalingReadyV1,
} from "./remote-signaling-payloads";

const bytes = (text: string) =>
  Uint8Array.from(text.match(/../g)!.map((value) => Number.parseInt(value, 16)));
const hex = (value: Uint8Array) =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("remote signaling attempt-store wire fixtures", () => {
  it("consumes literal common and fallback payload vectors", () => {
    expect(
      decodeRemoteChildAuthenticationBundleV1(bytes(fixture.payloads.fcabHex)).childAttemptId,
    ).toEqual(bytes("0102030405060708090a0b0c0d0e0f10"));
    expect(
      decodeRemoteFallbackPairAuthenticatedV1(bytes(fixture.payloads.fallbackPairHex))
        .admissionSequence,
    ).toBe(1n);
    expect(decodeRemoteFallbackNoiseCompleteV1(bytes(fixture.payloads.fallbackNoiseHex)).role).toBe(
      1,
    );
    expect(
      decodeRemoteSignalingReadyV1(bytes(fixture.payloads.readyHex)).finalProofSetDigest,
    ).toEqual(new Uint8Array(32).fill(0xaa));
  });
  it("uses independently fixed FCSE digest and FCAK bytes", () => {
    expect(fixture.transitions.length).toBeGreaterThan(0);
    for (const vector of fixture.requests) {
      const raw = bytes(vector.requestHex),
        decoded = decodeRemoteSignalingEventRequestV1(raw);
      expect(hex(encodeRemoteSignalingEventRequestV1(decoded))).toBe(vector.requestHex);
      expect(hex(remoteSignalingEventDigest(raw))).toBe(vector.eventDigestHex);
      const ack = decodeRemoteSignalingCommitAckV1(bytes(vector.ackHex));
      expect(hex(encodeRemoteSignalingCommitAckV1(ack))).toBe(vector.ackHex);
      expect(hex(ack.eventDigest)).toBe(vector.eventDigestHex);
    }
  });
  it("rejects malformed literal requests", () => {
    for (const vector of fixture.malformedRequests) {
      const message =
        vector.rejection === "length"
          ? /truncated|length|cap/
          : vector.rejection === "zero_id"
            ? /zero/
            : vector.rejection === "combination"
              ? /requires|disagree/
              : /magic|version|unknown|invalid/;
      expect(() => decodeRemoteSignalingEventRequestV1(bytes(vector.requestHex))).toThrow(message);
    }
  });
  it("round trips strict WebRTC signaling payloads and rejects admin FCWA", () => {
    const childAttemptId = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
    const transportEpoch = Uint8Array.from({ length: 16 }, (_, index) => index + 21);
    const description = {
      childAttemptId,
      transportEpoch,
      descriptionId: Uint8Array.from({ length: 16 }, (_, index) => index + 41),
      sdp: new TextEncoder().encode("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n"),
    };
    expect(decodeRemoteWebRtcOfferV1(encodeRemoteWebRtcOfferV1(description))).toEqual(description);
    const answer = encodeRemoteWebRtcAnswerV1(description);
    expect(decodeRemoteWebRtcAnswerV1(answer)).toEqual(description);
    const admin = answer.slice();
    admin.set(new TextEncoder().encode("FCWA"));
    expect(() => decodeRemoteWebRtcAnswerV1(admin)).toThrow();
    const candidate = {
      role: 1 as const,
      childAttemptId,
      transportEpoch,
      candidateId: Uint8Array.from({ length: 16 }, (_, index) => index + 61),
      sdpMid: "0",
      sdpMLineIndex: 0,
      candidate: "candidate:1 1 UDP 1 192.0.2.1 9 typ host",
    };
    expect(decodeRemoteWebRtcCandidateV1(encodeRemoteWebRtcCandidateV1(candidate))).toEqual(
      candidate,
    );
    const complete = { role: 2 as const, childAttemptId, transportEpoch };
    expect(decodeRemoteWebRtcIceCompleteV1(encodeRemoteWebRtcIceCompleteV1(complete))).toEqual(
      complete,
    );
  });
});
