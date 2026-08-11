import { describe, expect, it } from "vitest";
import {
  decodeFcdaFrame,
  decodeFcdcFrame,
  decodeFcsaFrame,
  decodeGatewayAck,
  decodeRemoteControlEventHeader,
  encodeFcdaFrame,
  encodeFcdcFrame,
  encodeFcsaFrame,
  encodeGatewayAck,
  encodeRemoteControlEventHeader,
  FCDA_MAGIC,
  FCDC_BYTES,
  FCDC_MAGIC,
  FCRC_MAGIC,
  FCSA_MAGIC,
  REMOTE_CONTROL_EVENT_HEADER_BYTES,
  REMOTE_CONTROL_EVENT_MAX_BYTES,
  REMOTE_CONTROL_EVENT_MAX_PAYLOAD,
  RemoteControlEventKind,
  RemoteGatewayCodecError,
} from "./binary-codecs";
import {
  REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES,
  REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES,
  REMOTE_GATEWAY_MAX_FCDA_BYTES,
  REMOTE_GATEWAY_MAX_FCSA_BYTES,
} from "./close-codes";

const randomId = () => crypto.getRandomValues(new Uint8Array(16));
const random32 = () => crypto.getRandomValues(new Uint8Array(32));
const random64 = () => crypto.getRandomValues(new Uint8Array(64));

describe("remote_gateway_binary_codec: FCDC challenge", () => {
  it("encodes and decodes exact 53-byte FCDC frame", () => {
    const challenge = random32();
    const frame = encodeFcdcFrame({
      challenge,
      issuedAt: 1_000n,
      expiresAt: 5_000n,
    });
    expect(frame.length).toBe(FCDC_BYTES);
    expect(String.fromCharCode(...frame.slice(0, 4))).toBe(FCDC_MAGIC);
    expect(frame[4]).toBe(1);

    const decoded = decodeFcdcFrame(frame);
    expect(decoded.challenge).toEqual(challenge);
    expect(decoded.issuedAt).toBe(1_000n);
    expect(decoded.expiresAt).toBe(5_000n);
  });

  it("rejects wrong magic", () => {
    const frame = encodeFcdcFrame({
      challenge: random32(),
      issuedAt: 1_000n,
      expiresAt: 5_000n,
    });
    frame[0] = 0x58; // corrupt magic
    expect(() => decodeFcdcFrame(frame)).toThrow(RemoteGatewayCodecError);
  });

  it("rejects wrong length", () => {
    expect(() => decodeFcdcFrame(new Uint8Array(52))).toThrow(RemoteGatewayCodecError);
    expect(() => decodeFcdcFrame(new Uint8Array(54))).toThrow(RemoteGatewayCodecError);
  });

  it("rejects issuedAt >= expiresAt", () => {
    expect(() =>
      encodeFcdcFrame({ challenge: random32(), issuedAt: 5_000n, expiresAt: 5_000n }),
    ).toThrow(RemoteGatewayCodecError);
  });
});

describe("remote_gateway_binary_codec: FCDA daemon auth", () => {
  it("encodes and decodes a valid FCDA frame", () => {
    const certJws = crypto.getRandomValues(new Uint8Array(256));
    const frame = encodeFcdaFrame({
      certificateJws: certJws,
      connectionNonce: random32(),
      lastDiscoverySeq: 42n,
      lastControlSeq: 10n,
      signature: random64(),
    });
    expect(String.fromCharCode(...frame.slice(0, 4))).toBe(FCDA_MAGIC);
    expect(frame[4]).toBe(1);
    expect(frame.length).toBeLessThanOrEqual(REMOTE_GATEWAY_MAX_FCDA_BYTES);

    const decoded = decodeFcdaFrame(frame);
    expect(decoded.certificateJws).toEqual(certJws);
    expect(decoded.lastDiscoverySeq).toBe(42n);
    expect(decoded.lastControlSeq).toBe(10n);
    expect(decoded.signature.length).toBe(64);
  });

  it("accepts the maximum 4,096-byte certificate (frame = 4,215)", () => {
    const certJws = new Uint8Array(REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES);
    crypto.getRandomValues(certJws);
    const frame = encodeFcdaFrame({
      certificateJws: certJws,
      connectionNonce: random32(),
      lastDiscoverySeq: 0n,
      lastControlSeq: 0n,
      signature: random64(),
    });
    expect(frame.length).toBe(REMOTE_GATEWAY_MAX_FCDA_BYTES);
    const decoded = decodeFcdaFrame(frame);
    expect(decoded.certificateJws.length).toBe(REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES);
  });

  it("rejects frame exceeding 4,215 bytes", () => {
    const certJws = new Uint8Array(REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES + 1);
    expect(() =>
      encodeFcdaFrame({
        certificateJws: certJws,
        connectionNonce: random32(),
        lastDiscoverySeq: 0n,
        lastControlSeq: 0n,
        signature: random64(),
      }),
    ).toThrow(RemoteGatewayCodecError);
  });

  it("rejects trailing bytes", () => {
    const frame = encodeFcdaFrame({
      certificateJws: crypto.getRandomValues(new Uint8Array(100)),
      connectionNonce: random32(),
      lastDiscoverySeq: 0n,
      lastControlSeq: 0n,
      signature: random64(),
    });
    const padded = new Uint8Array(frame.length + 1);
    padded.set(frame);
    padded[frame.length] = 0;
    expect(() => decodeFcdaFrame(padded)).toThrow(RemoteGatewayCodecError);
  });

  it("rejects wrong magic/version", () => {
    const frame = encodeFcdaFrame({
      certificateJws: crypto.getRandomValues(new Uint8Array(100)),
      connectionNonce: random32(),
      lastDiscoverySeq: 0n,
      lastControlSeq: 0n,
      signature: random64(),
    });
    frame[0] = 0x58;
    expect(() => decodeFcdaFrame(frame)).toThrow(RemoteGatewayCodecError);
  });
});

describe("remote_gateway_binary_codec: FCSA client auth", () => {
  it("encodes and decodes a valid FCSA frame", () => {
    const ticketId = randomId();
    const ticketSecret = random32();
    const admissionProof = crypto.getRandomValues(new Uint8Array(200));
    const frame = encodeFcsaFrame({ ticketId, ticketSecret, admissionProof });
    expect(String.fromCharCode(...frame.slice(0, 4))).toBe(FCSA_MAGIC);
    expect(frame[4]).toBe(1);
    expect(frame.length).toBeLessThanOrEqual(REMOTE_GATEWAY_MAX_FCSA_BYTES);

    const decoded = decodeFcsaFrame(frame);
    expect(decoded.ticketId).toEqual(ticketId);
    expect(decoded.ticketSecret).toEqual(ticketSecret);
    expect(decoded.admissionProof).toEqual(admissionProof);
  });

  it("accepts the maximum 509-byte admission proof (frame = 564)", () => {
    const admissionProof = new Uint8Array(REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES);
    crypto.getRandomValues(admissionProof);
    const frame = encodeFcsaFrame({
      ticketId: randomId(),
      ticketSecret: random32(),
      admissionProof,
    });
    expect(frame.length).toBe(REMOTE_GATEWAY_MAX_FCSA_BYTES);
    const decoded = decodeFcsaFrame(frame);
    expect(decoded.admissionProof.length).toBe(REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES);
  });

  it("rejects frame exceeding 564 bytes", () => {
    const admissionProof = new Uint8Array(REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES + 1);
    expect(() =>
      encodeFcsaFrame({
        ticketId: randomId(),
        ticketSecret: random32(),
        admissionProof,
      }),
    ).toThrow(RemoteGatewayCodecError);
  });

  it("rejects trailing/truncated bytes", () => {
    const frame = encodeFcsaFrame({
      ticketId: randomId(),
      ticketSecret: random32(),
      admissionProof: crypto.getRandomValues(new Uint8Array(100)),
    });
    const padded = new Uint8Array(frame.length + 1);
    padded.set(frame);
    padded[frame.length] = 0;
    expect(() => decodeFcsaFrame(padded)).toThrow(RemoteGatewayCodecError);
  });

  it("rejects zero ticketId", () => {
    expect(() =>
      encodeFcsaFrame({
        ticketId: new Uint8Array(16),
        ticketSecret: random32(),
        admissionProof: crypto.getRandomValues(new Uint8Array(100)),
      }),
    ).toThrow(RemoteGatewayCodecError);
  });
});

describe("remote_gateway_binary_codec: RemoteControlEventV1 header", () => {
  it("encodes and decodes a valid 98-byte header", () => {
    const eventId = randomId();
    const payloadDigest = random32();
    const header = encodeRemoteControlEventHeader({
      controlSeq: 1n,
      eventId,
      kind: RemoteControlEventKind.lease_refresh,
      serviceVersion: 9n,
      policyEpoch: 1n,
      authorityEpoch: 1n,
      issuedAt: 1_000n,
      payloadLength: 256,
      payloadDigest,
    });
    expect(header.length).toBe(REMOTE_CONTROL_EVENT_HEADER_BYTES);
    expect(String.fromCharCode(...header.slice(0, 4))).toBe(FCRC_MAGIC);
    expect(header[4]).toBe(1);

    const decoded = decodeRemoteControlEventHeader(header);
    expect(decoded.controlSeq).toBe(1n);
    expect(decoded.eventId).toEqual(eventId);
    expect(decoded.kind).toBe(RemoteControlEventKind.lease_refresh);
    expect(decoded.payloadLength).toBe(256);
    expect(decoded.payloadDigest).toEqual(payloadDigest);
  });

  it("rejects payload exceeding 65,536 bytes", () => {
    expect(() =>
      encodeRemoteControlEventHeader({
        controlSeq: 1n,
        eventId: randomId(),
        kind: RemoteControlEventKind.drain,
        serviceVersion: 9n,
        policyEpoch: 1n,
        authorityEpoch: 1n,
        issuedAt: 1_000n,
        payloadLength: REMOTE_CONTROL_EVENT_MAX_PAYLOAD + 1,
        payloadDigest: random32(),
      }),
    ).toThrow(RemoteGatewayCodecError);
  });

  it("rejects unknown kind", () => {
    const header = encodeRemoteControlEventHeader({
      controlSeq: 1n,
      eventId: randomId(),
      kind: RemoteControlEventKind.drain,
      serviceVersion: 9n,
      policyEpoch: 1n,
      authorityEpoch: 1n,
      issuedAt: 1_000n,
      payloadLength: 100,
      payloadDigest: random32(),
    });
    header[29] = 9; // unknown kind
    expect(() => decodeRemoteControlEventHeader(header)).toThrow(RemoteGatewayCodecError);
  });

  it("rejects controlSeq < 1", () => {
    expect(() =>
      encodeRemoteControlEventHeader({
        controlSeq: 0n,
        eventId: randomId(),
        kind: RemoteControlEventKind.drain,
        serviceVersion: 9n,
        policyEpoch: 1n,
        authorityEpoch: 1n,
        issuedAt: 1_000n,
        payloadLength: 100,
        payloadDigest: random32(),
      }),
    ).toThrow(RemoteGatewayCodecError);
  });

  it("proves whole event max is 65,634 bytes", () => {
    expect(REMOTE_CONTROL_EVENT_MAX_BYTES).toBe(
      REMOTE_CONTROL_EVENT_HEADER_BYTES + REMOTE_CONTROL_EVENT_MAX_PAYLOAD,
    );
  });
});

describe("remote_gateway_binary_codec: gateway ACK", () => {
  it("encodes and decodes a valid 26-byte ACK", () => {
    const commandId = randomId();
    const ack = encodeGatewayAck({
      kind: 1,
      commandId,
      committedSequence: 42n,
    });
    expect(ack.length).toBe(26);
    expect(ack[0]).toBe(1);
    const decoded = decodeGatewayAck(ack);
    expect(decoded.kind).toBe(1);
    expect(decoded.commandId).toEqual(commandId);
    expect(decoded.committedSequence).toBe(42n);
  });

  it("rejects wrong length", () => {
    expect(() => decodeGatewayAck(new Uint8Array(25))).toThrow(RemoteGatewayCodecError);
    expect(() => decodeGatewayAck(new Uint8Array(27))).toThrow(RemoteGatewayCodecError);
  });

  it("rejects wrong version", () => {
    const ack = encodeGatewayAck({ kind: 1, commandId: randomId(), committedSequence: 1n });
    ack[0] = 2;
    expect(() => decodeGatewayAck(ack)).toThrow(RemoteGatewayCodecError);
  });
});
