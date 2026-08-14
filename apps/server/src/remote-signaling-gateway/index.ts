/**
 * Remote signaling gateway — public surface.
 *
 * Importing this module opens zero Redis sockets. Explicit lazy command/
 * subscription factories start at server startup and close at shutdown.
 */

export {
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
  REMOTE_CONTROL_EVENT_MAX_COMPACT_JWS,
  REMOTE_CONTROL_EVENT_MAX_PAYLOAD,
  RemoteControlEventKind,
  type RemoteControlEventKindV1,
  type RemoteControlEventV1,
  RemoteGatewayCodecError,
} from "./binary-codecs";
export {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_CLOSE_REASON,
  REMOTE_GATEWAY_DATA_SUBPROTOCOL,
  REMOTE_GATEWAY_MAX_FRAME_BYTES,
  REMOTE_GATEWAY_MAX_ICE_CANDIDATE_BYTES,
  REMOTE_GATEWAY_MAX_QUEUED_BYTES,
  REMOTE_GATEWAY_MAX_SDP_BYTES,
  REMOTE_GATEWAY_MAX_UNACKED_EVENTS,
  REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES_CONTROL,
  REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES_SIGNAL,
  REMOTE_GATEWAY_PREAUTH_MAX_FRAMES,
  REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS,
  REMOTE_GATEWAY_PRESENCE_EXPIRY_MS,
  REMOTE_GATEWAY_PRESENCE_RENEWAL_MS,
  REMOTE_GATEWAY_RATE,
  REMOTE_GATEWAY_REPLAY_MAX_BYTES,
  REMOTE_GATEWAY_REPLAY_MAX_EVENTS,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
  type RemoteGatewayCloseCode,
  type RemoteGatewayOriginClass,
} from "./close-codes";
export {
  DaemonCertificateVerificationError,
  type DaemonCertificateVerifier,
  daemonControlAuthPreimage,
  RingDaemonCertificateVerifier,
  type VerifiedDaemonIdentity,
} from "./daemon-certificate-verifier";
export {
  createRemoteSignalingGateway,
  RemoteSignalingGateway,
  type RemoteSignalingGatewayConfig,
  type SafeLogger,
} from "./gateway";
export {
  OriginVerificationError,
  subprotocolExpectedOriginClass,
  verifyOriginClass,
} from "./origin-verifier";
export type { MonotonicClock } from "./rate-limiters";
export {
  DaemonControlRateLimiter,
  SignalingFrameRateLimiter,
  TicketCreationRateLimiter,
  TokenBucket,
  UnauthUpgradeRateLimiter,
} from "./rate-limiters";
export {
  InMemoryRemoteSignalingWakeSubscription,
  type RemoteSignalingWakeSubscription,
} from "./wake-subscription";
