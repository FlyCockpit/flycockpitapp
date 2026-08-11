/**
 * Exact close-code table for the remote signaling gateway.
 *
 * These are the only close codes the gateway may send. Public reasons contain
 * only the exact string named here — no ticket, proof, identity, or diagnostic
 * material leaks into a close reason, URL, cookie, log, or metric.
 */
export const REMOTE_GATEWAY_CLOSE_CODE = {
  /** Protocol invalid: wrong path, subprotocol, text frame, noncanonical bytes, compression. */
  protocol_invalid: 4400,
  /** Authentication failed: bad ticket, bad certificate, bad signature, wrong Origin class. */
  authentication_failed: 4401,
  /** Authorization revoked or no longer valid. */
  authorization_revoked: 4403,
  /** Pre-auth deadline exceeded (5 s, one frame, 4096 aggregate bytes). */
  authentication_timeout: 4408,
  /** Conflict or superseded by a newer generation. */
  conflict_or_superseded: 4409,
  /** Rate limit or backpressure exhaustion (256 events / 2 MiB queue). */
  rate_or_backpressure: 4429,
  /** Redis or Postgres dependency unavailable. */
  dependency_unavailable: 4503,
} as const;

export type RemoteGatewayCloseCode =
  (typeof REMOTE_GATEWAY_CLOSE_CODE)[keyof typeof REMOTE_GATEWAY_CLOSE_CODE];

/** The exact reason string for each close code — no other text is sent. */
export const REMOTE_GATEWAY_CLOSE_REASON: Record<RemoteGatewayCloseCode, string> = {
  4400: "protocol_invalid",
  4401: "authentication_failed",
  4403: "authorization_revoked",
  4408: "authentication_timeout",
  4409: "conflict_or_superseded",
  4429: "rate_or_backpressure",
  4503: "dependency_unavailable",
};

/** The two accepted subprotocols. */
export const REMOTE_GATEWAY_SUBPROTOCOL = {
  /** One client child attempt — browser or native. */
  signal: "flycockpit.remote-signal.v1",
  /** One persistent daemon instance generation. */
  control: "flycockpit.remote-control.v1",
} as const;

/** The later data-fallback subprotocol (routed through the same origin verifier). */
export const REMOTE_GATEWAY_DATA_SUBPROTOCOL = "flycockpit.remote-data.v1";

/** The exact WebSocket upgrade path. */
export const REMOTE_GATEWAY_WS_PATH = "/api/remote/ws";

/** Pre-auth limits: five seconds, one frame, 4096 aggregate bytes. */
export const REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS = 5_000;
export const REMOTE_GATEWAY_PREAUTH_MAX_FRAMES = 1;
export const REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES = 4_096;

/** Authenticated signaling/control frame cap. */
export const REMOTE_GATEWAY_MAX_FRAME_BYTES = 131_072;
/** SDP payload cap. */
export const REMOTE_GATEWAY_MAX_SDP_BYTES = 122_880;
/** ICE candidate cap. */
export const REMOTE_GATEWAY_MAX_ICE_CANDIDATE_BYTES = 4_096;

/** Daemon certificate JWS cap inside FCDA. */
export const REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES = 4_096;
/** Whole FCDA frame cap. */
export const REMOTE_GATEWAY_MAX_FCDA_BYTES = 4_215;
/** Whole FCSA frame cap. */
export const REMOTE_GATEWAY_MAX_FCSA_BYTES = 564;
/** Client admission proof cap. */
export const REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES = 509;
/** Lease/status JWS cap. */
export const REMOTE_GATEWAY_MAX_LEASE_STATUS_JWS_BYTES = 16_384;

/** Backpressure: max unacknowledged events and queued bytes per socket. */
export const REMOTE_GATEWAY_MAX_UNACKED_EVENTS = 256;
export const REMOTE_GATEWAY_MAX_QUEUED_BYTES = 2 * 1024 * 1024;

/** Replay page bounds. */
export const REMOTE_GATEWAY_REPLAY_MAX_EVENTS = 64;
export const REMOTE_GATEWAY_REPLAY_MAX_BYTES = 512 * 1024;

/** Rate constants (token buckets with injected monotonic time). */
export const REMOTE_GATEWAY_RATE = {
  unauthUpgrade: { perMinute: 10, burst: 5 },
  signaling: { perSecond: 64, burst: 128 },
  daemonControl: { perSecond: 32, burst: 64 },
  maxIceCandidatesPerRoleAttempt: 64,
  ticketCreationPerMinuteDevice: 10,
  ticketCreationPerMinuteAccount: 30,
  maxConcurrentSignalingSocketsPerDeviceAttachment: 2,
  maxControlSocketsPerInstanceGeneration: 1,
} as const;

/** Daemon presence lease constants. */
export const REMOTE_GATEWAY_PRESENCE_RENEWAL_MS = 15_000;
export const REMOTE_GATEWAY_PRESENCE_EXPIRY_MS = 45_000;

/** Origin classes — closed set. */
export type RemoteGatewayOriginClass =
  | "browser_same_origin"
  | "native_no_origin"
  | "daemon_no_origin";
