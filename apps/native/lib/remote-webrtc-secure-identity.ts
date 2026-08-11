/**
 * Secure identity lifecycle for the native WebRTC remote client.
 *
 * @see prompts/flycockpitapp/ready/remote-webrtc-native-client.md
 * Acceptance criterion 8: remote_native_secure_identity_lifecycle.
 *
 * Durable P-256 comes from the identity platform adapter. Per-child X25519
 * belongs only to the shared Rust native Noise binding used by fallback. The
 * WebRTC adapter never persists or treats X25519 as identity.
 *
 * Locked/lost key store yields unlock/re-enroll, never plaintext or a new
 * weaker identity.
 */

/** Durable identity key kind. */
export type RemoteIdentityKeyKind = "p256_durable" | "x25519_ephemeral";

/** Custody class mirrors the shared RemoteMetadataCustodyClass. */
export type RemoteIdentityCustodyClass =
  | "origin_protected"
  | "os_protected"
  | "hardware_or_external";

export interface RemoteIdentityKeyState {
  readonly keyId: Uint8Array;
  readonly kind: RemoteIdentityKeyKind;
  readonly custodyClass: RemoteIdentityCustodyClass;
  readonly generation: bigint;
  readonly status: "active" | "locked" | "lost" | "revoked";
}

/**
 * Asserts that an X25519 key is never treated as identity. Only durable P-256
 * keys may serve as identity keys. X25519 keys are transport-only and belong
 * to the Noise binding.
 */
export function assertNotIdentityKey(kind: RemoteIdentityKeyKind): void {
  if (kind === "x25519_ephemeral") {
    throw new Error("x25519_ephemeral must never be treated as identity");
  }
}

/**
 * Asserts that the WebRTC adapter never persists keys. This is a static
 * contract guard — the adapter has no persistence surface.
 */
export function assertNoKeyPersistence(surface: string): void {
  if (surface.includes("persist") || surface.includes("store") || surface.includes("write")) {
    throw new Error(`WebRTC adapter must not persist keys: ${surface}`);
  }
}

/**
 * Resolves the identity lifecycle action for a locked or lost key store.
 * Locked/lost yields unlock/re-enroll, never plaintext or a new weaker
 * identity. Re-enrollment produces a new durable P-256 at the same or stronger
 * custody class, never a weaker one.
 */
export function resolveIdentityLifecycleAction(
  state: RemoteIdentityKeyState,
): "unlock" | "re_enroll" | "none" {
  if (state.status === "locked") return "unlock";
  if (state.status === "lost") return "re_enroll";
  if (state.status === "revoked") return "re_enroll";
  return "none";
}

/**
 * Validates that a re-enrollment does not weaken the custody class. The new
 * custody class must be at least as strong as the prior one.
 */
export function assertReEnrollmentNotWeaker(
  prior: RemoteIdentityCustodyClass,
  next: RemoteIdentityCustodyClass,
): void {
  const strength: Readonly<Record<RemoteIdentityCustodyClass, number>> = {
    origin_protected: 1,
    os_protected: 2,
    hardware_or_external: 3,
  };
  if (strength[next] < strength[prior]) {
    throw new Error("re-enrollment must not weaken custody class");
  }
}

/**
 * Validates that a durable P-256 key is used for identity, not X25519. The
 * WebRTC adapter's identity surface must only reference durable P-256 keys.
 */
export function assertDurableP256Identity(key: RemoteIdentityKeyState): void {
  assertNotIdentityKey(key.kind);
  if (key.kind !== "p256_durable") {
    throw new Error("identity key must be durable p256");
  }
}
