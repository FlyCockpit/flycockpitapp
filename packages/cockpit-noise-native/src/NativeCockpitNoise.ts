import type { TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

/** Thin New-Architecture surface. All operations delegate to UniFFI/Rust. */
export interface Spec extends TurboModule {
  createInitiator(prologue: ArrayBuffer, transportEpoch: number): bigint;
  createResponder(prologue: ArrayBuffer, transportEpoch: number): bigint;
  writeHandshake(handle: bigint): ArrayBuffer;
  readHandshake(handle: bigint, frame: ArrayBuffer): void;
  handshakeHash(handle: bigint): ArrayBuffer;
  /** Invokes the native signaling-owned verifier callback before opening split state. */
  authorize(handle: bigint, clientFinalProof: ArrayBuffer, daemonFinalProof: ArrayBuffer): void;
  encryptRecord(handle: bigint, kind: number, payload: ArrayBuffer): ArrayBuffer;
  encryptFallbackRecord(
    handle: bigint,
    kind: number,
    routeGeneration: bigint,
    direction: number,
    peerSeenThrough: bigint,
    payload: ArrayBuffer,
  ): ArrayBuffer;
  encryptFallbackRekeyAction(
    handle: bigint,
    kind: number,
    routeGeneration: bigint,
    direction: number,
    peerSeenThrough: bigint,
    controlPayload: ArrayBuffer,
  ): ArrayBuffer;
  bindFallbackRoute(handle: bigint, routeGeneration: bigint): void;
  decryptRecord(handle: bigint, routingSequence: bigint, ciphertext: ArrayBuffer): ArrayBuffer;
  decryptFallbackRecord(handle: bigint, outerRecord: ArrayBuffer): ArrayBuffer;
  fallbackCreate(nowMillis: bigint): bigint;
  fallbackObserve(handle: bigint, outerRecord: ArrayBuffer): ArrayBuffer;
  fallbackAckDue(
    handle: bigint,
    nowMillis: bigint,
    immediate: boolean,
    receivedAckOnly: boolean,
  ): ArrayBuffer;
  fallbackCacheOutgoing(
    handle: bigint,
    sequence: bigint,
    ciphertext: ArrayBuffer,
    kind: number,
  ): void;
  fallbackAcknowledge(handle: bigint, largestContiguous: bigint): void;
  fallbackGapRetransmit(handle: bigint, nextMissing: bigint): ArrayBuffer;
  fallbackRetryDue(handle: bigint, elapsedMillis: bigint): ArrayBuffer;
  fallbackClose(handle: bigint): void;
  close(handle: bigint): void;
}

export default TurboModuleRegistry.getEnforcing<Spec>("CockpitNoise");
