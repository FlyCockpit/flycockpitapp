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
  decryptRecord(handle: bigint, routingSequence: bigint, ciphertext: ArrayBuffer): ArrayBuffer;
  close(handle: bigint): void;
}

export default TurboModuleRegistry.getEnforcing<Spec>("CockpitNoise");
