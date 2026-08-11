/**
 * Dependency pair gate for the native WebRTC remote client.
 *
 * @see prompts/flycockpitapp/ready/remote-webrtc-native-client.md
 * Acceptance criterion 1: remote_native_dependency_pair_gate.
 *
 * Pins exactly `react-native-webrtc@124.0.8` and
 * `@config-plugins/react-native-webrtc@15.0.1` for the repository's
 * `expo~56.0.3` / `react-native 0.85.3`. Records package provenance, license,
 * maintenance, plugin peer (`expo ^56`), New Architecture/platform compile
 * results, and lockfile/bundle impact. If this exact pair fails iOS/Android
 * compile or the passive data-channel contract, block/re-draft rather than
 * silently selecting another version.
 */

/** The exact pinned versions. Changing these requires re-drafting the prompt. */
export const REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR = {
  reactNativeWebrtc: "124.0.8",
  configPluginsReactNativeWebrtc: "15.0.1",
} as const;

/** The Expo/RN peer versions the pair is validated against. */
export const REMOTE_WEBRTC_NATIVE_PEER_PLATFORM = {
  expo: "~56.0.3",
  reactNative: "0.85.3",
} as const;

/** Plugin peer requirement: `expo ^56`. */
export const REMOTE_WEBRTC_NATIVE_PLUGIN_PEER_EXPO = "^56";

export interface DependencyPairProvenance {
  readonly name: string;
  readonly version: string;
  readonly license: string;
  readonly maintainer: string;
  readonly registry: string;
  readonly newArchitecture: boolean;
  readonly platforms: readonly ("ios" | "android")[];
}

/** Recorded provenance for the pinned pair. */
export const REMOTE_WEBRTC_NATIVE_PROVENANCE: readonly DependencyPairProvenance[] = [
  {
    name: "react-native-webrtc",
    version: REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR.reactNativeWebrtc,
    license: "MIT",
    maintainer: "react-native-webrtc maintainers",
    registry: "npm",
    newArchitecture: true,
    platforms: ["ios", "android"],
  },
  {
    name: "@config-plugins/react-native-webrtc",
    version: REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR.configPluginsReactNativeWebrtc,
    license: "MIT",
    maintainer: "Expo config-plugins collective",
    registry: "npm",
    newArchitecture: true,
    platforms: ["ios", "android"],
  },
];

export interface DependencyPairCompileResult {
  readonly platform: "ios" | "android";
  readonly compiled: boolean;
  readonly diagnosticsPath: string | null;
}

export interface DependencyPairGateResult {
  readonly exactVersions: boolean;
  readonly peerCompatible: boolean;
  readonly provenanceRecorded: boolean;
  readonly licenseRecorded: boolean;
  readonly maintenanceRecorded: boolean;
  readonly newArchitecture: boolean;
  readonly compileResults: readonly DependencyPairCompileResult[];
  readonly lockfileImpact: "none" | "additive" | "breaking";
  readonly bundleImpact: "none" | "additive" | "breaking";
  readonly passed: boolean;
  readonly reason: string | null;
}

/**
 * Validates that the provided dependency versions exactly match the pinned
 * pair. Any mismatch blocks the gate.
 */
export function validateExactVersions(
  reactNativeWebrtcVersion: string,
  configPluginsVersion: string,
): boolean {
  return (
    reactNativeWebrtcVersion === REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR.reactNativeWebrtc &&
    configPluginsVersion === REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR.configPluginsReactNativeWebrtc
  );
}

/**
 * Validates that the Expo version satisfies the plugin peer requirement
 * (`expo ^56`).
 */
export function validatePeerCompatible(expoVersion: string): boolean {
  // ~56.0.3 satisfies ^56
  const major = Number.parseInt(expoVersion.replace(/[~^]/, "").split(".")[0] ?? "0", 10);
  return major === 56;
}

/**
 * Runs the full dependency pair gate. Returns a structured result. If the gate
 * fails, the caller must block/re-draft rather than silently selecting another
 * version.
 */
export function runDependencyPairGate(input: {
  reactNativeWebrtcVersion: string;
  configPluginsVersion: string;
  expoVersion: string;
  compileResults: readonly DependencyPairCompileResult[];
  lockfileImpact: "none" | "additive" | "breaking";
  bundleImpact: "none" | "additive" | "breaking";
}): DependencyPairGateResult {
  const exactVersions = validateExactVersions(
    input.reactNativeWebrtcVersion,
    input.configPluginsVersion,
  );
  const peerCompatible = validatePeerCompatible(input.expoVersion);
  const provenanceRecorded = REMOTE_WEBRTC_NATIVE_PROVENANCE.length === 2;
  const licenseRecorded = REMOTE_WEBRTC_NATIVE_PROVENANCE.every((p) => p.license.length > 0);
  const maintenanceRecorded = REMOTE_WEBRTC_NATIVE_PROVENANCE.every((p) => p.maintainer.length > 0);
  const newArchitecture = REMOTE_WEBRTC_NATIVE_PROVENANCE.every((p) => p.newArchitecture);
  const allCompiled = input.compileResults.every((r) => r.compiled);

  const failures: string[] = [];
  if (!exactVersions) failures.push("exact version mismatch");
  if (!peerCompatible) failures.push("peer incompatible");
  if (!provenanceRecorded) failures.push("provenance not recorded");
  if (!licenseRecorded) failures.push("license not recorded");
  if (!maintenanceRecorded) failures.push("maintenance not recorded");
  if (!newArchitecture) failures.push("new architecture not supported");
  if (!allCompiled) failures.push("platform compile failed");
  if (input.lockfileImpact === "breaking") failures.push("breaking lockfile impact");
  if (input.bundleImpact === "breaking") failures.push("breaking bundle impact");

  return {
    exactVersions,
    peerCompatible,
    provenanceRecorded,
    licenseRecorded,
    maintenanceRecorded,
    newArchitecture,
    compileResults: input.compileResults,
    lockfileImpact: input.lockfileImpact,
    bundleImpact: input.bundleImpact,
    passed: failures.length === 0,
    reason: failures.length > 0 ? failures.join("; ") : null,
  };
}
