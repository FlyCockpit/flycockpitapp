export type RemotePolicyStrengthV1 = {
  minimumProtocolVersion: number;
  minimumKeyBits: number;
  sessionTtlSeconds: number;
  attemptGrantTtlSeconds: number;
  requireDeviceTrust: boolean;
  requireDaemonTrust: boolean;
};

/** Closed monotonic comparison: any relaxed dimension makes the revision weakening. */
export function classifyRemotePolicyRevision(
  current: RemotePolicyStrengthV1,
  proposed: RemotePolicyStrengthV1,
): "equal_or_stronger" | "weakening" {
  const weakening =
    proposed.minimumProtocolVersion < current.minimumProtocolVersion ||
    proposed.minimumKeyBits < current.minimumKeyBits ||
    proposed.sessionTtlSeconds > current.sessionTtlSeconds ||
    proposed.attemptGrantTtlSeconds > current.attemptGrantTtlSeconds ||
    (current.requireDeviceTrust && !proposed.requireDeviceTrust) ||
    (current.requireDaemonTrust && !proposed.requireDaemonTrust);
  return weakening ? "weakening" : "equal_or_stronger";
}
