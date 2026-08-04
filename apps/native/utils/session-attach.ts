export type NativeAttachAttempt = {
  id: number;
  client: object;
  connectionEpoch: number;
  sessionId: string;
};

type AppliedNativeAttachment = Omit<NativeAttachAttempt, "id">;

export class NativeAttachCoordinator {
  private nextId = 0;
  private current: NativeAttachAttempt | null = null;
  private applied: AppliedNativeAttachment | null = null;

  begin(client: object, connectionEpoch: number, sessionId: string): NativeAttachAttempt {
    const attempt = {
      id: ++this.nextId,
      client,
      connectionEpoch,
      sessionId,
    };
    // Attach mutates the daemon connection's destination before every later
    // hydration step is guaranteed to succeed. Starting any new attempt must
    // therefore revoke the previous session's readiness immediately.
    this.applied = null;
    this.current = attempt;
    return attempt;
  }

  invalidate() {
    this.nextId += 1;
    this.current = null;
    this.applied = null;
  }

  isCurrent(attempt: NativeAttachAttempt, client: object | null, connectionEpoch: number) {
    return (
      attempt.id === this.current?.id &&
      attempt.client === client &&
      attempt.connectionEpoch === connectionEpoch
    );
  }

  finish(attempt: NativeAttachAttempt, client: object | null, connectionEpoch: number) {
    if (!this.isCurrent(attempt, client, connectionEpoch)) return false;
    this.current = null;
    return true;
  }

  hasPending() {
    return this.current !== null;
  }

  isApplied(client: object, connectionEpoch: number, sessionId: string) {
    return (
      this.applied?.client === client &&
      this.applied.connectionEpoch === connectionEpoch &&
      this.applied.sessionId === sessionId
    );
  }

  isReady(client: object, connectionEpoch: number, sessionId: string) {
    return !this.hasPending() && this.isApplied(client, connectionEpoch, sessionId);
  }

  markApplied(attempt: NativeAttachAttempt, client: object | null, connectionEpoch: number) {
    if (!this.isCurrent(attempt, client, connectionEpoch)) return false;
    this.applied = {
      client: attempt.client,
      connectionEpoch: attempt.connectionEpoch,
      sessionId: attempt.sessionId,
    };
    return true;
  }

  needsAttach(client: object, connectionEpoch: number, sessionId: string) {
    const matches = (attachment: AppliedNativeAttachment | NativeAttachAttempt | null) =>
      attachment?.client === client &&
      attachment.connectionEpoch === connectionEpoch &&
      attachment.sessionId === sessionId;
    return !matches(this.current) && !matches(this.applied);
  }
}
