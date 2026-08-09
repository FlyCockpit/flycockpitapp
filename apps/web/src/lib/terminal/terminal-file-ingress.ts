import { TERMINAL_IMAGE_MAX_BYTES } from "@flycockpit/relay-protocol/terminal";

export const TERMINAL_INGRESS_QUEUE_LIMIT = 8;
export const TERMINAL_INGRESS_CHUNK_BYTES = 48 * 1024;
export const TERMINAL_INGRESS_OVERALL_MS = 120_000;
export const TERMINAL_INGRESS_HASH_MS = 15_000;
export const TERMINAL_INGRESS_REQUEST_MS = 10_000;
export const TERMINAL_INGRESS_FINISH_MS = 30_000;
export const TERMINAL_INGRESS_POST_OUTCOME_MS = 10_000;

export type TerminalImageMediaType = "image/png" | "image/jpeg" | "image/gif" | "image/webp";
export type TerminalIngressPhase =
  | "Queued"
  | "Hashing"
  | "Beginning"
  | "Uploading"
  | "Finishing"
  | "Reconciling"
  | "Committed"
  | "PrecommitFailed"
  | "CommitUnknown";
export type TerminalIngressErrorCode =
  | "Busy"
  | "TooManyFiles"
  | "TooLarge"
  | "UnsupportedType"
  | "HashFailed"
  | "Conflict"
  | "UploadFailed"
  | "MaterializationFailed"
  | "Expired"
  | "DeadlineExceeded"
  | "CommitUnknown"
  | "CleanupPending"
  | "Cancelled"
  | "TerminalUnavailable";

export type TerminalIngressIdentity = {
  clientInstanceId: string;
  sessionId: string;
  terminalId: string;
  terminalGeneration: number;
  bindingId: string;
  bindingEpoch: number;
};

export type TerminalIngressMetadata = {
  operationId: string;
  size: number;
  mediaType: TerminalImageMediaType;
  sha256: string;
};

export type TerminalIngressReceipt = {
  state: "prepared" | "committed" | "no_operation";
  nextOffset: number;
  inputSequence?: number;
};

export type TerminalIngressRequest = TerminalIngressIdentity & TerminalIngressMetadata;
export type TerminalIngressTransport = {
  begin(request: TerminalIngressRequest, signal: AbortSignal): Promise<TerminalIngressReceipt>;
  chunk(
    request: TerminalIngressRequest & { offset: number; dataBase64: string },
    signal: AbortSignal,
  ): Promise<TerminalIngressReceipt>;
  finish(request: TerminalIngressRequest, signal: AbortSignal): Promise<TerminalIngressReceipt>;
  status(request: TerminalIngressRequest, signal: AbortSignal): Promise<TerminalIngressReceipt>;
  abort(request: TerminalIngressRequest, signal: AbortSignal): Promise<TerminalIngressReceipt>;
};

export type TerminalIngressClock = {
  now(): number;
  setTimer(callback: () => void, milliseconds: number): ReturnType<typeof globalThis.setTimeout>;
  clearTimer(timer: ReturnType<typeof globalThis.setTimeout>): void;
};

export type TerminalIngressOutcome =
  | { kind: "committed"; operationId: string; inputSequence?: number }
  | {
      kind: "failed" | "unknown";
      operationId?: string;
      code: TerminalIngressErrorCode;
      phase?: Exclude<TerminalIngressPhase, "Committed" | "PrecommitFailed" | "CommitUnknown">;
      cleanup?: "clean" | "pending";
    };

export type TerminalIngressSnapshot = {
  operationId: string;
  operationGeneration: number;
  phase: TerminalIngressPhase;
  nextOffset: number;
  size: number;
  mediaType: TerminalImageMediaType;
};

type QueueEntry = {
  file: File;
  identity: TerminalIngressIdentity;
  acceptedAt: number;
  operationGeneration: number;
  controller: AbortController;
  resolve: (outcome: TerminalIngressOutcome) => void;
  operationId?: string;
};

class DeadlineError extends Error {
  constructor(
    readonly phase: Exclude<
      TerminalIngressSnapshot["phase"],
      "Committed" | "PrecommitFailed" | "CommitUnknown"
    >,
  ) {
    super(`terminal ingress deadline exceeded during ${phase}`);
  }
}

class HashError extends Error {}

const browserClock: TerminalIngressClock = {
  now: () => performance.now(),
  setTimer: (callback, milliseconds) => globalThis.setTimeout(callback, milliseconds),
  clearTimer: (timer) => globalThis.clearTimeout(timer),
};

export class TerminalFileIngressController {
  private readonly queue: QueueEntry[] = [];
  private active: QueueEntry | null = null;
  private operationGeneration = 0;
  private identityGeneration = 0;

  constructor(
    private readonly transport: TerminalIngressTransport,
    private readonly identity: () => TerminalIngressIdentity | null,
    private readonly clock: TerminalIngressClock = browserClock,
    private readonly onSnapshot: (snapshot: TerminalIngressSnapshot | null) => void = () => {},
  ) {}

  enqueue(file: File): Promise<TerminalIngressOutcome> {
    const identity = this.identity();
    if (!identity) return Promise.resolve({ kind: "failed", code: "TerminalUnavailable" });
    if (!isTerminalImageType(file.type)) {
      return Promise.resolve({ kind: "failed", code: "UnsupportedType" });
    }
    if (file.size < 1 || file.size > TERMINAL_IMAGE_MAX_BYTES) {
      return Promise.resolve({ kind: "failed", code: "TooLarge" });
    }
    if (this.queue.length + (this.active ? 1 : 0) >= TERMINAL_INGRESS_QUEUE_LIMIT) {
      return Promise.resolve({ kind: "failed", code: "Busy" });
    }
    return new Promise((resolve) => {
      this.operationGeneration += 1;
      this.queue.push({
        file,
        identity,
        acceptedAt: this.clock.now(),
        operationGeneration: this.operationGeneration,
        controller: new AbortController(),
        resolve,
        operationId: crypto.randomUUID(),
      });
      this.snapshot(this.queue[this.queue.length - 1] as QueueEntry, "Queued", 0);
      this.pump();
    });
  }

  updateIdentity(next: TerminalIngressIdentity | null) {
    const matches = (entry: QueueEntry) => next && sameTerminalGeneration(entry.identity, next);
    const oldIdentity = this.active?.identity ?? this.queue[0]?.identity;
    const generationChanged =
      !next || (oldIdentity ? !sameTerminalGeneration(oldIdentity, next) : false);
    if (generationChanged) this.identityGeneration += 1;
    if (this.active && !matches(this.active)) this.active.controller.abort();
    const retained: QueueEntry[] = [];
    for (const entry of this.queue) {
      if (next && matches(entry)) {
        entry.identity = {
          ...entry.identity,
          bindingId: next.bindingId,
          bindingEpoch: next.bindingEpoch,
        };
        retained.push(entry);
      } else
        entry.resolve({
          kind: "failed",
          operationId: entry.operationId,
          code: "TerminalUnavailable",
        });
    }
    this.queue.splice(0, this.queue.length, ...retained);
  }

  cancelAll() {
    this.updateIdentity(null);
  }

  private pump() {
    if (this.active || this.queue.length === 0) return;
    const entry = this.queue.shift();
    if (!entry) return;
    this.active = entry;
    void this.run(entry).then((outcome) => {
      entry.resolve(outcome);
      if (this.active === entry) this.active = null;
      this.onSnapshot(null);
      this.pump();
    });
  }

  private async run(entry: QueueEntry): Promise<TerminalIngressOutcome> {
    const guard = this.identityGeneration;
    const overallDeadline = entry.acceptedAt + TERMINAL_INGRESS_OVERALL_MS;
    let finishDispatched = false;
    let request: TerminalIngressRequest | null = null;
    try {
      this.assertCurrent(entry, guard);
      this.snapshot(entry, "Hashing", 0);
      let hashed: { bytes: Uint8Array; sha256: string };
      try {
        hashed = await this.effect(
          entry,
          guard,
          "Hashing",
          TERMINAL_INGRESS_HASH_MS,
          overallDeadline,
          async () => {
            const value = new Uint8Array(await entry.file.arrayBuffer());
            if (value.byteLength !== entry.file.size) throw new Error("bounded file size changed");
            const digest = await crypto.subtle.digest("SHA-256", value);
            return { bytes: value, sha256: bytesToHex(new Uint8Array(digest)) };
          },
        );
      } catch (error) {
        if (
          error instanceof DeadlineError ||
          (error instanceof DOMException && error.name === "AbortError")
        ) {
          throw error;
        }
        throw new HashError("terminal image digest failed");
      }
      const { bytes, sha256 } = hashed;
      const operationId = entry.operationId;
      if (!operationId) throw new Error("terminal ingress operation identity missing");
      request = {
        ...entry.identity,
        operationId,
        size: bytes.byteLength,
        mediaType: entry.file.type as TerminalImageMediaType,
        sha256,
      };
      this.snapshot(entry, "Beginning", 0);
      let receipt: TerminalIngressReceipt;
      try {
        receipt = await this.effect(
          entry,
          guard,
          "Beginning",
          TERMINAL_INGRESS_REQUEST_MS,
          overallDeadline,
          (signal) =>
            this.transport.begin(
              this.currentRequest(entry, request as TerminalIngressRequest),
              signal,
            ),
        );
      } catch {
        receipt = await this.recoverBeforeFinish(
          entry,
          guard,
          request,
          overallDeadline,
          "Beginning",
          true,
        );
      }
      if (receipt.state === "committed") return this.commit(entry, receipt);
      let offset = receipt.nextOffset;
      while (offset < bytes.byteLength) {
        this.snapshot(entry, "Uploading", offset);
        const end = Math.min(offset + TERMINAL_INGRESS_CHUNK_BYTES, bytes.byteLength);
        const chunk = bytes.slice(offset, end);
        try {
          receipt = await this.effect(
            entry,
            guard,
            "Uploading",
            TERMINAL_INGRESS_REQUEST_MS,
            overallDeadline,
            (signal) =>
              this.transport.chunk(
                {
                  ...this.currentRequest(entry, request as TerminalIngressRequest),
                  offset,
                  dataBase64: uint8ToBase64(chunk),
                },
                signal,
              ),
          );
        } catch {
          receipt = await this.recoverBeforeFinish(
            entry,
            guard,
            request,
            overallDeadline,
            "Uploading",
            false,
          );
        }
        if (receipt.state === "committed") return this.commit(entry, receipt);
        if (receipt.nextOffset < offset || receipt.nextOffset > bytes.byteLength) {
          throw new Error("non-monotonic terminal ingress offset");
        }
        offset = receipt.nextOffset;
      }
      this.snapshot(entry, "Finishing", offset);
      finishDispatched = true;
      receipt = await this.effect(
        entry,
        guard,
        "Finishing",
        TERMINAL_INGRESS_FINISH_MS,
        overallDeadline,
        (signal) =>
          this.transport.finish(
            this.currentRequest(entry, request as TerminalIngressRequest),
            signal,
          ),
      );
      if (receipt.state === "committed") return this.commit(entry, receipt);
      return this.reconcile(entry, guard, request);
    } catch (error) {
      if (finishDispatched && request) return this.reconcile(entry, guard, request);
      const liveIdentity = this.identity();
      const code =
        !liveIdentity || !sameTerminalGeneration(entry.identity, liveIdentity)
          ? "TerminalUnavailable"
          : classifyError(error);
      const cleanup = request
        ? await this.abortPrepared(
            entry,
            guard,
            request,
            this.clock.now() + TERMINAL_INGRESS_POST_OUTCOME_MS,
          )
        : undefined;
      if (cleanup === "committed" && request)
        return this.commit(entry, { state: "committed", nextOffset: request.size });
      const cleanupOutcome = cleanup === "clean" || cleanup === "pending" ? cleanup : undefined;
      this.snapshot(entry, "PrecommitFailed", 0);
      return {
        kind: "failed",
        operationId: entry.operationId,
        code,
        phase: error instanceof DeadlineError ? error.phase : undefined,
        cleanup: cleanupOutcome,
      };
    }
  }

  private async recoverBeforeFinish(
    entry: QueueEntry,
    guard: number,
    request: TerminalIngressRequest,
    overallDeadline: number,
    phase: "Beginning" | "Uploading",
    beginMayBeMissing: boolean,
  ): Promise<TerminalIngressReceipt> {
    const receipt = await this.effect(
      entry,
      guard,
      phase,
      TERMINAL_INGRESS_REQUEST_MS,
      overallDeadline,
      (signal) => this.transport.status(this.currentRequest(entry, request), signal),
    );
    if (receipt.state !== "no_operation") return receipt;
    if (!beginMayBeMissing) throw new Error("terminal ingress operation unavailable");
    this.snapshot(entry, "Beginning", 0);
    return this.effect(
      entry,
      guard,
      "Beginning",
      TERMINAL_INGRESS_REQUEST_MS,
      overallDeadline,
      (signal) => this.transport.begin(this.currentRequest(entry, request), signal),
    );
  }

  private async reconcile(
    entry: QueueEntry,
    guard: number,
    request: TerminalIngressRequest,
  ): Promise<TerminalIngressOutcome> {
    this.snapshot(entry, "Reconciling", request.size);
    const postDeadline = this.clock.now() + TERMINAL_INGRESS_POST_OUTCOME_MS;
    try {
      const receipt = await this.effect(
        entry,
        guard,
        "Reconciling",
        TERMINAL_INGRESS_REQUEST_MS,
        postDeadline,
        (signal) => this.transport.status(this.currentRequest(entry, request), signal),
      );
      if (receipt.state === "committed") return this.commit(entry, receipt);
      if (receipt.state === "prepared") {
        const cleanup = await this.abortPrepared(entry, guard, request, postDeadline);
        if (cleanup === "committed")
          return this.commit(entry, { state: "committed", nextOffset: request.size });
        return {
          kind: "failed",
          operationId: request.operationId,
          code: cleanup === "pending" ? "CleanupPending" : "UploadFailed",
          cleanup,
        };
      }
      return { kind: "failed", operationId: request.operationId, code: "TerminalUnavailable" };
    } catch {
      this.snapshot(entry, "CommitUnknown", request.size);
      return { kind: "unknown", operationId: request.operationId, code: "CommitUnknown" };
    }
  }

  private async abortPrepared(
    entry: QueueEntry,
    guard: number,
    request: TerminalIngressRequest,
    deadline: number,
  ): Promise<"clean" | "pending" | "committed"> {
    const cleanupDeadline = Math.min(deadline, this.clock.now() + TERMINAL_INGRESS_POST_OUTCOME_MS);
    try {
      const receipt = await this.effect(
        entry,
        guard,
        "Reconciling",
        TERMINAL_INGRESS_REQUEST_MS,
        cleanupDeadline,
        (signal) => this.transport.abort(this.currentRequest(entry, request), signal),
      );
      return receipt.state === "committed" ? "committed" : "clean";
    } catch {
      return "pending";
    }
  }

  private async effect<T>(
    entry: QueueEntry,
    guard: number,
    phase: Exclude<
      TerminalIngressSnapshot["phase"],
      "Committed" | "PrecommitFailed" | "CommitUnknown"
    >,
    phaseBudget: number,
    overallDeadline: number,
    run: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    this.assertCurrent(entry, guard);
    const deadline = Math.min(overallDeadline, this.clock.now() + phaseBudget);
    if (this.clock.now() >= deadline) throw new DeadlineError(phase);
    const phaseController = new AbortController();
    const cancel = () => phaseController.abort();
    entry.controller.signal.addEventListener("abort", cancel, { once: true });
    const timer = this.clock.setTimer(() => phaseController.abort(), deadline - this.clock.now());
    try {
      const result = await run(phaseController.signal);
      if (this.clock.now() >= deadline) throw new DeadlineError(phase);
      this.assertCurrent(entry, guard);
      return result;
    } catch (error) {
      if (phaseController.signal.aborted && !entry.controller.signal.aborted) {
        throw new DeadlineError(phase);
      }
      throw error;
    } finally {
      this.clock.clearTimer(timer);
      entry.controller.signal.removeEventListener("abort", cancel);
    }
  }

  private assertCurrent(entry: QueueEntry, guard: number) {
    if (
      this.active !== entry ||
      this.identityGeneration !== guard ||
      entry.controller.signal.aborted
    ) {
      throw new DOMException("terminal ingress cancelled", "AbortError");
    }
    const identity = this.identity();
    if (!identity || !sameTerminalGeneration(entry.identity, identity)) {
      throw new DOMException("terminal generation unavailable", "AbortError");
    }
    // A reconnect may rotate only the live binding capability.
    entry.identity = {
      ...entry.identity,
      bindingId: identity.bindingId,
      bindingEpoch: identity.bindingEpoch,
    };
  }

  private currentRequest(
    entry: QueueEntry,
    request: TerminalIngressRequest,
  ): TerminalIngressRequest {
    return {
      ...request,
      bindingId: entry.identity.bindingId,
      bindingEpoch: entry.identity.bindingEpoch,
    };
  }

  private commit(entry: QueueEntry, receipt: TerminalIngressReceipt): TerminalIngressOutcome {
    this.snapshot(entry, "Committed", entry.file.size);
    return entry.operationId
      ? committed(entry.operationId, receipt)
      : { kind: "unknown", code: "CommitUnknown" };
  }

  private snapshot(entry: QueueEntry, phase: TerminalIngressPhase, nextOffset: number) {
    if (!entry.operationId && phase !== "Queued" && phase !== "Hashing") return;
    this.onSnapshot({
      operationId: entry.operationId ?? "pending",
      operationGeneration: entry.operationGeneration,
      phase,
      nextOffset,
      size: entry.file.size,
      mediaType: entry.file.type as TerminalImageMediaType,
    });
  }
}

function sameTerminalGeneration(left: TerminalIngressIdentity, right: TerminalIngressIdentity) {
  return (
    left.clientInstanceId === right.clientInstanceId &&
    left.sessionId === right.sessionId &&
    left.terminalId === right.terminalId &&
    left.terminalGeneration === right.terminalGeneration
  );
}

function committed(operationId: string, receipt: TerminalIngressReceipt): TerminalIngressOutcome {
  return { kind: "committed", operationId, inputSequence: receipt.inputSequence };
}

function classifyError(error: unknown): TerminalIngressErrorCode {
  if (error instanceof DeadlineError) return "DeadlineExceeded";
  if (error instanceof DOMException && error.name === "AbortError") return "Cancelled";
  if (error instanceof HashError) return "HashFailed";
  if (error instanceof Error && isTerminalIngressErrorCode(error.message)) return error.message;
  return "UploadFailed";
}

function isTerminalIngressErrorCode(value: string): value is TerminalIngressErrorCode {
  return (
    value === "Conflict" ||
    value === "UploadFailed" ||
    value === "MaterializationFailed" ||
    value === "Expired" ||
    value === "Cancelled" ||
    value === "TerminalUnavailable"
  );
}

function isTerminalImageType(value: string): value is TerminalImageMediaType {
  return (
    value === "image/png" ||
    value === "image/jpeg" ||
    value === "image/gif" ||
    value === "image/webp"
  );
}

function bytesToHex(bytes: Uint8Array) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function uint8ToBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
