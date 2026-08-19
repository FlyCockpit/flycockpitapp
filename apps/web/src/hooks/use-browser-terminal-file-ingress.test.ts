import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { planTerminalPaste, TERMINAL_IMAGE_MAX_BYTES } from "@flycockpit/relay-protocol/terminal";
import { describe, expect, it, vi } from "vitest";
import {
  TERMINAL_INGRESS_CHUNK_BYTES,
  TERMINAL_INGRESS_FINISH_MS,
  TERMINAL_INGRESS_HASH_MS,
  TERMINAL_INGRESS_OVERALL_MS,
  TERMINAL_INGRESS_POST_OUTCOME_MS,
  TERMINAL_INGRESS_QUEUE_LIMIT,
  TERMINAL_INGRESS_REQUEST_MS,
  TerminalFileIngressController,
  type TerminalIngressClock,
  type TerminalIngressIdentity,
  type TerminalIngressRequest,
  type TerminalIngressTransport,
} from "../lib/terminal/terminal-file-ingress";
import { createTerminalDropHandler, type TerminalDropEvent } from "./browser-terminal-paste";

const identity: TerminalIngressIdentity = {
  clientInstanceId: "client",
  sessionId: "session",
  terminalId: "terminal",
  terminalGeneration: 7,
  bindingId: "binding",
  bindingEpoch: 1,
};

function image(bytes: Uint8Array, type = "image/png") {
  const copy = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  return new File([copy], "fixture.png", { type });
}

function transport(overrides: Partial<TerminalIngressTransport> = {}): TerminalIngressTransport {
  return {
    begin: async () => ({ state: "prepared", nextOffset: 0 }),
    chunk: async (request) => ({ state: "prepared", nextOffset: request.offset + 1 }),
    finish: async () => ({ state: "committed", nextOffset: 0, inputSequence: 1 }),
    status: async () => ({ state: "prepared", nextOffset: 0 }),
    abort: async () => ({ state: "no_operation", nextOffset: 0 }),
    ...overrides,
  };
}

function fakeClock(): TerminalIngressClock & { advance(ms: number): void } {
  let now = 0;
  const timers: Array<{ callback: () => void; fireAt: number; cancelled: boolean }> = [];
  return {
    now: () => now,
    setTimer: (callback, milliseconds) => {
      const entry = { callback, fireAt: now + milliseconds, cancelled: false };
      timers.push(entry);
      return entry as unknown as ReturnType<typeof globalThis.setTimeout>;
    },
    clearTimer: (timer) => {
      const entry = timer as unknown as { cancelled: boolean };
      entry.cancelled = true;
    },
    advance: (ms: number) => {
      now += ms;
      for (const entry of timers) {
        if (!entry.cancelled && entry.fireAt <= now) {
          entry.cancelled = true;
          entry.callback();
        }
      }
    },
  };
}

/** Rejects with an AbortError when the signal aborts. */
function abortOnSignal(signal: AbortSignal): Promise<never> {
  return new Promise((_resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("aborted", "AbortError"));
      return;
    }
    signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), {
      once: true,
    });
  });
}

/** Drains the microtask queue enough for async ingress phases to advance. */
async function flushMicrotasks(): Promise<void> {
  // file.arrayBuffer() + crypto.subtle.digest() + multiple effect awaits
  // each add microtask hops; we need several macrotask ticks to drain them.
  for (let i = 0; i < 10; i++) {
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
  }
}

describe("browser terminal typed file ingress", () => {
  it("browser_terminal_one_image_plan", () => {
    for (const type of ["image/png", "image/jpeg", "image/gif", "image/webp"]) {
      expect(planTerminalPaste({ files: [{ type, size: 1 }] }).kind).toBe("image");
      expect(planTerminalPaste({ files: [{ type, size: TERMINAL_IMAGE_MAX_BYTES }] }).kind).toBe(
        "image",
      );
    }
    expect(planTerminalPaste({ files: [] })).toEqual({ kind: "empty" });
    expect(
      planTerminalPaste({
        files: [
          { type: "image/png", size: 1 },
          { type: "image/png", size: 1 },
        ],
      }),
    ).toMatchObject({ kind: "error", code: "too_many_files" });
  });

  it("browser_terminal_operation_protocol", async () => {
    const bytes = new Uint8Array(TERMINAL_INGRESS_CHUNK_BYTES + 3).fill(7);
    const requests: Array<{ action: string; request: TerminalIngressRequest }> = [];
    const chunks: number[] = [];
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => {
          requests.push({ action: "begin", request });
          return { state: "prepared", nextOffset: 0 };
        },
        chunk: async (request) => {
          requests.push({ action: "chunk", request });
          chunks.push(request.dataBase64.length);
          const decoded = Buffer.from(request.dataBase64, "base64");
          return { state: "prepared", nextOffset: request.offset + decoded.byteLength };
        },
        finish: async (request) => {
          requests.push({ action: "finish", request });
          return { state: "committed", nextOffset: bytes.length, inputSequence: 4 };
        },
      }),
      () => identity,
    );

    await expect(controller.enqueue(image(bytes))).resolves.toMatchObject({ kind: "committed" });
    expect(requests.map(({ action }) => action)).toEqual(["begin", "chunk", "chunk", "finish"]);
    expect(new Set(requests.map(({ request }) => request.operationId)).size).toBe(1);
    expect(requests[0]?.request.operationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(requests[0]?.request.sha256).toBe(
      Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex"),
    );
    expect(chunks).toHaveLength(2);
  });

  it("browser_terminal_operations_are_bounded_fifo", async () => {
    let releaseFirst: (() => void) | undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const order: string[] = [];
    let begins = 0;
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => {
          begins += 1;
          order.push(request.operationId);
          if (begins === 1) await firstGate;
          return { state: "prepared", nextOffset: request.size };
        },
      }),
      () => identity,
    );
    const accepted = Array.from({ length: TERMINAL_INGRESS_QUEUE_LIMIT }, (_, index) =>
      controller.enqueue(image(new Uint8Array([index + 1]))),
    );
    await expect(controller.enqueue(image(new Uint8Array([9])))).resolves.toMatchObject({
      kind: "failed",
      code: "Busy",
    });
    releaseFirst?.();
    await expect(Promise.all(accepted)).resolves.toHaveLength(TERMINAL_INGRESS_QUEUE_LIMIT);
    expect(order).toHaveLength(TERMINAL_INGRESS_QUEUE_LIMIT);
    expect(new Set(order).size).toBe(TERMINAL_INGRESS_QUEUE_LIMIT);
  });

  it("browser_terminal_replay_and_identity", async () => {
    const begin = vi
      .fn<TerminalIngressTransport["begin"]>()
      .mockRejectedValueOnce(new Error("lost acknowledgement"))
      .mockResolvedValue({ state: "prepared", nextOffset: 1 });
    const status = vi
      .fn<TerminalIngressTransport["status"]>()
      .mockResolvedValueOnce({ state: "prepared", nextOffset: 1 })
      .mockResolvedValueOnce({ state: "committed", nextOffset: 1, inputSequence: 1 });
    const finish = vi
      .fn<TerminalIngressTransport["finish"]>()
      .mockRejectedValueOnce(new Error("lost finish acknowledgement"));
    const controller = new TerminalFileIngressController(
      transport({ begin, status, finish }),
      () => identity,
    );
    const outcome = await controller.enqueue(image(new Uint8Array([1])));
    expect(outcome.kind).toBe("committed");
    expect(begin).toHaveBeenCalledOnce();
    expect(status).toHaveBeenCalledTimes(2);
    expect(status.mock.calls[0]?.[0].operationId).toBe(status.mock.calls[1]?.[0].operationId);
  });

  it("browser_terminal_same_identity_new_paste_queues_without_cancelling", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const abort = vi.fn<TerminalIngressTransport["abort"]>(async () => ({
      state: "no_operation",
      nextOffset: 0,
    }));
    let count = 0;
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => {
          count += 1;
          if (count === 1) await gate;
          return { state: "prepared", nextOffset: request.size };
        },
        abort,
      }),
      () => identity,
    );
    const first = controller.enqueue(image(new Uint8Array([1])));
    const second = controller.enqueue(image(new Uint8Array([2])));
    release?.();
    await Promise.all([first, second]);
    expect(count).toBe(2);
    expect(abort).not.toHaveBeenCalled();
  });

  it("browser_terminal_failure_preserves_prior_and_continues_fifo", () => {
    expect({
      hash: TERMINAL_INGRESS_HASH_MS,
      request: TERMINAL_INGRESS_REQUEST_MS,
      finish: TERMINAL_INGRESS_FINISH_MS,
      overall: TERMINAL_INGRESS_OVERALL_MS,
      postOutcome: TERMINAL_INGRESS_POST_OUTCOME_MS,
    }).toEqual({
      hash: 15_000,
      request: 10_000,
      finish: 30_000,
      overall: 120_000,
      postOutcome: 10_000,
    });
  });

  it("browser_terminal_deadline_hash_boundary_completes_before", async () => {
    // Deadline-1 success at the Hash boundary: gate the hash phase (file
    // arrayBuffer) to resolve just before its phase budget (HASH_MS - 1). The
    // hash phase timer (at HASH_MS) has NOT fired, so the post-await check
    // passes and the operation commits normally. This proves the controller
    // does not spuriously fail when within the hash phase budget.
    const clock = fakeClock();
    let releaseHash: (() => void) | undefined;
    const hashGate = new Promise<void>((resolve) => {
      releaseHash = resolve;
    });
    const gatedFile = new File([new Uint8Array([42])], "hash.png", { type: "image/png" });
    const origArrayBuffer = gatedFile.arrayBuffer.bind(gatedFile);
    gatedFile.arrayBuffer = async () => {
      await hashGate;
      return origArrayBuffer();
    };
    const begin = vi.fn<TerminalIngressTransport["begin"]>(async (request) => ({
      state: "prepared",
      nextOffset: request.size,
    }));
    const finish = vi.fn<TerminalIngressTransport["finish"]>(async () => ({
      state: "committed",
      nextOffset: 1,
      inputSequence: 1,
    }));
    const controller = new TerminalFileIngressController(
      { ...transport(), begin, finish },
      () => identity,
      clock,
    );
    const pending = controller.enqueue(gatedFile);
    // Let the controller reach the hash phase (gated).
    await flushMicrotasks();
    // Advance to JUST BEFORE the hash phase deadline — timer does not fire.
    clock.advance(TERMINAL_INGRESS_HASH_MS - 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_HASH_MS);
    // Release the gate; arrayBuffer resolves, post-await check passes, commits.
    releaseHash?.();
    const outcome = await pending;
    expect(outcome.kind).toBe("committed");
    expect(begin).toHaveBeenCalledOnce();
    expect(finish).toHaveBeenCalledOnce();
  });

  it("browser_terminal_deadline_hash_boundary_rejects_after", async () => {
    // At the Hash boundary: the hash phase reads file.arrayBuffer() + digests.
    // We use a File with a gated arrayBuffer() to control timing. After the
    // hash deadline elapses (clock advanced past HASH_MS), the phase timer
    // fires and aborts the phase controller. Since arrayBuffer doesn't check
    // the signal, the post-await check (now >= deadline) catches it.
    const clock = fakeClock();
    let releaseHash: (() => void) | undefined;
    const hashGate = new Promise<void>((resolve) => {
      releaseHash = resolve;
    });
    // File subclass that delays arrayBuffer() until the gate resolves.
    const gatedFile = new File([new Uint8Array([1])], "hash.png", { type: "image/png" });
    const origArrayBuffer = gatedFile.arrayBuffer.bind(gatedFile);
    gatedFile.arrayBuffer = async () => {
      await hashGate;
      return origArrayBuffer();
    };
    const controller = new TerminalFileIngressController(transport(), () => identity, clock);
    const pending = controller.enqueue(gatedFile);
    // Let the controller reach the hash phase (gated).
    await flushMicrotasks();
    // Advance past the hash deadline — timer fires, phase controller aborts.
    clock.advance(TERMINAL_INGRESS_HASH_MS + 1);
    // Release the gate; arrayBuffer resolves, then post-await check fires.
    releaseHash?.();
    const outcome = await pending;
    expect(outcome.kind).toBe("failed");
    if (outcome.kind === "failed") {
      expect(outcome.code).toBe("DeadlineExceeded");
    }
  });

  it("browser_terminal_deadline_begin_boundary_rejects_after", async () => {
    // At the Begin boundary: begin awaits a never-resolving gate. We advance
    // JUST PAST the begin phase budget (TERMINAL_INGRESS_REQUEST_MS) while
    // remaining WELL BELOW the overall deadline (TERMINAL_INGRESS_OVERALL_MS).
    // The begin phase timer fires at REQUEST_MS, aborting the phase controller;
    // begin rejects with DeadlineError("Beginning"). The recovery (status)
    // returns no_operation, so begin is retried — the retry gets a fresh
    // REQUEST_MS budget. We advance again past the retry's phase budget
    // (still below overall), the retry's phase timer fires, retry begin
    // rejects DeadlineError("Beginning"), recoverBeforeFinish propagates it,
    // and the run catch block classifies it as DeadlineExceeded. This proves
    // the PHASE deadline (not the overall cap) caused the failure: the clock
    // never reaches OVERALL_MS.
    const clock = fakeClock();
    const beginGate = new Promise<void>(() => {}); // never resolves
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (_request, signal) => {
          await Promise.race([beginGate, abortOnSignal(signal)]);
          return { state: "prepared", nextOffset: 0 };
        },
        status: async () => ({ state: "no_operation", nextOffset: 0 }),
      }),
      () => identity,
      clock,
    );
    const pending = controller.enqueue(image(new Uint8Array([1])));
    // Let the hash phase complete and the begin phase start (gated).
    await flushMicrotasks();
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    // Advance JUST PAST the begin phase budget — phase timer fires, begin
    // rejects, recovery starts (status returns no_operation, retry begin).
    clock.advance(TERMINAL_INGRESS_REQUEST_MS + 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    // Let the recovery + retry begin start (gated).
    await flushMicrotasks();
    // Advance past the retry's phase budget (still below overall) — retry
    // begin's phase timer fires, retry rejects, recoverBeforeFinish throws
    // DeadlineError("Beginning"), run catch returns DeadlineExceeded.
    clock.advance(TERMINAL_INGRESS_REQUEST_MS + 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    const outcome = await pending;
    expect(outcome.kind).toBe("failed");
    if (outcome.kind === "failed") {
      expect(outcome.code).toBe("DeadlineExceeded");
    }
  });

  it("browser_terminal_deadline_begin_boundary_completes_before", async () => {
    // Deadline-1 success at the Begin boundary: gate begin to resolve just
    // before its phase budget (REQUEST_MS - 1). The begin phase timer (at
    // REQUEST_MS) has NOT fired, so the post-await check (now < deadline)
    // passes and the operation completes normally. This proves the controller
    // does not spuriously fail when within the begin phase budget.
    const clock = fakeClock();
    let releaseBegin: (() => void) | undefined;
    const beginGate = new Promise<void>((resolve) => {
      releaseBegin = resolve;
    });
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request, signal) => {
          await Promise.race([beginGate, abortOnSignal(signal)]);
          return { state: "prepared", nextOffset: request.size };
        },
      }),
      () => identity,
      clock,
    );
    const pending = controller.enqueue(image(new Uint8Array([1])));
    // Let the hash phase complete and the begin phase start (gated).
    await flushMicrotasks();
    // Advance to JUST BEFORE the begin phase deadline — timer does not fire.
    clock.advance(TERMINAL_INGRESS_REQUEST_MS - 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_REQUEST_MS);
    // Release the gate; begin resolves, post-await check passes, finish commits.
    releaseBegin?.();
    const outcome = await pending;
    expect(outcome.kind).toBe("committed");
  });

  it("browser_terminal_deadline_chunk_boundary_rejects_after", async () => {
    // At the chunk (Uploading) boundary: chunk awaits a never-resolving gate.
    // We advance JUST PAST the chunk phase budget (TERMINAL_INGRESS_REQUEST_MS)
    // while remaining WELL BELOW the overall deadline. The chunk phase timer
    // fires at REQUEST_MS, aborting the phase controller; chunk rejects with
    // DeadlineError("Uploading"). The recovery (status) is also gated, so its
    // phase timer fires on the next advance (still below overall), status
    // rejects DeadlineError("Uploading"), recoverBeforeFinish propagates it,
    // and the run catch block classifies it as DeadlineExceeded with
    // phase "Uploading". This proves the PHASE deadline (not the overall cap)
    // caused the failure: the clock never reaches OVERALL_MS.
    const clock = fakeClock();
    const gate = new Promise<void>(() => {}); // never resolves
    const bytes = new Uint8Array(TERMINAL_INGRESS_CHUNK_BYTES + 1).fill(5);
    const controller = new TerminalFileIngressController(
      transport({
        // Begin returns nextOffset=0 so the chunk loop starts (not request.size
        // which would skip chunks entirely).
        begin: async () => ({ state: "prepared", nextOffset: 0 }),
        chunk: async (_request, signal) => {
          await Promise.race([gate, abortOnSignal(signal)]);
          return { state: "prepared", nextOffset: TERMINAL_INGRESS_CHUNK_BYTES + 1 };
        },
        // Recovery: status is also gated so its phase timer fires (not a
        // no_operation shortcut that would mask the deadline).
        status: async (_request, signal) => {
          await Promise.race([gate, abortOnSignal(signal)]);
          return { state: "no_operation", nextOffset: 0 };
        },
      }),
      () => identity,
      clock,
    );
    const pending = controller.enqueue(image(bytes));
    // Let hash+begin complete; begin returns nextOffset=0, so the chunk loop
    // starts at offset=0 and calls the gated chunk transport.
    await flushMicrotasks();
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    // Advance JUST PAST the chunk phase budget — phase timer fires, chunk
    // rejects DeadlineError("Uploading"), recovery (status) starts (gated).
    clock.advance(TERMINAL_INGRESS_REQUEST_MS + 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    // Let the recovery status phase start (gated).
    await flushMicrotasks();
    // Advance past the status phase budget (still below overall) — status
    // phase timer fires, status rejects DeadlineError("Uploading"),
    // recoverBeforeFinish throws, run catch returns DeadlineExceeded.
    clock.advance(TERMINAL_INGRESS_REQUEST_MS + 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    const outcome = await pending;
    expect(outcome.kind).toBe("failed");
    if (outcome.kind === "failed") {
      expect(outcome.code).toBe("DeadlineExceeded");
      expect(outcome.phase).toBe("Uploading");
    }
  });

  it("browser_terminal_deadline_chunk_boundary_completes_before", async () => {
    // Deadline-1 success at the chunk boundary: gate chunk to resolve just
    // before its phase budget (REQUEST_MS - 1). The chunk phase timer (at
    // REQUEST_MS) has NOT fired, so the post-await check passes and the
    // operation completes normally. This proves the controller does not
    // spuriously fail when within the chunk phase budget.
    const clock = fakeClock();
    let releaseChunk: (() => void) | undefined;
    const chunkGate = new Promise<void>((resolve) => {
      releaseChunk = resolve;
    });
    // File is exactly one chunk so a single chunk call completes the upload.
    const bytes = new Uint8Array(TERMINAL_INGRESS_CHUNK_BYTES).fill(5);
    const controller = new TerminalFileIngressController(
      transport({
        begin: async () => ({ state: "prepared", nextOffset: 0 }),
        chunk: async (_request, signal) => {
          await Promise.race([chunkGate, abortOnSignal(signal)]);
          return { state: "prepared", nextOffset: bytes.byteLength };
        },
      }),
      () => identity,
      clock,
    );
    const pending = controller.enqueue(image(bytes));
    // Let hash+begin complete; chunk loop starts (gated).
    await flushMicrotasks();
    // Advance to JUST BEFORE the chunk phase deadline — timer does not fire.
    clock.advance(TERMINAL_INGRESS_REQUEST_MS - 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_REQUEST_MS);
    // Release the gate; chunk resolves, post-await check passes, finish commits.
    releaseChunk?.();
    const outcome = await pending;
    expect(outcome.kind).toBe("committed");
  });

  it("browser_terminal_deadline_finish_boundary_rejects_after", async () => {
    // At the Finish boundary: finish was dispatched (finishDispatched=true).
    // The finish transport awaits a gate. We advance JUST PAST the finish
    // phase budget (TERMINAL_INGRESS_FINISH_MS) while remaining WELL BELOW the
    // overall deadline. The finish phase timer fires at FINISH_MS, aborting the
    // phase controller; finish rejects. Since finishDispatched=true, the
    // controller enters reconcile. With status also throwing, the outcome is
    // CommitUnknown. This proves the PHASE deadline (not the overall cap)
    // caused the failure: the clock never reaches OVERALL_MS.
    const clock = fakeClock();
    const finishGate = new Promise<void>(() => {}); // never resolves
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => ({ state: "prepared", nextOffset: request.size }),
        finish: async (_request, signal) => {
          await Promise.race([finishGate, abortOnSignal(signal)]);
          return { state: "prepared", nextOffset: 1 };
        },
        status: async () => {
          throw new Error("status lost");
        },
      }),
      () => identity,
      clock,
    );
    const pending = controller.enqueue(image(new Uint8Array([1])));
    // Let hash+begin complete (no chunks since begin returns nextOffset=size).
    await flushMicrotasks();
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    // Advance JUST PAST the finish phase budget (well below overall) — timer
    // fires, finish rejects, controller enters reconcile, status throws,
    // outcome is CommitUnknown.
    clock.advance(TERMINAL_INGRESS_FINISH_MS + 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_OVERALL_MS);
    const outcome = await pending;
    expect(outcome.kind).toBe("unknown");
    if (outcome.kind === "unknown") {
      expect(outcome.code).toBe("CommitUnknown");
    }
  });

  it("browser_terminal_deadline_finish_boundary_completes_before", async () => {
    // Deadline-1 success at the Finish boundary: gate finish to resolve just
    // before its phase budget (FINISH_MS - 1). The finish phase timer (at
    // FINISH_MS) has NOT fired, so the post-await check passes and the
    // operation commits normally. This proves the controller does not
    // spuriously fail when within the finish phase budget.
    const clock = fakeClock();
    let releaseFinish: (() => void) | undefined;
    const finishGate = new Promise<void>((resolve) => {
      releaseFinish = resolve;
    });
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => ({ state: "prepared", nextOffset: request.size }),
        finish: async (_request, signal) => {
          await Promise.race([finishGate, abortOnSignal(signal)]);
          return { state: "committed", nextOffset: 1, inputSequence: 9 };
        },
      }),
      () => identity,
      clock,
    );
    const pending = controller.enqueue(image(new Uint8Array([1])));
    // Let hash+begin complete (no chunks since begin returns nextOffset=size).
    await flushMicrotasks();
    // Advance to JUST BEFORE the finish phase deadline — timer does not fire.
    clock.advance(TERMINAL_INGRESS_FINISH_MS - 1);
    expect(clock.now()).toBeLessThan(TERMINAL_INGRESS_FINISH_MS);
    // Release the gate; finish resolves, post-await check passes, commits.
    releaseFinish?.();
    const outcome = await pending;
    expect(outcome.kind).toBe("committed");
  });

  it("browser_terminal_deadline_overall_rejects_regardless_of_phase", async () => {
    // The overall deadline (120s) caps every phase. We gate begin and advance
    // past the overall deadline (well beyond the 10s per-phase begin budget),
    // proving the overall cap fires even when the per-phase budget is unmet.
    const clock = fakeClock();
    const beginGate = new Promise<void>(() => {}); // never resolves
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (_request, signal) => {
          await Promise.race([beginGate, abortOnSignal(signal)]);
          return { state: "prepared", nextOffset: 0 };
        },
      }),
      () => identity,
      clock,
    );
    const pending = controller.enqueue(image(new Uint8Array([1])));
    await flushMicrotasks();
    // Advance past the overall deadline.
    clock.advance(TERMINAL_INGRESS_OVERALL_MS + 1);
    const outcome = await pending;
    expect(outcome.kind).toBe("failed");
    if (outcome.kind === "failed") {
      expect(outcome.code).toBe("DeadlineExceeded");
    }
  });

  it("browser_terminal_rejected_file_has_no_text_fallback", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const interceptor = readFileSync(
      resolve(root, "apps/web/src/hooks/browser-terminal-paste.ts"),
      "utf8",
    );
    expect(interceptor).not.toContain('getData("text")');
    expect(planTerminalPaste({ files: [{ type: "text/plain", size: 1 }] })).toMatchObject({
      kind: "error",
      code: "unsupported_file",
    });
  });

  it("browser_terminal_control_plane_never_handles_host_path", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const sources = [
      "apps/web/src/lib/terminal/terminal-file-ingress.ts",
      "apps/web/src/lib/terminal/terminal-client.ts",
      "apps/web/src/hooks/use-browser-terminal.ts",
    ].map((file) => readFileSync(resolve(root, file), "utf8"));
    const joined = sources.join("\n");
    for (const forbidden of [
      "ESC[200~",
      "shellLiteral",
      "retainedMedia",
      "durableMedia",
      "attachmentId",
    ]) {
      expect(joined).not.toContain(forbidden);
    }
    expect(sources.slice(0, 2).join("\n")).not.toContain("terminal.write(");
  });

  it("browser_terminal_dom_non_coupling_inventory", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const source = readFileSync(
      resolve(root, "apps/web/src/lib/terminal/terminal-file-ingress.ts"),
      "utf8",
    );
    expect(source).not.toMatch(/composer|CockpitSession|retained-media|durable-media/);
  });

  it("browser_terminal_drop_rejects_multi_file_as_one_gesture", () => {
    // Behavioral proof exercising the REAL production drop path
    // (createTerminalDropHandler — the exact factory useBrowserTerminal uses).
    // We drive the factory with a synthetic TerminalDropEvent carrying two
    // image files and a spy pasteFiles. The factory must forward the COMPLETE
    // two-file array in ONE call (whole-gesture), producing a single
    // too_many_files plan. A map-split handleDrop (pasteFiles([file]) per file)
    // would invoke pasteFiles twice with one file each, and each single image
    // would be accepted — so the once-only + complete-array assertions FAIL
    // if the production path reverts to map-split.
    const first = new File([new Uint8Array([1])], "drop-a.png", { type: "image/png" });
    const second = new File([new Uint8Array([2])], "drop-b.png", { type: "image/png" });
    const pasteFiles = vi.fn((files: readonly File[]) => planTerminalPaste({ files }));
    const dropEvent: TerminalDropEvent = {
      dataTransfer: { files: [first, second] } as unknown as DataTransfer,
      preventDefault: vi.fn(),
    };
    const handleDrop = createTerminalDropHandler(pasteFiles);
    handleDrop(dropEvent);
    // ONE whole-gesture call with the complete two-file array.
    expect(pasteFiles).toHaveBeenCalledOnce();
    expect(pasteFiles.mock.calls[0]?.[0]).toEqual([first, second]);
    // The complete-array plan is a single too_many_files rejection.
    expect(pasteFiles.mock.results[0]?.value).toMatchObject({
      kind: "error",
      code: "too_many_files",
    });
    // Distinguishing: each file alone is a valid image plan — a map-split
    // handler would accept both individually, so the once-only assertion
    // above is what rejects that regression.
    expect(planTerminalPaste({ files: [first] }).kind).toBe("image");
    expect(planTerminalPaste({ files: [second] }).kind).toBe("image");
    // The real handler prevents the default drop.
    expect(dropEvent.preventDefault).toHaveBeenCalledOnce();
  });

  it("browser_terminal_drop_zero_file_is_no_op", () => {
    // The real production handler is a no-op for a zero-file drop: pasteFiles
    // is never called and preventDefault is never called.
    const pasteFiles = vi.fn();
    const dropEvent: TerminalDropEvent = {
      dataTransfer: { files: [] } as unknown as DataTransfer,
      preventDefault: vi.fn(),
    };
    const handleDrop = createTerminalDropHandler(pasteFiles);
    handleDrop(dropEvent);
    expect(pasteFiles).not.toHaveBeenCalled();
    expect(dropEvent.preventDefault).not.toHaveBeenCalled();
    // planTerminalPaste on the empty array confirms no partial enqueue.
    expect(planTerminalPaste({ files: [] })).toEqual({ kind: "empty" });
  });

  it("browser_terminal_drop_single_file_matches_paste_path", () => {
    // Single-file drop must be identical to single-file paste: one valid image
    // plan, forwarded as a single whole-gesture call.
    const file = new File([new Uint8Array([1])], "solo.png", { type: "image/png" });
    const pasteFiles = vi.fn((files: readonly File[]) => planTerminalPaste({ files }));
    const dropEvent: TerminalDropEvent = {
      dataTransfer: { files: [file] } as unknown as DataTransfer,
      preventDefault: vi.fn(),
    };
    const handleDrop = createTerminalDropHandler(pasteFiles);
    handleDrop(dropEvent);
    expect(pasteFiles).toHaveBeenCalledOnce();
    expect(pasteFiles.mock.calls[0]?.[0]).toEqual([file]);
    expect(pasteFiles.mock.results[0]?.value).toMatchObject({ kind: "image" });
  });

  it("browser_terminal_drop_source_uses_factory_and_has_no_map_split_pattern", () => {
    // AC2: the source must no longer contain the N-single-file-gesture pattern,
    // and must route handleDrop through createTerminalDropHandler so the
    // behavioral tests above exercise the real production path.
    const root = resolve(import.meta.dirname, "../../../..");
    const hook = readFileSync(resolve(root, "apps/web/src/hooks/use-browser-terminal.ts"), "utf8");
    expect(hook).toContain("createTerminalDropHandler");
    expect(hook).not.toContain("files.map((file) => pasteFiles([file]))");
    expect(hook).not.toContain("Promise.all(files.map");
    // Guard against a forEach-based map-split regression that keeps the
    // factory import/string but bypasses createTerminalDropHandler in the
    // actual handleDrop. The behavioral browser test
    // (browser_terminal_hook_handleDrop_whole_gesture_not_map_split) is the
    // primary guard; this grep is defense-in-depth.
    expect(hook).not.toContain("files.forEach((file) => void pasteFiles([file]))");
    expect(hook).not.toContain("files.forEach((file) => pasteFiles([file]))");
  });

  it("browser_terminal_browser_project_contract", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const nodePath = "src/hooks/use-browser-terminal-file-ingress.test.ts";
    const browserPath = "src/hooks/use-browser-terminal-file-ingress.browser.test.ts";
    expect(readFileSync(resolve(root, `apps/web/${nodePath}`), "utf8")).toContain(
      "browser_terminal_operation_protocol",
    );
    expect(readFileSync(resolve(root, `apps/web/${browserPath}`), "utf8")).toContain(
      "browser_terminal_native_controller_integration",
    );
  });
});
