import { describe, expect, it } from "vitest";
import { NativeAttachCoordinator } from "./session-attach";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

describe("NativeAttachCoordinator", () => {
  it("ignores a stale B response after rapid B then C selection", async () => {
    const client = {};
    const coordinator = new NativeAttachCoordinator();
    const bResponse = deferred<string>();
    const cResponse = deferred<string>();
    const applied: string[] = [];

    const bAttempt = coordinator.begin(client, 4, "session-b");
    const b = bResponse.promise.then((sessionId) => {
      if (coordinator.markApplied(bAttempt, client, 4)) applied.push(sessionId);
      coordinator.finish(bAttempt, client, 4);
    });
    const cAttempt = coordinator.begin(client, 4, "session-c");
    const c = cResponse.promise.then((sessionId) => {
      if (coordinator.markApplied(cAttempt, client, 4)) applied.push(sessionId);
      coordinator.finish(cAttempt, client, 4);
    });

    bResponse.resolve("session-b");
    await b;
    expect(coordinator.hasPending()).toBe(true);
    expect(applied).toEqual([]);

    cResponse.resolve("session-c");
    await c;

    expect(applied).toEqual(["session-c"]);
    expect(coordinator.hasPending()).toBe(false);
    expect(coordinator.needsAttach(client, 4, "session-c")).toBe(false);
  });

  it("does not duplicate a completed manual attach in the same epoch", () => {
    const client = {};
    const coordinator = new NativeAttachCoordinator();
    const attempt = coordinator.begin(client, 8, "session-b");

    expect(coordinator.isReady(client, 8, "session-b")).toBe(false);
    expect(coordinator.markApplied(attempt, client, 8)).toBe(true);
    expect(
      coordinator.isReady(client, 8, "session-b"),
      "exact replay is still inside the current attach attempt",
    ).toBe(false);
    expect(coordinator.finish(attempt, client, 8)).toBe(true);
    expect(coordinator.isReady(client, 8, "session-b")).toBe(true);
    expect(coordinator.needsAttach(client, 8, "session-b")).toBe(false);
    expect(coordinator.needsAttach(client, 9, "session-b")).toBe(true);
    expect(coordinator.isReady(client, 9, "session-b")).toBe(false);
  });

  it("does not duplicate a pending attach for the same session and epoch", () => {
    const client = {};
    const coordinator = new NativeAttachCoordinator();
    coordinator.begin(client, 8, "session-b");

    expect(coordinator.hasPending()).toBe(true);
    expect(coordinator.needsAttach(client, 8, "session-b")).toBe(false);
  });

  it("rejects an old-client response after the connection lifecycle changes", () => {
    const oldClient = {};
    const newClient = {};
    const coordinator = new NativeAttachCoordinator();
    const oldAttempt = coordinator.begin(oldClient, 2, "session-a");

    coordinator.invalidate();

    expect(coordinator.markApplied(oldAttempt, newClient, 3)).toBe(false);
    expect(coordinator.needsAttach(newClient, 3, "session-a")).toBe(true);
    expect(coordinator.isReady(newClient, 3, "session-a")).toBe(false);
  });

  it("does not restore cached readiness after a new-epoch attach fails", () => {
    const client = {};
    const coordinator = new NativeAttachCoordinator();
    const oldAttempt = coordinator.begin(client, 2, "session-a");
    coordinator.markApplied(oldAttempt, client, 2);
    coordinator.finish(oldAttempt, client, 2);
    expect(coordinator.isReady(client, 2, "session-a")).toBe(true);

    coordinator.invalidate();
    const failedAttempt = coordinator.begin(client, 3, "session-a");
    coordinator.finish(failedAttempt, client, 3);

    expect(coordinator.isReady(client, 3, "session-a")).toBe(false);
  });

  it("revokes A readiness when a same-epoch B attach fails", () => {
    const client = {};
    const coordinator = new NativeAttachCoordinator();
    const appliedA = coordinator.begin(client, 4, "session-a");
    coordinator.markApplied(appliedA, client, 4);
    coordinator.finish(appliedA, client, 4);
    expect(coordinator.isReady(client, 4, "session-a")).toBe(true);

    const failedB = coordinator.begin(client, 4, "session-b");
    expect(coordinator.isReady(client, 4, "session-a")).toBe(false);
    coordinator.finish(failedB, client, 4);

    expect(coordinator.isReady(client, 4, "session-a")).toBe(false);
    expect(coordinator.isReady(client, 4, "session-b")).toBe(false);
    expect(coordinator.needsAttach(client, 4, "session-a")).toBe(true);
  });
});
