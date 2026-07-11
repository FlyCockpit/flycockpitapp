import { describe, expect, it } from "vitest";
import { mapWithConcurrency } from "./concurrency.js";

describe("mapWithConcurrency", () => {
  it("processes every item exactly once", async () => {
    const items = Array.from({ length: 25 }, (_, i) => i);
    const seen: number[] = [];
    await mapWithConcurrency(items, 8, async (i) => {
      seen.push(i);
    });
    expect(seen.toSorted((a, b) => a - b)).toEqual(items);
  });

  it("never exceeds the concurrency limit", async () => {
    let inFlight = 0;
    let peak = 0;
    await mapWithConcurrency(
      Array.from({ length: 30 }, (_, i) => i),
      8,
      async () => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 1));
        inFlight -= 1;
      },
    );
    expect(peak).toBeLessThanOrEqual(8);
    expect(peak).toBeGreaterThan(1);
  });

  it("rejects with the first error", async () => {
    await expect(
      mapWithConcurrency([1, 2, 3], 2, async (i) => {
        if (i === 2) throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
  });

  it("handles an empty item list", async () => {
    let called = false;
    await mapWithConcurrency([], 8, async () => {
      called = true;
    });
    expect(called).toBe(false);
  });
});
