import { describe, expect, it } from "vitest";
import { anchoredScrollTop, shouldLoadOlderHistory } from "./scroll-anchor";

describe("scroll anchor helpers", () => {
  it("keeps the same visible transcript item after prepending content", () => {
    expect(
      anchoredScrollTop({
        previousScrollHeight: 1000,
        previousScrollTop: 120,
        nextScrollHeight: 1400,
      }),
    ).toBe(520);
  });

  it("does not move backwards if measured content height shrinks", () => {
    expect(
      anchoredScrollTop({
        previousScrollHeight: 1000,
        previousScrollTop: 120,
        nextScrollHeight: 900,
      }),
    ).toBe(120);
  });

  it("loads older history only near the top threshold", () => {
    expect(shouldLoadOlderHistory({ scrollTop: 40 })).toBe(true);
    expect(shouldLoadOlderHistory({ scrollTop: 120 })).toBe(false);
    expect(shouldLoadOlderHistory({ scrollTop: 25, threshold: 24 })).toBe(false);
  });
});
