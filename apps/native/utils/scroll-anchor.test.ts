import { describe, expect, it } from "vitest";
import {
  anchoredContentOffsetY,
  contentOffsetAfterLayoutChange,
  isUserNearTop,
  shouldApplyPrependAnchor,
  shouldLoadOlderHistory,
} from "./scroll-anchor";

describe("native_history_prepend_anchor", () => {
  it("uses measured content delta so the visible anchor stays put after prepend", () => {
    // User scrolled slightly; older page grows content by 400px at the top.
    expect(
      anchoredContentOffsetY({
        previousContentHeight: 1000,
        previousOffsetY: 120,
        nextContentHeight: 1400,
      }),
    ).toBe(520);
  });

  it("covers user-at-top: offset 0 becomes the height of newly prepended rows", () => {
    expect(isUserNearTop({ offsetY: 0 })).toBe(true);
    expect(
      anchoredContentOffsetY({
        previousContentHeight: 800,
        previousOffsetY: 0,
        nextContentHeight: 1200,
      }),
    ).toBe(400);
  });

  it("covers user-away: same delta math keeps the mid-list viewport stable", () => {
    expect(isUserNearTop({ offsetY: 640 })).toBe(false);
    expect(
      anchoredContentOffsetY({
        previousContentHeight: 2000,
        previousOffsetY: 640,
        nextContentHeight: 2600,
      }),
    ).toBe(1240);
  });

  it("covers variable row height via content-size delta rather than fixed row height", () => {
    // Prepended block is irregular (markdown / multi-line), measured as 317.
    expect(
      anchoredContentOffsetY({
        previousContentHeight: 1500,
        previousOffsetY: 48,
        nextContentHeight: 1817,
      }),
    ).toBe(365);
  });

  it("covers rotation/resize: non-prepend layout changes do not invent a jump", () => {
    expect(
      contentOffsetAfterLayoutChange({
        previousOffsetY: 220,
        prependPending: false,
        previousContentHeight: 1000,
        nextContentHeight: 900,
      }),
    ).toBe(220);

    expect(
      shouldApplyPrependAnchor({
        prependPending: false,
        contentGrewFromPrepend: true,
      }),
    ).toBe(false);

    expect(
      contentOffsetAfterLayoutChange({
        previousOffsetY: 220,
        prependPending: true,
        previousContentHeight: 1000,
        nextContentHeight: 1300,
      }),
    ).toBe(520);

    expect(
      shouldApplyPrependAnchor({
        prependPending: true,
        contentGrewFromPrepend: true,
      }),
    ).toBe(true);
  });

  it("does not move backwards if measured content height shrinks during prepend apply", () => {
    expect(
      anchoredContentOffsetY({
        previousContentHeight: 1000,
        previousOffsetY: 120,
        nextContentHeight: 900,
      }),
    ).toBe(120);
  });

  it("loads older history only near the top threshold", () => {
    expect(shouldLoadOlderHistory({ offsetY: 40 })).toBe(true);
    expect(shouldLoadOlderHistory({ offsetY: 120 })).toBe(false);
    expect(shouldLoadOlderHistory({ offsetY: 25, threshold: 24 })).toBe(false);
  });
});
