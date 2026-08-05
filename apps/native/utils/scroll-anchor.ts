export type ContentSizeAnchorInput = {
  previousContentHeight: number;
  previousOffsetY: number;
  nextContentHeight: number;
};

/**
 * After older rows prepend at the top of a non-inverted list, restore the
 * offset so the previously visible content stays put. Uses measured content
 * height delta so variable row heights and layout growth are handled.
 */
export function anchoredContentOffsetY(input: ContentSizeAnchorInput) {
  const growth = Math.max(0, input.nextContentHeight - input.previousContentHeight);
  return input.previousOffsetY + growth;
}

/**
 * When content size changes without a prepend (rotation/resize), keep the
 * current offset — do not invent a growth-based jump.
 */
export function contentOffsetAfterLayoutChange(input: {
  previousOffsetY: number;
  prependPending: boolean;
  previousContentHeight: number;
  nextContentHeight: number;
}) {
  if (!input.prependPending) return input.previousOffsetY;
  return anchoredContentOffsetY({
    previousContentHeight: input.previousContentHeight,
    previousOffsetY: input.previousOffsetY,
    nextContentHeight: input.nextContentHeight,
  });
}

export function shouldLoadOlderHistory(input: { offsetY: number; threshold?: number }) {
  return input.offsetY <= (input.threshold ?? 96);
}

/**
 * User is considered "at top" when near offset 0. Away means scrolled down
 * enough that an unanchored prepend would still need the same delta math
 * (the anchor still applies; this only labels the case).
 */
export function isUserNearTop(input: { offsetY: number; threshold?: number }) {
  return shouldLoadOlderHistory(input);
}

export function shouldApplyPrependAnchor(input: {
  prependPending: boolean;
  /** True when the size change is from a completed older-page merge. */
  contentGrewFromPrepend: boolean;
}) {
  return input.prependPending && input.contentGrewFromPrepend;
}
