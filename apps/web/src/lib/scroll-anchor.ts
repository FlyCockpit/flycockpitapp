export type ScrollAnchorInput = {
  previousScrollHeight: number;
  previousScrollTop: number;
  nextScrollHeight: number;
};

export function anchoredScrollTop(input: ScrollAnchorInput) {
  return input.previousScrollTop + Math.max(0, input.nextScrollHeight - input.previousScrollHeight);
}

export function shouldLoadOlderHistory(input: { scrollTop: number; threshold?: number }) {
  return input.scrollTop <= (input.threshold ?? 96);
}
