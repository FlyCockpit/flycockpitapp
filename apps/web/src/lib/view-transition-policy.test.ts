import { describe, expect, it } from "vitest";

import { getPageViewTransitionTypes } from "./view-transition-policy";

describe("getPageViewTransitionTypes", () => {
  it("allows page transitions when the pathname changes", () => {
    expect(
      getPageViewTransitionTypes({
        pathChanged: true,
        hrefChanged: true,
        hashChanged: false,
      }),
    ).toEqual([]);
  });

  it("blocks page transitions for same-path search-param updates", () => {
    expect(
      getPageViewTransitionTypes({
        pathChanged: false,
        hrefChanged: true,
        hashChanged: false,
      }),
    ).toBe(false);
  });

  it("blocks page transitions for same-path hash updates", () => {
    expect(
      getPageViewTransitionTypes({
        pathChanged: false,
        hrefChanged: true,
        hashChanged: true,
      }),
    ).toBe(false);
  });

  it("blocks page transitions when no location surface changes", () => {
    expect(
      getPageViewTransitionTypes({
        pathChanged: false,
        hrefChanged: false,
        hashChanged: false,
      }),
    ).toBe(false);
  });
});
