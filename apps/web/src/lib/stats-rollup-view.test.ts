import { describe, expect, it } from "vitest";
import { statsRollupToView } from "./stats-rollup-view";

describe("statsRollupToView", () => {
  it("maps token model rows", () => {
    const view = statsRollupToView({
      tokens: {
        by_model: [
          {
            provider: "openai",
            model: "gpt-5",
            total_tokens: 1234,
            calls: 3,
          },
        ],
      },
      recovery: {
        by_model: [
          {
            model: "gpt-5",
            calls: 4,
            recovered_pct: 25,
          },
        ],
      },
    });

    expect(view.tokenRows).toEqual([{ label: "openai/gpt-5", value: "1,234", detail: "3 calls" }]);
  });

  it("falls back to total tokens when the rollup has no model rows", () => {
    expect(statsRollupToView(null, 42)).toMatchObject({
      tokenRows: [],
      fallbackTotal: "42",
    });
  });
});
