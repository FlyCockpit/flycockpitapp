import { describe, expect, it } from "vitest";
import { statsRollupToView } from "./stats-rollup-view";

describe("statsRollupToView", () => {
  it("maps token model rows and recovery rows by LLM mode", () => {
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
        by_llm_mode: [
          {
            llm_mode: "normal",
            calls: 4,
            recovered_pct: 25,
          },
          {
            llm_mode: "thinking",
            calls: 2,
            recovered_pct: 50,
          },
        ],
      },
    });

    expect(view.tokenRows).toEqual([{ label: "openai/gpt-5", value: "1,234", detail: "3 calls" }]);
    expect(view.recoveryModeRows).toEqual([
      { label: "normal", value: "4", detail: "25.0% recovered" },
      { label: "thinking", value: "2", detail: "50.0% recovered" },
    ]);
  });

  it("falls back to total tokens when the rollup has no model rows", () => {
    expect(statsRollupToView(null, 42)).toMatchObject({
      tokenRows: [],
      recoveryModeRows: [],
      fallbackTotal: "42",
    });
  });
});
