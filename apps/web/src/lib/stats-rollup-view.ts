export type StatsViewRow = {
  label: string;
  value: string;
  detail?: string;
};

export type StatsRollupView = {
  tokenRows: StatsViewRow[];
  recoveryModeRows: StatsViewRow[];
  fallbackTotal: string | null;
};

function asRecord(value: unknown) {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

function asArray(value: unknown) {
  return Array.isArray(value) ? value : [];
}

function stringField(record: Record<string, unknown>, key: string) {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function numberField(record: Record<string, unknown>, key: string) {
  const value = record[key];
  return typeof value === "number" ? value : undefined;
}

function formatCount(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatPercent(value: number | undefined) {
  return typeof value === "number" ? `${value.toFixed(1)}%` : "0.0%";
}

export function statsRollupToView(
  rollup: unknown,
  fallbackTotalTokens?: number | null,
): StatsRollupView {
  const root = asRecord(rollup);
  const tokens = asRecord(root?.tokens);
  const recovery = asRecord(root?.recovery);

  const tokenRows = asArray(tokens?.by_model).flatMap((item): StatsViewRow[] => {
    const row = asRecord(item);
    if (!row) return [];
    const model = stringField(row, "model") ?? "unknown";
    const provider = stringField(row, "provider");
    const total = numberField(row, "total_tokens") ?? 0;
    const calls = numberField(row, "calls") ?? 0;
    return [
      {
        label: provider ? `${provider}/${model}` : model,
        value: formatCount(total),
        detail: `${formatCount(calls)} calls`,
      },
    ];
  });

  const recoveryModeRows = asArray(recovery?.by_llm_mode).flatMap((item): StatsViewRow[] => {
    const row = asRecord(item);
    if (!row) return [];
    const mode = stringField(row, "llm_mode") ?? "unknown";
    const calls = numberField(row, "calls") ?? 0;
    return [
      {
        label: mode,
        value: formatCount(calls),
        detail: `${formatPercent(numberField(row, "recovered_pct"))} recovered`,
      },
    ];
  });

  return {
    tokenRows,
    recoveryModeRows,
    fallbackTotal:
      tokenRows.length || typeof fallbackTotalTokens !== "number"
        ? null
        : formatCount(fallbackTotalTokens),
  };
}
