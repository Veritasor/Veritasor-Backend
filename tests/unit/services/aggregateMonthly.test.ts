import { describe, it, expect } from "vitest";
import {
  aggregateMonthly,
  type RevenueEntry,
} from "../../../src/services/revenue/aggregateMonthly";

const entry = (
  overrides: Partial<RevenueEntry> & { date: string; amount: number },
): RevenueEntry => ({
  id: crypto.randomUUID(),
  currency: "USD",
  source: "stripe",
  ...overrides,
});

describe("aggregateMonthly", () => {
  it("groups entries by month", () => {
    const entries: RevenueEntry[] = [
      entry({ date: "2026-01-05T00:00:00Z", amount: 100 }),
      entry({ date: "2026-01-20T00:00:00Z", amount: 50 }),
      entry({ date: "2026-02-10T00:00:00Z", amount: 200 }),
    ];

    const result = aggregateMonthly(entries);

    expect(result).toHaveLength(2);
    expect(result[0]).toEqual({
      period: "2026-01",
      total: 150,
      net: 150,
      currency: "USD",
    });
    expect(result[1]).toEqual({
      period: "2026-02",
      total: 200,
      net: 200,
      currency: "USD",
    });
  });

  it("subtracts refunds from net", () => {
    const entries: RevenueEntry[] = [
      entry({ date: "2026-03-01T00:00:00Z", amount: 500 }),
      entry({ date: "2026-03-15T00:00:00Z", amount: 75, refund: true }),
    ];

    const result = aggregateMonthly(entries);

    expect(result).toHaveLength(1);
    expect(result[0].total).toBe(500);
    expect(result[0].net).toBe(425);
  });

  it("returns empty array for no entries", () => {
    expect(aggregateMonthly([])).toEqual([]);
  });

  it("sorts results chronologically", () => {
    const entries: RevenueEntry[] = [
      entry({ date: "2026-06-01T00:00:00Z", amount: 10 }),
      entry({ date: "2026-01-01T00:00:00Z", amount: 20 }),
      entry({ date: "2026-03-01T00:00:00Z", amount: 30 }),
    ];

    const result = aggregateMonthly(entries);
    const periods = result.map((r) => r.period);
    expect(periods).toEqual(["2026-01", "2026-03", "2026-06"]);
  });

  it("handles floating-point amounts cleanly", () => {
    const entries: RevenueEntry[] = [
      entry({ date: "2026-04-01T00:00:00Z", amount: 10.1 }),
      entry({ date: "2026-04-02T00:00:00Z", amount: 10.2 }),
    ];

    const result = aggregateMonthly(entries);
    expect(result[0].total).toBe(20.3);
  });
});
