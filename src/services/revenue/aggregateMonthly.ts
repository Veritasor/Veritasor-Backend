export type RevenueEntry = {
  id: string;
  amount: number;
  currency: string;
  date: string;
  source: string;
  refund?: boolean;
  raw?: any;
};

export type MonthlySummary = {
  period: string;
  total: number;
  net: number;
  currency: string;
};

export function aggregateMonthly(entries: RevenueEntry[]): MonthlySummary[] {
  const buckets = new Map<
    string,
    { total: number; refunds: number; currency: string }
  >();

  for (const entry of entries) {
    const period = entry.date.slice(0, 7); // YYYY-MM
    const existing = buckets.get(period);

    if (existing) {
      if (entry.refund) {
        existing.refunds += Math.abs(entry.amount);
      } else {
        existing.total += entry.amount;
      }
    } else {
      buckets.set(period, {
        total: entry.refund ? 0 : entry.amount,
        refunds: entry.refund ? Math.abs(entry.amount) : 0,
        currency: entry.currency,
      });
    }
  }

  const results: MonthlySummary[] = [];

  for (const [period, data] of buckets) {
    results.push({
      period,
      total: round(data.total),
      net: round(data.total - data.refunds),
      currency: data.currency,
    });
  }

  results.sort((a, b) => a.period.localeCompare(b.period));
  return results;
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}

export default aggregateMonthly;
