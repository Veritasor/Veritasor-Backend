import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("DLQ Throughput Grafana Dashboard Artifact", () => {
  it("ships a valid Grafana dashboard JSON artifact with required DLQ panels", () => {
    const dashboardPath = resolve(process.cwd(), "ops/grafana/dlq.json");
    const content = readFileSync(dashboardPath, "utf8");
    const dashboard = JSON.parse(content);

    expect(dashboard.title).toBe("DLQ Throughput Dashboard");
    expect(dashboard.uid).toBe("dlq-throughput");
    expect(Array.isArray(dashboard.panels)).toBe(true);
    expect(dashboard.panels.length).toBeGreaterThanOrEqual(3);

    // Verify presence of DLQ metric expressions in targets
    const expressions = dashboard.panels.flatMap((panel: any) =>
      (panel.targets || []).map((t: any) => t.expr)
    );

    const hasIngestMetric = expressions.some((expr: string) =>
      expr && expr.includes("dlq_ingest_total")
    );
    const hasReplayMetric = expressions.some((expr: string) =>
      expr && expr.includes("dlq_replay_total")
    );
    expect(hasIngestMetric).toBe(true);
    expect(hasReplayMetric).toBe(true);
  });
});
