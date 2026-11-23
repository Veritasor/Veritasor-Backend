import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("Webhook EWMA Failure Decay Grafana Dashboard Artifact", () => {
  it("ships a valid Grafana dashboard JSON artifact with required EWMA panels", () => {
    const dashboardPath = resolve(process.cwd(), "ops/grafana/webhook-decay-dashboard.json");
    const content = readFileSync(dashboardPath, "utf8");
    const dashboard = JSON.parse(content);

    expect(dashboard.title).toBe("Webhook Delivery Failure Exponential-Decay Dashboard");
    expect(dashboard.uid).toBe("webhook-decay-dashboard");
    expect(Array.isArray(dashboard.panels)).toBe(true);
    expect(dashboard.panels.length).toBeGreaterThanOrEqual(4);

    // Verify presence of EWMA metric expressions in targets
    const expressions = dashboard.panels.flatMap((panel: any) =>
      (panel.targets || []).map((t: any) => t.expr)
    );

    const hasEWMAMetric = expressions.some((expr: string) =>
      expr && expr.includes("webhook_delivery_failure_ewma_score")
    );
    expect(hasEWMAMetric).toBe(true);
  });
});
