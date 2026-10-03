import { beforeEach, describe, expect, it } from "vitest";
import {
  metricsRegistry,
  pgbouncerActiveClients,
  pgbouncerScrapeErrorsTotal,
  pgbouncerServerConnections,
  pgbouncerWaitingClients,
} from "../../src/metrics.js";

beforeEach(() => metricsRegistry.resetMetrics());

describe("PgBouncer metrics", () => {
  it("registers pool, stats, and exporter-health families", async () => {
    const output = await metricsRegistry.metrics();
    for (const name of [
      "pgbouncer_waiting_clients", "pgbouncer_max_wait_seconds",
      "pgbouncer_active_clients",
      "pgbouncer_server_connections", "pgbouncer_avg_query_time_seconds",
      "pgbouncer_total_requests", "pgbouncer_total_query_time_seconds",
      "pgbouncer_scraper_enabled", "pgbouncer_scrape_success", "pgbouncer_scrape_duration_seconds",
      "pgbouncer_last_successful_scrape_timestamp_seconds", "pgbouncer_scrape_errors",
    ]) expect(output).toContain(name);
  });

  it("separates pools by database and user", async () => {
    pgbouncerWaitingClients.set({ database: "app", user: "one" }, 2);
    pgbouncerWaitingClients.set({ database: "app", user: "two" }, 4);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('database="app",user="one"} 2');
    expect(output).toContain('database="app",user="two"} 4');
  });

  it("separates server connection states", async () => {
    pgbouncerServerConnections.set({ database: "app", user: "one", state: "active" }, 2);
    pgbouncerServerConnections.set({ database: "app", user: "one", state: "idle" }, 5);
    expect(await metricsRegistry.metrics()).toContain('state="idle"');
  });

  it("resets gauges without resetting failure counters", async () => {
    pgbouncerActiveClients.set({ database: "app", user: "one" }, 3);
    pgbouncerScrapeErrorsTotal.inc({ reason: "timeout" });
    pgbouncerActiveClients.reset();
    const output = await metricsRegistry.metrics();
    expect(output).not.toContain("pgbouncer_active_clients{");
    expect(output).toContain('pgbouncer_scrape_errors_total{reason="timeout"} 1');
  });
});