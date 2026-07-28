import { describe, it, expect, beforeEach } from "vitest";
import { metricsRegistry } from "../../src/metrics.js";
import {
  pgbouncerWaitingClients,
  pgbouncerAvgWaitTimeSeconds,
  pgbouncerActiveClients,
  pgbouncerIdleClients,
  pgbouncerServerConnections,
  pgbouncerAvgQueryTimeSeconds,
  pgbouncerTotalRequestsTotal,
  pgbouncerTotalQueryTimeSecondsTotal,
} from "../../src/metrics.js";

beforeEach(async () => {
  await metricsRegistry.resetMetrics();
});

describe("PgBouncer metrics", () => {
  it("registers pgbouncer_waiting_clients gauge", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_waiting_clients");
  });

  it("registers pgbouncer_avg_wait_time_seconds gauge", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_avg_wait_time_seconds");
  });

  it("registers pgbouncer_active_clients gauge", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_active_clients");
  });

  it("registers pgbouncer_idle_clients gauge", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_idle_clients");
  });

  it("registers pgbouncer_server_connections gauge", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_server_connections");
  });

  it("registers pgbouncer_avg_query_time_seconds gauge", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_avg_query_time_seconds");
  });

  it("registers pgbouncer_total_requests_total counter", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_total_requests_total");
  });

  it("registers pgbouncer_total_query_time_seconds_total counter", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_total_query_time_seconds_total");
  });

  it("records waiting_clients with database label", async () => {
    pgbouncerWaitingClients.set({ database: "veritasor" }, 5);
    pgbouncerWaitingClients.set({ database: "analytics" }, 10);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_waiting_clients{database="veritasor"} 5');
    expect(output).toContain('pgbouncer_waiting_clients{database="analytics"} 10');
  });

  it("records avg_wait_time_seconds with database label", async () => {
    pgbouncerAvgWaitTimeSeconds.set({ database: "veritasor" }, 0.1);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_avg_wait_time_seconds{database="veritasor"} 0.1');
  });

  it("records active_clients with database label", async () => {
    pgbouncerActiveClients.set({ database: "veritasor" }, 3);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_active_clients{database="veritasor"} 3');
  });

  it("records idle_clients with database label", async () => {
    pgbouncerIdleClients.set({ database: "veritasor" }, 8);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_idle_clients{database="veritasor"} 8');
  });

  it("records server_connections with database label", async () => {
    pgbouncerServerConnections.set({ database: "veritasor" }, 2);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_server_connections{database="veritasor"} 2');
  });

  it("records avg_query_time_seconds with database label", async () => {
    pgbouncerAvgQueryTimeSeconds.set({ database: "veritasor" }, 0.005);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_avg_query_time_seconds{database="veritasor"} 0.005');
  });

  it("increments total_requests_total counter", async () => {
    pgbouncerTotalRequestsTotal.inc({ database: "veritasor" }, 1000);
    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "pgbouncer_total_requests_total");
    expect(counter).toBeDefined();
    const value = (counter!.values as Array<{ labels: Record<string, string>; value: number }>).find(
      (v) => v.labels.database === "veritasor",
    );
    expect(value?.value).toBe(1000);
  });

  it("increments total_query_time_seconds_total counter", async () => {
    pgbouncerTotalQueryTimeSecondsTotal.inc({ database: "veritasor" }, 5.5);
    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "pgbouncer_total_query_time_seconds_total");
    expect(counter).toBeDefined();
    const value = (counter!.values as Array<{ labels: Record<string, string>; value: number }>).find(
      (v) => v.labels.database === "veritasor",
    );
    expect(value?.value).toBe(5.5);
  });

  it("tracks separate databases independently", async () => {
    pgbouncerWaitingClients.set({ database: "veritasor" }, 5);
    pgbouncerWaitingClients.set({ database: "analytics" }, 10);
    pgbouncerActiveClients.set({ database: "veritasor" }, 3);
    pgbouncerActiveClients.set({ database: "analytics" }, 7);

    const output = await metricsRegistry.metrics();
    expect(output).toContain('database="veritasor"');
    expect(output).toContain('database="analytics"');
  });
});