import { trace, type Span, type SpanContext } from "@opentelemetry/api";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  httpRequestDuration,
  metricsRegistry,
  observeHttpRequestDuration,
} from "./metrics.js";
import { getActiveTraceExemplarLabels } from "./tracing.js";

const TRACE_ID = "11111111111111111111111111111111";
const SPAN_ID = "2222222222222222";

function withFakeSpan<T>(spanContext: SpanContext, callback: () => T): T {
  const fakeSpan = {
    spanContext: () => spanContext,
  } as Span;

  const getActiveSpanSpy = vi
    .spyOn(trace, "getActiveSpan")
    .mockReturnValue(fakeSpan);

  try {
    return callback();
  } finally {
    getActiveSpanSpy.mockRestore();
  }
}

describe("HTTP request metrics exemplars", () => {
  beforeEach(() => {
    metricsRegistry.resetMetrics();
  });

  it("returns no exemplar labels when there is no active span", () => {
    expect(getActiveTraceExemplarLabels()).toEqual({});
  });

  it("drops exemplars when there is no active span", () => {
    observeHttpRequestDuration(
      { method: "GET", route: "/health", status_code: "200" },
      0.25,
    );

    const bucketValues = Object.values(httpRequestDuration.hashMap)[0];
    expect(bucketValues.bucketExemplars[0.25]).toBeNull();
  });

  it("attaches the active trace id as an exemplar when a span is active", () => {
    const spanContext: SpanContext = {
      traceId: TRACE_ID,
      spanId: SPAN_ID,
      traceFlags: 1,
      isRemote: false,
    };

    withFakeSpan(spanContext, () => {
      observeHttpRequestDuration(
        { method: "GET", route: "/health", status_code: "200" },
        0.25,
      );
    });

    const bucketValues = Object.values(httpRequestDuration.hashMap)[0];
    expect(bucketValues.bucketExemplars[0.25]).toMatchObject({
      labelSet: { trace_id: TRACE_ID },
    });
  });
});

describe("metricsRegistry", () => {
  beforeEach(() => {
    metricsRegistry.resetMetrics();
  });

  it("uses the OpenMetrics content type and registers the request histogram", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("# TYPE http_request_duration_seconds histogram");
    expect(output).toContain("# EOF");

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const histogram = metrics.find((metric) => metric.name === "http_request_duration_seconds");
    expect(histogram).toMatchObject({
      name: "http_request_duration_seconds",
      type: "histogram",
      help: "HTTP request duration in seconds",
    });
  });

  it("resets observations while retaining registered metric families", async () => {
    observeHttpRequestDuration(
      { method: "GET", route: "/health", status_code: "200" },
      0.25,
    );
    expect(await metricsRegistry.metrics()).toContain('http_request_duration_seconds_count{method="GET",route="/health",status_code="200"} 1');

    metricsRegistry.resetMetrics();

    expect(await metricsRegistry.metrics()).not.toContain('method="GET",route="/health",status_code="200"');
    expect(await metricsRegistry.metrics()).toContain("# HELP http_request_duration_seconds");
  });
});

describe("observeHttpRequestDuration", () => {
  beforeEach(() => {
    metricsRegistry.resetMetrics();
  });

  it("records the duration and labels in the histogram", async () => {
    observeHttpRequestDuration(
      { method: "POST", route: "/attestations", status_code: "201" },
      0.125,
    );

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const histogram = metrics.find((metric) => metric.name === "http_request_duration_seconds");
    const values = histogram?.values as Array<{ labels: Record<string, string>; value: number }>;
    expect(values).toEqual(expect.arrayContaining([
      expect.objectContaining({
        labels: expect.objectContaining({
          method: "POST",
          route: "/attestations",
          status_code: "201",
        }),
        value: 1,
      }),
    ]));
    expect(values.find((value) => value.metricName === "http_request_duration_seconds_count")?.value).toBe(1);
  });

  it("rejects unknown labels and non-finite durations deterministically", () => {
    expect(() => observeHttpRequestDuration(
      { method: "GET", route: "/health", status_code: "200", unexpected: "value" },
      0.1,
    )).toThrow();
    expect(() => observeHttpRequestDuration(
      { method: "GET", route: "/health", status_code: "200" },
      Number.NaN,
    )).toThrow();
  });
});
