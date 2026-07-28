import { trace, type Span, type SpanContext } from "@opentelemetry/api";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  httpRequestDuration,
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
    httpRequestDuration.reset();
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
