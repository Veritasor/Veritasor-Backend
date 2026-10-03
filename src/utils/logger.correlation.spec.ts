import express, { type Request, type Response } from "express";
import request from "supertest";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  context,
  trace,
  type Span,
  type SpanContext,
  type Tracer,
} from "@opentelemetry/api";
import { AsyncHooksContextManager } from "@opentelemetry/context-async-hooks";
import { requestLogger } from "../middleware/requestLogger.js";
import { logger } from "./logger.js";

type LogEntry = Record<string, unknown>;
type MockSpan = Span & {
  setAttribute: ReturnType<typeof vi.fn>;
  setStatus: ReturnType<typeof vi.fn>;
  recordException: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
};

const TRACE_ID = "11111111111111111111111111111111";
const SPAN_ID = "2222222222222222";

function createMockSpan(): MockSpan {
  const spanContext: SpanContext = {
    traceId: TRACE_ID,
    spanId: SPAN_ID,
    traceFlags: 1,
    isRemote: false,
  };

  return {
    spanContext: () => spanContext,
    setAttribute: vi.fn().mockReturnThis(),
    setStatus: vi.fn(),
    recordException: vi.fn(),
    updateName: vi.fn().mockReturnThis(),
    addEvent: vi.fn().mockReturnThis(),
    addLink: vi.fn().mockReturnThis(),
    end: vi.fn(),
    isRecording: vi.fn(() => true),
  } as unknown as MockSpan;
}

describe("logger trace correlation", () => {
  const contextManager = new AsyncHooksContextManager();
  const originalOtelEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

  beforeAll(() => {
    context.setGlobalContextManager(contextManager.enable());
  });

  afterAll(() => {
    contextManager.disable();
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = originalOtelEndpoint;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = originalOtelEndpoint;
  });

  it("fails fast in tests when an active span log line masks trace correlation", () => {
    const span = createMockSpan();
    const consoleLogSpy = vi
      .spyOn(console, "log")
      .mockImplementation(() => undefined);

    expect(() => {
      context.with(trace.setSpan(context.active(), span), () => {
        logger.info({
          type: "handler",
          trace_id: undefined,
          span_id: undefined,
        });
      });
    }).toThrow(/missing active OpenTelemetry trace correlation/i);

    expect(consoleLogSpy).not.toHaveBeenCalled();
  });

  it("enriches every request lifecycle log with trace and span IDs across awaits", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://127.0.0.1:4318/v1/traces";

    const span = createMockSpan();
    const consoleLogSpy = vi
      .spyOn(console, "log")
      .mockImplementation(() => undefined);

    const mockTracer: Pick<Tracer, "startActiveSpan"> = {
      startActiveSpan: (
        _name: string,
        _options: unknown,
        callback: (activeSpan: Span) => unknown,
      ) => {
        return context.with(trace.setSpan(context.active(), span), () =>
          callback(span),
        );
      },
    };

    vi.spyOn(trace, "getTracer").mockReturnValue(mockTracer as Tracer);

    const app = express();
    app.use(requestLogger);
    app.get("/correlation", async (_req: Request, res: Response) => {
      logger.info({ type: "handler", step: "before-await" });
      await Promise.resolve();
      await new Promise((resolve) => setTimeout(resolve, 0));
      logger.info({ type: "handler", step: "after-await" });
      res.status(200).json({ ok: true });
    });

    const response = await request(app).get("/correlation?token=secret");

    expect(response.status).toBe(200);

    const entries = consoleLogSpy.mock.calls.map(
      ([line]: [unknown, ...unknown[]]) => JSON.parse(String(line)) as LogEntry,
    );
    const requestLogEntry = entries.find(
      (entry: LogEntry) =>
        entry.type === "request" && entry.path === "/correlation",
    );
    const correlationId = requestLogEntry?.correlationId;
    const lifecycleEntries = entries.filter(
      (entry: LogEntry) => entry.correlationId === correlationId,
    );

    expect(lifecycleEntries).toHaveLength(4);

    for (const entry of lifecycleEntries) {
      expect(entry.trace_id).toBe(TRACE_ID);
      expect(entry.span_id).toBe(SPAN_ID);
      expect(entry.correlationId).toEqual(correlationId);
    }

    const requestEntry = lifecycleEntries.find(
      (entry: LogEntry) => entry.type === "request",
    );
    const beforeAwaitEntry = lifecycleEntries.find(
      (entry: LogEntry) =>
        entry.type === "handler" && entry.step === "before-await",
    );
    const afterAwaitEntry = lifecycleEntries.find(
      (entry: LogEntry) =>
        entry.type === "handler" && entry.step === "after-await",
    );
    const responseEntry = lifecycleEntries.find(
      (entry: LogEntry) => entry.type === "response",
    );

    expect(requestEntry?.query).toEqual({ token: "[REDACTED]" });
    expect(beforeAwaitEntry).toBeDefined();
    expect(afterAwaitEntry).toBeDefined();
    expect(responseEntry?.statusCode).toBe(200);
  });
});
