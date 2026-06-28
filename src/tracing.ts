import {
  SpanKind,
  SpanStatusCode,
  context,
  propagation,
  trace,
  type Context,
  type Span,
} from "@opentelemetry/api";
import type { Request, Response } from "express";
import { logger } from "./utils/logger.js";

type OpenTelemetrySdk = {
  start: () => void;
  shutdown: () => Promise<void>;
};

let sdk: OpenTelemetrySdk | undefined;
let sdkStarted = false;
let sdkStartPromise: Promise<OpenTelemetrySdk | undefined> | undefined;

const HTTP_HEADER_GETTER = {
  get(carrier: Request["headers"], key: string) {
    const value = carrier[key.toLowerCase()];
    return Array.isArray(value)
      ? value
      : value === undefined
        ? undefined
        : [value];
  },
  keys(carrier: Request["headers"]) {
    return Object.keys(carrier);
  },
};

export function isOpenTelemetryEnabled(): boolean {
  return Boolean(process.env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim());
}

export async function initializeOpenTelemetry(): Promise<
  OpenTelemetrySdk | undefined
> {
  if (!isOpenTelemetryEnabled()) {
    return undefined;
  }

  if (sdkStartPromise) {
    return sdkStartPromise;
  }

  sdkStartPromise = (async () => {
    const [{ NodeSDK }, { OTLPTraceExporter }] = await Promise.all([
      import("@opentelemetry/sdk-node"),
      import("@opentelemetry/exporter-trace-otlp-http"),
    ]);

    const traceExporter = new OTLPTraceExporter({
      url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
    });

    sdk = new NodeSDK({
      serviceName: process.env.OTEL_SERVICE_NAME ?? "veritasor-backend",
      traceExporter,
    });

    sdk.start();
    sdkStarted = true;

    logger.info({
      type: "opentelemetry",
      enabled: true,
      exporter: "otlp-http",
    });

    return sdk;
  })().catch((error: unknown) => {
    sdkStartPromise = undefined;
    logger.error(
      {
        type: "opentelemetry",
        enabled: false,
        errorMessage: error instanceof Error ? error.message : String(error),
      },
      "opentelemetry: failed to initialize tracing exporter",
    );
    throw error;
  });

  return sdkStartPromise;
}

export async function shutdownOpenTelemetry(): Promise<void> {
  if (!sdkStarted || !sdk) {
    return;
  }

  await sdk.shutdown();
  sdkStarted = false;
}

export function getHttpRequestContext(req: Request): Context {
  if (!isOpenTelemetryEnabled()) {
    return context.active();
  }

  return propagation.extract(context.active(), req.headers, HTTP_HEADER_GETTER);
}

export function startHttpRequestSpan(
  req: Request,
  res: Response,
  correlationId: string,
  next: () => void,
  onFinish?: () => void,
): void {
  if (!isOpenTelemetryEnabled()) {
    if (onFinish) {
      res.once("finish", onFinish);
    }
    next();
    return;
  }

  const tracer = trace.getTracer("veritasor-backend.http");
  const requestContext = getHttpRequestContext(req);

  context.with(requestContext, () => {
    tracer.startActiveSpan(
      `HTTP ${req.method} ${req.path}`,
      {
        kind: SpanKind.SERVER,
        attributes: {
          "http.request.method": req.method,
          "url.path": req.path,
          "client.address": req.ip,
          "user_agent.original": req.headers["user-agent"] ?? "",
          "veritasor.correlation_id": correlationId,
        },
      },
      (span) => {
        const spanExecutionContext = context.active();
        let ended = false;
        const endSpan = () => {
          if (ended) {
            return;
          }
          ended = true;
          const route = (req.route?.path as string | undefined) ?? req.path;
          span.setAttribute("http.route", route);
          span.setAttribute("http.response.status_code", res.statusCode);
          if (res.statusCode >= 500) {
            span.setStatus({ code: SpanStatusCode.ERROR });
          }
          span.end();
        };

        res.once("finish", () => {
          context.with(spanExecutionContext, () => {
            onFinish?.();
            endSpan();
          });
        });
        res.once("close", () => {
          context.with(spanExecutionContext, endSpan);
        });

        try {
          next();
        } catch (error) {
          recordRedactedException(span, error);
          span.setStatus({ code: SpanStatusCode.ERROR });
          endSpan();
          throw error;
        }
      },
    );
  });
}

export async function traceSorobanRpcAttempt<T>(
  operationName: string,
  attempt: number,
  execute: () => Promise<T>,
): Promise<T> {
  if (!isOpenTelemetryEnabled()) {
    return execute();
  }

  const tracer = trace.getTracer("veritasor-backend.soroban");

  return tracer.startActiveSpan(
    `soroban.rpc ${operationName}`,
    {
      kind: SpanKind.CLIENT,
      attributes: {
        "rpc.system": "soroban",
        "rpc.method": operationName,
        "soroban.rpc.attempt": attempt,
      },
    },
    async (span) => {
      try {
        const result = await execute();
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (error) {
        recordRedactedException(span, error);
        span.setStatus({ code: SpanStatusCode.ERROR });
        throw error;
      } finally {
        span.end();
      }
    },
  );
}

function recordRedactedException(span: Span, error: unknown): void {
  const errorName = error instanceof Error ? error.name : "NonError";
  span.recordException({
    name: errorName,
    message: "redacted",
  });
  span.setAttribute("error.type", errorName);
}
