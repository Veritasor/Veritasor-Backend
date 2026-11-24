/**
 * Public tracing surface.
 *
 * The implementation lives in focused modules under `src/tracing/`:
 *
 *  - `protocol.ts`        — OTLP transport and feature-flag resolution
 *  - `resource.ts`        — cloud-provider resource detection
 *  - `exporter-config.ts` — endpoint and exporter option resolution
 *  - `trace-exporter.ts`  — trace exporter + sampler construction
 *  - `log-exporter.ts`    — log exporter construction
 *  - `mtls.ts`            — gRPC mTLS credentials and rotation watchers
 *  - `initialize.ts`      — SDK initialization
 *  - `shutdown.ts`        — SDK shutdown
 *  - `sampler.ts`         — per-route sampler
 *  - `sanitizer.ts`       — span attribute sanitizer
 *
 * This file re-exports the stable API consumed by the rest of the application
 * and keeps the HTTP/Soroban span helpers.
 */

import {
  SpanKind,
  SpanStatusCode,
  context,
  isSpanContextValid,
  propagation,
  trace,
  type Context,
  type Span,
} from "@opentelemetry/api";
import type { Request, Response } from "express";
import { isOpenTelemetryEnabled } from "./tracing/protocol.js";

export { getExporterProtocol, isGrpcMtlsEnabled, isOpenTelemetryEnabled } from "./tracing/protocol.js";
export type { ExporterProtocol } from "./tracing/protocol.js";

export {
  DEFAULT_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS,
  MAX_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS,
  resolveCloudDetectorTimeoutMs,
  detectAwsResources,
  detectGcpResources,
  detectKubernetesResources,
  detectCloudResources,
} from "./tracing/resource.js";
export type {
  CloudResourceAttributes,
  CloudResourceDetectionResult,
} from "./tracing/resource.js";

export { initializeOpenTelemetry } from "./tracing/initialize.js";
export { shutdownOpenTelemetry } from "./tracing/shutdown.js";

export const ALLOWED_BAGGAGE_KEYS = new Set(["tenant.id"]);

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

export function getHttpRequestContext(req: Request): Context {
  if (!isOpenTelemetryEnabled()) {
    return context.active();
  }

  return propagation.extract(context.active(), req.headers, HTTP_HEADER_GETTER);
}

export function getActiveTraceExemplarLabels(): Record<string, string> {
  const activeSpan = trace.getActiveSpan();
  const spanContext = activeSpan?.spanContext();

  if (!spanContext || !isSpanContextValid(spanContext)) {
    return {};
  }

  return {
    trace_id: spanContext.traceId,
  };
}

export const UNMATCHED_ROUTE = "__unmatched__";

export function getNormalizedRoute(req: Request): string {
  if (req.route && req.route.path !== undefined) {
    const basePath = req.baseUrl || "";
    const routePath = typeof req.route.path === "string" ? req.route.path : String(req.route.path);
    return `${basePath}${routePath}`;
  }
  return UNMATCHED_ROUTE;
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
  const extractedContext = getHttpRequestContext(req);

  let requestContext = extractedContext;
  const b = propagation.getBaggage(extractedContext);
  if (b) {
    let newBaggage = propagation.createBaggage();
    for (const key of ALLOWED_BAGGAGE_KEYS) {
      const entry = b.getEntry(key);
      if (entry) {
        newBaggage = newBaggage.setEntry(key, entry);
      }
    }
    requestContext = propagation.setBaggage(extractedContext, newBaggage);
  }

  context.with(requestContext, () => {
    const initialRoute = req.route && req.route.path !== undefined ? getNormalizedRoute(req) : undefined;
    const initialSpanName = initialRoute ? `HTTP ${req.method} ${initialRoute}` : `HTTP ${req.method}`;

    tracer.startActiveSpan(
      initialSpanName,
      {
        kind: SpanKind.SERVER,
        attributes: {
          "http.request.method": req.method,
          "url.path": req.path,
          ...(initialRoute ? { "http.route": initialRoute } : {}),
          "client.address": req.ip,
          "user_agent.original": req.headers["user-agent"] ?? "",
          "veritasor.correlation_id": correlationId,
        },
      },
      (span) => {
        const activeBaggage = propagation.getBaggage(context.active());
        const tenantId = activeBaggage?.getEntry("tenant.id")?.value;
        if (tenantId) {
          span.setAttribute("tenant.id", tenantId);
        }

        const spanExecutionContext = context.active();
        let ended = false;
        const endSpan = () => {
          if (ended) {
            return;
          }
          ended = true;
          const route = getNormalizedRoute(req);
          span.updateName?.(`HTTP ${req.method} ${route}`);
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
  let currentContext = context.active();
  const b = propagation.getBaggage(currentContext);
  if (b) {
    currentContext = propagation.setBaggage(currentContext, b.removeEntry("tenant.id"));
  }

  return context.with(currentContext, () => {
    return tracer.startActiveSpan(
      `soroban.rpc ${operationName}`,
      {
        kind: SpanKind.CLIENT,
        attributes: {
          "rpc.system": "soroban",
          "rpc.method": operationName,
          "soroban.rpc.attempt": attempt,
          "retry.attempt": attempt,
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
  });
}

function recordRedactedException(span: Span, error: unknown): void {
  const errorName = error instanceof Error ? error.name : "NonError";
  span.recordException({
    name: errorName,
    message: "redacted",
  });
  span.setAttribute("error.type", errorName);
}
