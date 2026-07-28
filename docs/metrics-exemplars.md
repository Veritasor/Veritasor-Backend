# Prometheus exemplars for trace correlation

The HTTP request duration histogram now emits exemplars that carry the active OpenTelemetry trace ID. This allows Grafana to link a spike in the histogram directly to the matching trace when the trace backend is configured.

## How it works

- The request logger observes the histogram at response time.
- The active span context is read from the current OpenTelemetry context.
- When a valid trace is present, the histogram attaches an exemplar label named `trace_id`.
- When no span is active, the exemplar is omitted and the histogram records the sample normally.

## Security and cardinality considerations

- Only the trace ID is attached as an exemplar label. No request headers, bodies, or other user-controlled values are exported.
- Trace IDs are bounded by the number of in-flight requests and the trace sampling policy, which keeps exemplar cardinality controlled.
- The implementation intentionally avoids adding per-request labels such as route or method to exemplars to prevent unbounded growth.

## Grafana link configuration

A typical Grafana link can use the exemplar value directly:

```json
{
  "title": "Open trace",
  "url": "https://your-tracing-ui.example/trace/$__value.raw"
}
```

If your tracing UI expects a different query parameter, substitute the placeholder accordingly. The key point is that the exemplar value is the trace ID emitted by the metric.
