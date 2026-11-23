# Observability and Tracing

## OpenTelemetry setup

`initializeOpenTelemetry()` is exported from `src/tracing.ts` and called once at
boot from `src/app.ts` (`telemetryReady`). Its implementation is split into
focused modules under `src/tracing/`:

| File | Responsibility |
| --- | --- |
| `protocol.ts` | `OTEL_EXPORTER_PROTOCOL` / `OTEL_GRPC_MTLS_ENABLED` resolution |
| `resource.ts` | AWS, GCP and Kubernetes resource attribute detection |
| `exporter-config.ts` | OTLP endpoint derivation and exporter options |
| `trace-exporter.ts` | Trace exporter and route-aware sampler construction |
| `log-exporter.ts` | Log exporter construction |
| `mtls.ts` | gRPC mTLS credentials and certificate rotation |
| `initialize.ts` | SDK initialization |
| `shutdown.ts` | SDK shutdown |
| `sampler.ts` / `sanitizer.ts` | Per-route sampling and PII redaction |

Exporter packages are imported lazily: only the protocol selected by
`OTEL_EXPORTER_PROTOCOL` is loaded. The supported environment variables are:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: enabling setting; tracing is disabled when unset.
- `OTEL_EXPORTER_PROTOCOL`: `http` (default) or `grpc`; unknown values fall back to `http`.
- `OTEL_SERVICE_NAME`: service name reported to the collector (default `veritasor-backend`).
- `OTEL_GRPC_MTLS_ENABLED` plus `OTEL_MTLS_CA`/`OTEL_MTLS_CERT`/`OTEL_MTLS_KEY` (secret loader) or `OTEL_MTLS_CA_PATH`/`OTEL_MTLS_CERT_PATH`/`OTEL_MTLS_KEY_PATH` (files): gRPC mutual TLS.
- `CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS`: per-detector timeout in milliseconds (default 1000, clamped to 100–5000).
- `OTEL_SAMPLING_DEFAULT_RATE`, `OTEL_SAMPLING_HOT_ROUTES`, `OTEL_SAMPLING_RARE_ROUTES`: route-aware sampler configuration.

## Attestation Submissions

Batch-flush deadlines and queue waits are traced with dedicated OpenTelemetry spans. This allows developers to debug batch-window delays and trace errors related to batch composition.

### Spans
- `queue.enqueue`: Emitted when an attestation is added to the batch queue. Includes `user.id`, `business.id`, and `queue.size` attributes.
- `batch.flush`: Emitted when the queue is flushed (either by reaching max size or flush deadline). Includes `batch.size` attribute. Contains Span Links back to the `queue.enqueue` spans to associate child submissions with the batch process.
- `queue.dequeue`: Emitted for each individual submission from the batch. Includes `queue.wait_time_ms` indicating the duration an item spent waiting in the queue. Links to its parent `queue.enqueue` span.

### Attributes
- `queue.size`: The size of the batching queue when the item was enqueued.
- `queue.wait_time_ms`: The duration (in ms) the item waited in the queue before processing.
- `batch.size`: The number of items processed during a batch flush.

## PgBouncer pool metrics

Set `METRICS_ENABLED=true` and provide `PGBOUNCER_METRICS_ADMIN_URL` to add
PgBouncer runtime statistics to the existing `/metrics` registry. The exporter
runs in-process but uses an isolated pool limited to one connection. It runs
`SHOW POOLS` and `SHOW STATS` after the prior cycle finishes, so a slow or failed
admin query cannot create overlapping work.

Use a dedicated PgBouncer account listed in `stats_users`; do not reuse the
application database credential or put an admin credential in `DATABASE_URL`.
The URL must target PgBouncer's virtual admin database (normally `pgbouncer`).
Store the URL in the deployment secret manager and never log it. `admin_users`
is not required: the exporter executes only read-only `SHOW` commands.

Configuration:

- `PGBOUNCER_METRICS_ADMIN_URL`: explicit admin-console connection URL. Unset disables the exporter.
- `PGBOUNCER_METRICS_SCRAPE_INTERVAL_MS`: default 15000, clamped to 1000..300000.
- `PGBOUNCER_METRICS_QUERY_TIMEOUT_MS`: default 2000, clamped to 100..min(interval, 30000).

Pool gauges carry `database` and `user`; server connection gauges also carry the
bounded `state` label. `SHOW STATS` totals are gauges because PgBouncer can reset
them on restart or `RELOAD`. Exporter health is reported by
`pgbouncer_scraper_enabled`, `pgbouncer_scrape_success`, `pgbouncer_scrape_errors_total`, scrape duration, and
the last-success timestamp. A failed scrape preserves the last good pool series
and does not affect application database traffic.

Prometheus recording and alerting rules live in `ops/alerts/backend.rules.yaml`.
They aggregate pool-user series at database scope for queue alerts and alert when
admin authentication or connectivity remains broken.