# Chaos Testing with Toxiproxy

This directory contains property-based chaos tests using Toxiproxy to simulate downstream faults.
These tests validate that the API degrades gracefully when dependencies (Postgres, Redis, Soroban) experience turbulence.

## Execution

The chaos tests run on a separate CI label and must be explicitly triggered to prevent flakiness in the default test job.

Run locally via:
```bash
CHAOS_TESTS=true pnpm test tests/chaos/toxiproxy.spec.ts
```

## Failure Scenarios & Expected Behavior

| Downstream | Fault Type | Expected Behavior |
| :--- | :--- | :--- |
| **Postgres** | Connection Reset (`reset_peer`) | The connection pool (pg/tinypool) should handle the reset. Idempotent retries should prevent data corruption. |
| **Postgres** | High Latency (`latency`) | Query should timeout if latency > statement_timeout (5s). App should return 503 rather than locking up. |
| **Redis** | Partition/Timeout | Rate limiters should fail open or use fallback. Cache operations should be bypassed without breaking critical paths. |
| **Soroban** | Connection Timeout | The `SorobanRetryPolicy` will retry with backoff. If max retries are exceeded, the circuit breaker opens and rejects requests immediately. |
| **Soroban** | Partition during Write | If the network drops while submitting a transaction, idempotency middleware ensures that the client can retry without generating a duplicate attestation. |

## SLO Expectations

1. **API Availability**: The API must maintain >99.9% uptime for core reads, even if Soroban RPC is degraded.
2. **Data Integrity**: Network partitions during write operations must **never** corrupt internal idempotency state or create split-brain records between PG and Soroban.
3. **Timeouts**: No API request should hang indefinitely. Global request timeout is 10s. Downstream timeouts must be strictly bounded (e.g. 5s for DB).
