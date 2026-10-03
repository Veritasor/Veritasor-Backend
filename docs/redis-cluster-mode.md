Redis Cluster Mode

Overview

This project supports single-node Redis and Redis Cluster deployments. When `REDIS_CLUSTER_NODES` is set (comma-separated host:port list) the application will use `ioredis` Cluster mode unless `REDIS_FORCE_SINGLE_NODE=true`.

Hash-tagging

To ensure keys for the same business land in the same Redis Cluster slot we use a hash tag helper: keys include `{businessId}` wrapped in braces. For example:

- rate limiter: `rate-limit:{biz-123}:ip:1.2.3.4`
- idempotency: `idempotency:payments:{biz-123}:user:abc:key-uuid`

Configuration

- `REDIS_URL` - single-node Redis URL (redis[s]://...)
- `REDIS_CLUSTER_NODES` - comma-separated cluster nodes, e.g. `host1:7000,host2:7001`
- `REDIS_FORCE_SINGLE_NODE` - if `true`, prefer single-node mode even when cluster nodes are provided
- `REDIS_TLS` - `true` to enable TLS

Health

Call `redisHealthProbe()` to get a readiness-friendly `ok` / `error:<msg>` string. It performs a PING with a 1s timeout and never throws.

Failure modes

- The Redis circuit breaker prevents noisy retries during outages.
- MOVED/ASK redirects are parsed and either handled by the client or retried against the target node.

See source in `src/redis.ts` for implementation details.
