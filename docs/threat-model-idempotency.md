# Threat Model: Idempotency Semantics

This document outlines the threat model for the idempotency implementation in Veritasor Backend.

## 1. Request Replay Attacks
- **Threat**: An attacker intercepts a valid request and replays it to cause duplicate side effects (e.g., multiple on-chain attestations).
- **Mitigation**: The `Idempotency-Key` header ensures that duplicate requests are detected. The middleware caches the original response and returns it for subsequent requests with the same key.
- **Residual Risk**: Attacker can still replay the request within the TTL window, but no duplicate side effects will occur.

## 2. Idempotency Key Collisions (Same Key, Different Body)
- **Threat**: A client accidentally (or maliciously) uses the same `Idempotency-Key` for two different operations.
- **Mitigation**: The middleware hashes the request body and compares it with the cached version. If the hashes do not match, the request is rejected with `422 Unprocessable Entity` (`IDEMPOTENCY_KEY_COLLISION`). This prevents the backend from incorrectly returning a cached response for a different operation.

## 3. Storage Exhaustion (DoS)
- **Threat**: An attacker sends a large number of requests with unique `Idempotency-Key` values to exhaust the server's memory or cache storage.
- **Mitigation**:
    - The in-memory store has a maximum size limit (`MAX_MEMORY_STORE_SIZE`).
    - Once the limit is reached, the store attempts to prune expired entries.
    - If the store is still full, it stops caching new entries to prevent Out-of-Memory (OOM) errors.
    - In production, a distributed cache like Redis should be used with eviction policies (e.g., LRU).

## 4. Clock Skew
- **Threat**: In a distributed environment, clock skew between server nodes could lead to inconsistent TTL enforcement.
- **Mitigation**: 
    - The current implementation uses a local in-memory store, so clock skew between nodes is not an issue (each node has its own cache).
    - If migrating to a shared store (Redis), use a single source of truth for time or relative TTLs (e.g., Redis `EXPIRE`).

## 5. Cross-User Key Collisions
- **Threat**: User A uses a key that User B also uses, leading to User B receiving User A's cached response.
- **Mitigation**: Idempotency keys are scoped by User ID (or IP address if anonymous). The full store key is `idempotency:{scope}:{userKey}:{keyValue}`, ensuring isolation between users.

## 6. Information Leakage
- **Threat**: Cached responses might contain sensitive data that should not be visible to unauthorized parties.
- **Mitigation**: 
    - Keys are scoped by user, so only the original requester (or someone with their credentials) can retrieve the cached response.
    - The middleware only caches successful responses (2xx).

## 7. Operational TTL Expectations
- **TTL Window**: 24 hours.
- **Rationale**: 24 hours is sufficient for most client retries in case of network failure or timeout.
- **Configuration**: Currently hardcoded as `DEFAULT_TTL_MS`, but can be overridden per middleware instance.
