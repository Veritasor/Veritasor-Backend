# Threat Model Notes: Signup Abuse Prevention

## Auth, Webhooks, and Integrations

### Attack Vectors Addressed
- **IP Evasion:**
  - IPv6 canonicalization and IPv4-mapped normalization prevent attackers from bypassing rate limits using alternate notations.
- **Email Aliasing:**
  - Plus-addressing normalization blocks mass signups using `user+tag@domain.com` variants.
- **Burst/Distributed Attacks:**
  - Global and per-identifier rate limits, with progressive delays and explicit blocks, mitigate both single-source and distributed signup abuse.

### Observability & Error Handling
- All denials and blocks are logged with structured context (IP, email, reason).
- API responses include explicit error types and rate limit headers (no silent failures).

### API Contract Stability
- All changes are backward compatible; normalization is internal and does not affect API request/response shape.
- No changes to versioned endpoints or error envelope structure.

### Idempotency & Operator Guidance
- All normalization and blocking logic is deterministic and idempotent.
- Operators can monitor and tune thresholds via config, and all edge case handling is documented in tests/SETUP.md.

### Remaining Risks
- Attackers with access to large pools of real IPs/emails may still attempt distributed abuse, but global rate limits and observability provide mitigation and detection.

---

**See also:** tests/SETUP.md for implementation and test coverage details.
