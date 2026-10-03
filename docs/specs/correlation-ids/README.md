# Structured Request Logging with Correlation IDs and Trace Context

## Overview

This document describes the implementation of structured request logging with correlation IDs and OpenTelemetry trace correlation in the Veritasor-Backend API. Correlation IDs enable request tracing across distributed systems, while `trace_id` and `span_id` let operators join logs to traces for a single in-flight request.

## Features

### 1. Automatic Correlation ID Generation
- Generates cryptographically secure UUIDs (v4) for each incoming request
- Uses `crypto.randomUUID()` for secure, unpredictable identifiers
- Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (RFC 4122 compliant)

### 2. Header-Based Correlation ID Propagation
- Accepts existing correlation IDs via `X-Request-ID` header
- Enables distributed tracing across microservices
- Returns correlation ID in response header for client-side tracking

### 3. Structured JSON Logging
- Logs request, handler, and response events with correlation metadata
- Adds `trace_id` and `span_id` whenever an OpenTelemetry span is active
- Includes metadata: method, path, status code, duration, timestamp
- Compatible with log aggregation tools (ELK, Datadog, Splunk)

### 4. Request Context Attachment
- Attaches correlation ID to request object via `CorrelatedRequest` interface
- Available in downstream handlers for logging and tracing
- Type-safe access: `(req as CorrelatedRequest).correlationId`

## Security Considerations

### 1. Sensitive Data Protection
**CRITICAL**: The request logger NEVER logs:
- Request/response bodies (prevents password, token, PII exposure)
- Authorization headers
- Cookie values
- API keys or secrets

**Implementation**:
```typescript
// Body is purposely omitted to avoid sensitive data
const requestLog = {
  type: 'request',
  correlationId,
  method: req.method,
  path: req.path,
  query: req.query,  // Query params only (no body)
  ip: req.ip,
  userAgent: req.headers['user-agent'],
  timestamp: new Date().toISOString(),
};
```

### 2. Correlation ID Security
- **Unpredictability**: Uses `crypto.randomUUID()` (cryptographically secure)
- **No Information Leakage**: UUIDs contain no meaningful data
- **Header Injection Prevention**: Express.js handles header sanitization
- **Rate Limiting**: Correlation IDs don't bypass rate limiting

### 3. Log Injection Prevention
- JSON serialization prevents log injection attacks
- Structured logging format separates data from message
- No string concatenation in log messages
- In tests, the logger throws immediately if a log line is emitted while a span is active but the final record does not contain the active `trace_id` and `span_id`

### 4. IP Address Logging
- Logs client IP for abuse detection and security auditing
- Respects `X-Forwarded-For` header when behind proxy
- Consider GDPR/privacy implications for IP logging

## Usage

### Basic Request Logging
All requests automatically receive correlation IDs:

```bash
# Request without correlation ID
curl http://localhost:3000/api/health

# Response includes X-Request-ID header
HTTP/1.1 200 OK
X-Request-ID: f4d68654-78e5-4b92-97d6-25d8bedfda35
```

### Distributed Tracing
Propagate correlation ID across services:

```bash
# Service A generates correlation ID
curl -H "X-Request-ID: trace-12345" http://service-a/api/data

# Service A calls Service B with same correlation ID
curl -H "X-Request-ID: trace-12345" http://service-b/api/process

# Both services log with same correlation ID for tracing
```

### Accessing Correlation ID in Handlers
```typescript
import { CorrelatedRequest } from '../middleware/requestLogger.js';

app.get('/api/example', async (req: Request, res: Response) => {
  const correlationId = (req as CorrelatedRequest).correlationId;

  await someAsyncWork();

  logger.info({
    type: 'business_logic',
    correlationId,
    message: 'Processing request',
  });

  res.json({ success: true });
});
```

When OpenTelemetry is enabled, the logger automatically enriches that log line with the active `trace_id` and `span_id` from the request span.

## Log Format

### Request Log
```json
{
  "type": "request",
  "correlationId": "f4d68654-78e5-4b92-97d6-25d8bedfda35",
  "trace_id": "11111111111111111111111111111111",
  "span_id": "2222222222222222",
  "method": "GET",
  "path": "/api/health",
  "query": {},
  "ip": "::ffff:127.0.0.1",
  "userAgent": "curl/7.88.1",
  "timestamp": "2026-03-27T08:19:43.974Z"
}
```

### Response Log
```json
{
  "type": "response",
  "correlationId": "f4d68654-78e5-4b92-97d6-25d8bedfda35",
  "trace_id": "11111111111111111111111111111111",
  "span_id": "2222222222222222",
  "method": "GET",
  "path": "/api/health",
  "statusCode": 200,
  "durationMs": 0.348,
  "timestamp": "2026-03-27T08:19:43.976Z"
}
```

## Testing

### Unit Tests
Located in `src/utils/logger.correlation.spec.ts`:

1. **Fail-fast enforcement**: Verifies tests throw if a log line masks `trace_id` or `span_id` while a span is active
2. **Request lifecycle correlation**: Validates request, handler, and response logs all carry the active trace metadata
3. **Async propagation**: Confirms correlation survives `await` boundaries inside handlers
4. **Redaction compatibility**: Ensures sensitive query values remain redacted while trace correlation is present

### Running Tests
```bash
npm test
```

## Performance Considerations

- **Minimal Overhead**: UUID generation is fast (~1μs per ID)
- **No Database Calls**: Correlation IDs are stateless
- **Memory Efficient**: UUIDs are 36 bytes each
- **Async Logging**: Non-blocking log writes

## Monitoring and Alerting

### Recommended Alerts
1. **Missing Correlation IDs**: Alert if requests lack correlation IDs
2. **Missing Trace Correlation**: Alert if in-request logs are missing `trace_id` or `span_id`
3. **Duplicate Correlation IDs**: Detect ID reuse (potential security issue)
4. **Log Volume**: Monitor log volume by correlation ID
5. **Error Rate**: Track errors per correlation ID

### Log Aggregation
Query logs by correlation ID:
```bash
# Elasticsearch/Kibana
GET /logs/_search
{
  "query": {
    "match": {
      "correlationId": "f4d68654-78e5-4b92-97d6-25d8bedfda35"
    }
  }
}
```

## Future Enhancements

1. **Baggage**: Propagate custom metadata across services
2. **Sampling**: Implement sampling for high-traffic scenarios
3. **Correlation ID Length**: Configurable ID length/entropy
4. **Log/trace dashboards**: Add canned observability dashboards keyed by `correlationId`, `trace_id`, and `span_id`

## References

- [RFC 4122: UUID Specification](https://tools.ietf.org/html/rfc4122)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
