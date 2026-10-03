# Threat Model: Enhanced Optional Auth Middleware

## Overview

This document outlines the threat model for the enhanced `optionalAuth` middleware that provides clear distinction between absent vs malformed tokens, comprehensive error classification, and structured logging for authentication events.

## Service Architecture

```
Client → API Layer → optionalAuth Middleware → JWT Verification → Database Lookup
                    ↓
                 Structured Logs
                    ↓
               Event Classification
                    ↓
              Request Processing
```

## Threat Analysis

### 1. Token Security

#### 1.1 Token Enumeration Attacks
**Threat**: Attacker attempts to enumerate valid tokens by observing different error responses.

**Mitigations**:
- All auth failures result in the same behavior: `req.user = undefined`
- No 401 responses from optionalAuth middleware
- Structured logs don't expose token content or validation details
- Consistent processing time regardless of token validity

**Residual Risk**: Low - behavioral uniformity prevents enumeration

#### 1.2 Token Injection Attacks
**Threat**: Attacker injects malicious tokens to exploit parsing vulnerabilities.

**Mitigations**:
- Robust token extraction with strict validation
- Case-insensitive Bearer prefix validation
- Proper whitespace handling and token length limits
- Malformed headers classified as `MALFORMED_HEADER` events

**Residual Risk**: Minimal - comprehensive input validation

#### 1.3 Token Replay Attacks
**Threat**: Attacker replays captured tokens to gain unauthorized access.

**Mitigations**:
- JWT verification includes expiration and signature validation
- Database verification ensures user still exists
- Structured logging tracks authentication patterns
- Request correlation via `requestId` enables replay detection

**Residual Risk**: Low - JWT provides inherent replay protection

### 2. Header Manipulation

#### 2.1 Authorization Header Injection Attacks
**Threat**: Attacker manipulates Authorization header to cause parsing errors or information disclosure.

**Mitigations**:
- Comprehensive header parsing with error handling
- All parsing errors result in `MALFORMED_HEADER` classification
- No sensitive information leaked in error responses
- Structured logging captures header metadata safely

**Examples of Mitigated Attacks**:
- `Authorization: Basic dGVzdA==` → `MALFORMED_HEADER`
- `Authorization: Bearr token` → `MALFORMED_HEADER`
- `Authorization: Bearer:token` → `MALFORMED_HEADER`
- `Authorization: <script>alert('xss')</script>` → `MALFORMED_HEADER`

**Residual Risk**: None - all malformed headers handled uniformly

#### 2.2 Header Length Attacks
**Threat**: Attacker sends extremely long Authorization headers to cause memory exhaustion.

**Mitigations**:
- Token length tracking in logs for monitoring
- No unbounded string operations
- Memory usage proportional to header size
- Rate limiting at application layer

**Residual Risk**: Low - bounded memory usage

### 3. Database Security

#### 3.1 Database Enumeration via User Lookup
**Threat**: Attacker uses valid tokens to enumerate existing users by observing database lookup results.

**Mitigations**:
- User not found results in `USER_NOT_FOUND` event (same behavior as invalid token)
- No different error responses for missing users
- Structured logs track attempted user IDs for monitoring
- Rate limiting prevents bulk enumeration

**Residual Risk**: Low - behavioral uniformity prevents enumeration

#### 3.2 Database Denial of Service
**Threat**: Attacker overwhelms database with authentication requests.

**Mitigations**:
- Database errors classified as `DATABASE_ERROR` but don't block requests
- Requests proceed without authentication even if database fails
- Structured logging enables monitoring of database issues
- Circuit breaking patterns can be implemented at higher levels

**Residual Risk**: Medium - requires operational monitoring

### 4. Logging Security

#### 4.1 Log Injection
**Threat**: Attacker injects malicious content into structured logs.

**Mitigations**:
- JSON-structured logging prevents injection attacks
- All log fields properly escaped and serialized
- No raw user input directly logged
- Token content never logged, only metadata

**Log Fields Analysis**:
```json
{
  "timestamp": "2024-03-15T12:00:00.000Z",     // Safe
  "level": "info",                               // Safe (enum)
  "service": "optional-auth",                    // Safe (constant)
  "event": "AUTH_EVENT_TYPE",                    // Safe (enum)
  "userId": "user_123",                          // Non-sensitive identifier
  "userAgent": "Mozilla/5.0...",                 // Safe (sanitized)
  "ip": "192.168.1.100",                       // Safe (IP address)
  "requestId": "req_1234567890_abc",            // Safe (generated)
  "error": "Error message",                      // Safe (sanitized)
  "tokenLength": 256,                            // Safe (number only)
  "hasBearerPrefix": true,                       // Safe (boolean)
  "headerPresent": true,                         // Safe (boolean)
  "duration": 15                                 // Safe (number only)
}
```

**Residual Risk**: None - structured format prevents injection

#### 4.2 Information Disclosure via Logs
**Threat**: Sensitive authentication information exposed in logs.

**Mitigations**:
- No token content or secrets logged
- User IDs only (non-sensitive identifiers)
- Error messages sanitized for client safety
- Log access controlled by standard logging infrastructure

**Residual Risk**: Low - no sensitive data logged

### 5. Timing Attacks

#### 5.1 Authentication Timing Attacks
**Threat**: Attacker measures response times to infer token validity.

**Mitigations**:
- Consistent processing path regardless of authentication outcome
- Database lookup performed for all valid tokens
- Structured logging adds minimal overhead
- No early returns based on token validity

**Processing Flow**:
1. Extract and classify token (consistent time)
2. Verify JWT (consistent time for valid tokens)
3. Database lookup (consistent time for valid tokens)
4. Log event (consistent time)
5. Call next() (always)

**Residual Risk**: Low - consistent processing paths

### 6. Network Security

#### 6.1 Man-in-the-Middle Attacks
**Threat**: Attacker intercepts or modifies Authorization headers.

**Mitigations**:
- HTTPS/TLS encryption for all communications
- JWT signature verification prevents token tampering
- Header manipulation detected and logged
- Request correlation via `requestId`

**Residual Risk**: Low - cryptographic protections

## Attack Scenarios

### Scenario 1: Token Enumeration Attack
```
Attacker sends: Authorization: Bearer valid_token_1
→ Log: AUTH_SUCCESS (user found)

Attacker sends: Authorization: Bearer invalid_token
→ Log: INVALID_TOKEN (same behavior: req.user = undefined)

Attacker sends: Authorization: Bearer nonexistent_user_token
→ Log: USER_NOT_FOUND (same behavior: req.user = undefined)
```

**Detection**: Monitor `INVALID_TOKEN` vs `USER_NOT_FOUND` ratios
**Response**: Rate limiting and IP blocking for excessive attempts

### Scenario 2: Header Injection Attack
```
Attacker sends: Authorization: <script>alert('xss')</script>
→ Log: MALFORMED_HEADER (parsed safely)

Attacker sends: Authorization: Basic dGVzdA==
→ Log: MALFORMED_HEADER (wrong scheme)

Attacker sends: Authorization: Bearer:malicious_payload
→ Log: MALFORMED_HEADER (wrong separator)
```

**Detection**: Monitor `MALFORMED_HEADER` event patterns
**Response**: IP blocking for systematic header manipulation

### Scenario 3: Database DoS Attack
```
Attacker floods with valid tokens → Database overload
→ Log: DATABASE_ERROR (requests continue without auth)
→ Service remains available (degraded but functional)
```

**Detection**: Monitor `DATABASE_ERROR` event rates
**Response**: Circuit breaking and rate limiting

### Scenario 4: Timing Attack Attempt
```
Attacker measures response times:
- No token: ~5ms
- Invalid token: ~8ms  
- Valid token: ~12ms (includes DB lookup)
- Valid token, no user: ~12ms (includes DB lookup)
```

**Detection**: Monitor timing patterns in auth logs
**Response**: Add jitter to processing times if needed

## Security Controls

### Preventive Controls
1. **Input Validation**: Strict header parsing and token validation
2. **Behavioral Uniformity**: Same response for all auth failures
3. **Structured Logging**: Safe, parseable log format
4. **Rate Limiting**: Application-level protection against abuse
5. **Encryption**: HTTPS/TLS for all communications

### Detective Controls
1. **Comprehensive Logging**: All auth events logged with correlation
2. **Event Classification**: 10 specific auth event types for monitoring
3. **Performance Tracking**: Request duration monitoring
4. **Pattern Analysis**: Log analysis for attack detection
5. **Metrics Collection**: Auth success/failure rates

### Corrective Controls
1. **Rate Limiting**: Dynamic limits based on behavior patterns
2. **IP Blocking**: Automated blocking for malicious patterns
3. **Circuit Breaking**: Database failure handling
4. **Alerting**: Real-time alerts for suspicious patterns
5. **Manual Review**: Security team investigation of anomalies

## Monitoring & Alerting

### Key Metrics to Monitor
1. **Auth Success Rate**: Percentage of `AUTH_SUCCESS` events
2. **Malformed Header Rate**: Percentage of `MALFORMED_HEADER` events
3. **Database Error Rate**: Frequency of `DATABASE_ERROR` events
4. **Token Validation Time**: Average JWT verification duration
5. **Database Lookup Time**: Average user lookup duration

### Alert Thresholds
- `MALFORMED_HEADER` rate > 10% of total auth events
- `DATABASE_ERROR` rate > 5% of total auth events
- Auth success rate < 80% for sustained periods
- Average auth processing time > 100ms
- High-frequency requests from single IP

### Log Analysis Patterns
```bash
# Find potential token enumeration attacks
grep '"event":"INVALID_TOKEN"' auth.log | cut -d',' -f8 | sort | uniq -c | sort -nr

# Monitor malformed header patterns
grep '"event":"MALFORMED_HEADER"' auth.log | jq -r '.userAgent' | sort | uniq -c

# Track database issues by time
grep '"event":"DATABASE_ERROR"' auth.log | jq -r '.timestamp' | cut -d'T' -f1 | sort | uniq -c

# Find slow authentication requests
grep '"duration":[0-9]*' auth.log | jq 'select(.duration > 100)'

# Monitor authentication by IP
grep '"ip":"' auth.log | jq -r '.ip' | sort | uniq -c | sort -nr | head -10
```

## Residual Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Sophisticated timing attacks | Low | Medium | Add jitter, monitor timing patterns |
| Database credential exposure | Low | High | Secure credential management, monitoring |
| Log infrastructure compromise | Low | Medium | Log access controls, encryption |
| Zero-day JWT vulnerabilities | Low | High | Keep libraries updated, monitoring |
| Insider threat (log access) | Low | Medium | Access controls, audit trails |

## Compliance Considerations

### Data Protection
- No personal data in logs beyond user IDs
- No sensitive authentication data logged
- IP addresses logged only for security monitoring
- User agent strings logged for attack detection

### Security Standards
- OWASP API Security guidelines followed
- Secure logging practices implemented
- Input validation and sanitization
- Error handling without information disclosure

### Audit Requirements
- Complete audit trail of all auth events
- Correlation IDs for request tracking
- Tamper-evident logging structure
- Retention policies for security logs

## Testing & Validation

### Security Testing
- Penetration testing of token parsing
- Header injection attempt testing
- Timing attack resistance testing
- Database failure scenario testing

### Performance Testing
- Load testing with various auth scenarios
- Memory usage testing with large headers
- Database performance under auth load
- Logging performance impact testing

### Compliance Testing
- Data protection validation
- Log access control testing
- Audit trail completeness verification
- Security standards compliance testing

## Conclusion

The enhanced optionalAuth middleware implements comprehensive security controls to address identified threats while maintaining the optional nature of authentication. The combination of clear event classification, structured logging, and behavioral uniformity provides strong protection against common authentication attacks while enabling effective monitoring and operational visibility.

Key security strengths:
- Clear distinction between absent vs malformed tokens
- Comprehensive error classification without information disclosure
- Structured logging for security monitoring and debugging
- Consistent behavior regardless of authentication outcome
- Robust input validation and error handling

The service maintains a strong security posture while providing the flexibility needed for optional authentication patterns in modern API architectures.
