# Threat Model: Enhanced Attestation Submit Service

## Overview

This document outlines the threat model for the hardened `submitAttestation` service with retry logic, error taxonomy, and structured logging for Soroban blockchain submissions.

## Service Architecture

```
Client → API Layer → submitAttestation Service → Soroban Network
                    ↓
                 Structured Logs
                    ↓
               Error Taxonomy
                    ↓
              Retry Logic
```

## Threat Analysis

### 1. Transaction Security

#### 1.1 Double-Spending Prevention
**Threat**: Malicious actor submits duplicate attestations to create multiple on-chain transactions.

**Mitigations**:
- Idempotency keys at API layer prevent duplicate submissions
- Transaction hash validation ensures unique on-chain transactions
- Merkle root determinism prevents data manipulation

**Residual Risk**: Low - handled by existing API idempotency middleware

#### 1.2 Transaction Replay Attacks
**Threat**: Attacker replays a valid transaction to cause unintended effects.

**Mitigations**:
- Soroban network inherently prevents transaction replay through sequence numbers
- Nonce conflicts are detected and retried with exponential backoff
- Transaction expiration enforced by Stellar network

**Residual Risk**: Minimal - network-level protection

### 2. Retry Logic Security

#### 2.1 Infinite Retry Loops
**Threat**: Malformed error conditions cause infinite retry attempts.

**Mitigations**:
- Maximum retry attempts (3) enforced by configuration
- Exponential backoff with jitter prevents rapid-fire requests
- Non-retryable errors (validation, insufficient balance) fail immediately

**Residual Risk**: None - hard limits prevent infinite loops

#### 2.2 Resource Exhaustion
**Threat**: High retry volume exhausts server resources or rate limits.

**Mitigations**:
- Jitter (±25%) prevents thundering herd attacks
- Configurable max delay (30s) caps retry intervals
- Structured logging enables monitoring of retry patterns

**Residual Risk**: Low - controlled by configuration limits

#### 2.3 Fee Bump Attacks
**Threat**: Attacker manipulates fee structures to cause excessive fee payments.

**Mitigations**:
- Fee-related errors are retryable but logged for monitoring
- No automatic fee escalation beyond normal retry logic
- Operators can monitor fee bump patterns via structured logs

**Residual Risk**: Medium - requires operational monitoring

### 3. Error Handling Security

#### 3.1 Information Disclosure
**Threat**: Error messages leak sensitive internal information.

**Mitigations**:
- Client-safe error messages hide internal implementation details
- Sensitive information only logged internally with proper access controls
- Error taxonomy provides consistent, non-revealing responses

**Examples**:
- Bad: "Database connection failed to postgres://user:pass@host"
- Good: "Service temporarily unavailable"

**Residual Risk**: Low - systematic message sanitization

#### 3.2 Error Injection
**Threat**: Attacker manipulates error codes to bypass security controls.

**Mitigations**:
- Error codes are enums, not user-controllable strings
- Error classification logic is deterministic and tested
- Invalid error codes default to retryable behavior (safe default)

**Residual Risk**: None - code-based classification

### 4. Logging Security

#### 4.1 Log Injection
**Threat**: Malicious input injects structured data into logs.

**Mitigations**:
- JSON-structured logging prevents injection attacks
- Input sanitization before log entry
- No raw request bodies logged

**Residual Risk**: None - structured format prevents injection

#### 4.2 Sensitive Data Exposure
**Threat**: Logs contain sensitive information that could be exploited.

**Mitigations**:
- No private keys, passwords, or tokens in logs
- Transaction hashes and user IDs only (non-sensitive identifiers)
- Log access controlled by standard logging infrastructure

**Log Fields Analysis**:
```json
{
  "timestamp": "2024-03-15T12:00:00.000Z",     // Safe
  "level": "info",                           // Safe
  "service": "attestation-submit",           // Safe
  "message": "Human-readable description",   // Safe (sanitized)
  "userId": "user_123",                     // Non-sensitive identifier
  "businessId": "biz_456",                  // Non-sensitive identifier
  "period": "2024-03",                      // Non-sensitive
  "attempt": 1,                             // Safe
  "maxAttempts": 3,                         // Safe
  "error": "Error message",                 // Safe (sanitized)
  "errorCode": "ERROR_CODE",                // Safe (enum)
  "duration": 1500                          // Safe
}
```

**Residual Risk**: Low - no sensitive data logged

### 5. Network Security

#### 5.1 Soroban Network Manipulation
**Threat**: Attacker manipulates Soroban network responses to cause failures.

**Mitigations**:
- Network errors are retryable with exponential backoff
- Response validation prevents malformed data processing
- Timeout handling prevents hanging on slow responses

**Residual Risk**: Medium - depends on network security

#### 5.2 Man-in-the-Middle Attacks
**Threat**: Attacker intercepts or modifies Soroban communications.

**Mitigations**:
- HTTPS/TLS encryption for all network communications
- Stellar network signatures prevent transaction tampering
- Transaction hash validation detects corruption

**Residual Risk**: Low - cryptographic protections

### 6. Authentication & Authorization

#### 6.1 Unauthorized Submissions
**Threat**: Unauthorized user submits attestations for another business.

**Mitigations**:
- User authentication required at API layer
- Business ownership validation before submission
- User ID correlation in all log entries

**Residual Risk**: None - handled by existing auth middleware

#### 6.2 Privilege Escalation
**Threat**: Attacker gains elevated privileges to submit attestations.

**Mitigations**:
- Role-based access controls at API layer
- Business-scoped authorization checks
- Audit trail in structured logs

**Residual Risk**: None - existing auth framework

## Attack Scenarios

### Scenario 1: Fee Manipulation Attack
```
Attacker submits attestation with insufficient balance
→ Service returns 400 INSUFFICIENT_BALANCE (no retry)
→ Attacker cannot force fee payment through retries
```

**Detection**: Monitor `INSUFFICIENT_BALANCE` error codes per user
**Response**: Rate limit or temporarily suspend account

### Scenario 2: Network Flooding Attack
```
Attacker triggers network timeout errors
→ Service retries with exponential backoff (1s, 2s, 4s)
→ Jitter prevents synchronized retry storms
→ Max 3 attempts per request limits resource usage
```

**Detection**: Monitor retry patterns and `NETWORK_TIMEOUT` errors
**Response**: Network-level rate limiting

### Scenario 3: Error Information Harvesting
```
Attacker probes with various invalid inputs
→ Service returns consistent, non-revealing error messages
→ Internal details only logged, not exposed to client
→ Error taxonomy prevents information disclosure
```

**Detection**: Monitor for unusual error pattern requests
**Response**: Standard security monitoring

## Security Controls

### Preventive Controls
1. **Input Validation**: All inputs validated before processing
2. **Authentication**: Required for all attestation submissions
3. **Authorization**: Business ownership verification
4. **Rate Limiting**: API-level rate limiting prevents abuse
5. **Idempotency**: Duplicate submission prevention

### Detective Controls
1. **Structured Logging**: All events logged with correlation IDs
2. **Error Monitoring**: Error patterns tracked and alerted
3. **Retry Metrics**: Retry patterns monitored for anomalies
4. **Audit Trail**: Complete audit trail of all submissions

### Corrective Controls
1. **Circuit Breaking**: Service can be disabled if anomalies detected
2. **Rate Limiting**: Dynamic rate limiting based on behavior
3. **Account Suspension**: Automated suspension for abusive patterns
4. **Manual Review**: Security team review of suspicious patterns

## Monitoring & Alerting

### Key Metrics to Monitor
1. **Retry Rate**: Percentage of requests requiring retries
2. **Error Distribution**: Breakdown by error code
3. **Submission Success Rate**: Overall success percentage
4. **Response Time**: Including retry delays
5. **Failed Authentication**: Failed auth attempts per user

### Alert Thresholds
- Retry rate > 20% for sustained period
- `INSUFFICIENT_BALANCE` errors > 10/hour per user
- Network timeout errors > 50/hour globally
- Authentication failure rate > 5%

### Log Analysis
- Correlate user ID across multiple failures
- Track retry patterns for potential abuse
- Monitor error code distribution changes
- Analyze response time anomalies

## Residual Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Soroban network compromise | Low | High | Network monitoring, diversification |
| Zero-day in retry logic | Low | Medium | Code review, testing, rapid patching |
| Insider threat (logging access) | Low | Medium | Access controls, log rotation |
| Cryptographic weakness | Low | High | Regular security updates, monitoring |

## Compliance Considerations

### Data Protection
- No personal data in logs
- User IDs only (non-PII identifiers)
- Business IDs only (non-sensitive)

### Financial Regulations
- Transaction audit trail maintained
- Fee transparency in logs
- Error reporting for compliance

### Security Standards
- OWASP API Security guidelines followed
- Secure logging practices implemented
- Error handling meets security standards

## Testing & Validation

### Security Testing
- Penetration testing of retry logic
- Error injection testing
- Log injection attempts
- Authentication bypass attempts

### Performance Testing
- Load testing with retry scenarios
- Resource exhaustion testing
- Network failure simulation
- Concurrent submission testing

### Compliance Testing
- Data protection validation
- Audit trail completeness
- Error message sanitization
- Log access control validation

## Conclusion

The enhanced attestation submit service implements comprehensive security controls to address identified threats. The combination of retry logic with exponential backoff, clear error taxonomy, and structured logging provides both resilience and observability while maintaining security best practices.

Key security strengths:
- Hard limits prevent resource exhaustion
- Structured logging enables comprehensive monitoring
- Error taxonomy prevents information disclosure
- Retry logic handles transient failures safely

The service maintains a strong security posture while providing the resilience needed for blockchain interactions in a production environment.
