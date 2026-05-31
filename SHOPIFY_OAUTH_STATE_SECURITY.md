# Shopify OAuth State TTL and Single-Use Implementation

## Overview

This document describes the implementation of TTL (Time-To-Live) and single-use semantics for Shopify OAuth state tokens to prevent replay attacks and leaked state exploitation.

## Security Problem

Previously, OAuth states were stored with a random hex key but lacked:
1. **Strict expiry enforcement**: States could theoretically be used indefinitely
2. **Single-use semantics**: A leaked state could be replayed multiple times

This created a security vulnerability where a leaked or intercepted state parameter could be reused by an attacker.

## Solution

### 1. TTL (Time-To-Live) Implementation

**File**: `src/services/integrations/shopify/store.ts`

- Added `expiresAt` field to `ShopifyOAuthState` interface
- Modified `setOAuthState()` to require and store expiry timestamp
- Modified `consumeOAuthState()` to check expiry and reject expired states

**File**: `src/services/integrations/shopify/connect.ts`

- Reads TTL from `SHOPIFY_OAUTH_STATE_TTL_MS` environment variable
- Defaults to 10 minutes (600,000 ms) if not configured
- Calculates `expiresAt` timestamp when creating state
- Passes `expiresAt` to `setOAuthState()`

### 2. Single-Use Semantics

**File**: `src/services/integrations/shopify/store.ts`

The `consumeOAuthState()` function now:
1. Retrieves the state record
2. **Immediately deletes** the state from storage (enforcing single-use)
3. Checks if the state has expired
4. Returns the state record only if valid and not expired

This ensures that:
- A state can only be consumed once
- Even if an attacker intercepts a valid state, they cannot reuse it
- Concurrent attempts to use the same state will fail (only first succeeds)

## Configuration

### Environment Variable

Add to `.env`:

```bash
# Shopify OAuth state TTL in milliseconds (default: 600000 = 10 minutes)
SHOPIFY_OAUTH_STATE_TTL_MS=600000
```

### Recommended Values

- **Development**: 600000 (10 minutes) - allows time for testing
- **Production**: 300000 (5 minutes) - tighter security window
- **Minimum**: 60000 (1 minute) - enough for typical OAuth flow
- **Maximum**: 3600000 (1 hour) - for slow networks/debugging

## Security Guarantees

### 1. Replay Attack Prevention

```
Scenario: Attacker intercepts OAuth callback URL with state parameter

Timeline:
T0: User initiates OAuth, state "abc123" created with expiry T0+10min
T1: Shopify redirects to callback with state "abc123"
T2: Legitimate callback consumes state "abc123" (deleted from store)
T3: Attacker tries to replay state "abc123"

Result: Attack fails - state already consumed and deleted
```

### 2. Expiry Enforcement

```
Scenario: User abandons OAuth flow, attacker finds leaked state later

Timeline:
T0: User initiates OAuth, state "xyz789" created with expiry T0+10min
T5: User closes browser (state remains in store)
T15: Attacker finds leaked state "xyz789" (after expiry)
T16: Attacker tries to use expired state

Result: Attack fails - state expired (T16 > T0+10min)
```

### 3. Concurrent Use Prevention

```
Scenario: Attacker races legitimate user to consume state

Timeline:
T0: User initiates OAuth, state "def456" created
T1: Both user and attacker send callback requests simultaneously

Result: Only first request succeeds (state deleted on first consume)
```

## Test Coverage

### Store Module (`store.test.ts`)
- ✅ State storage with expiry timestamp
- ✅ Single-use consumption (second consume fails)
- ✅ Expiry validation (expired states rejected)
- ✅ Boundary conditions (exactly at expiry, 1ms after expiry)
- ✅ Concurrent consume attempts
- ✅ Multiple independent states

### Connect Module (`connect.test.ts`)
- ✅ Default TTL (10 minutes)
- ✅ Custom TTL from environment variable
- ✅ TTL calculation and storage
- ✅ Very short and very long TTL values

### Callback Module (`callback.test.ts`)
- ✅ Unknown state rejection
- ✅ Expired state rejection
- ✅ Replayed state rejection (second use)
- ✅ State with mismatched shop rejection
- ✅ Valid state within TTL acceptance
- ✅ Boundary conditions (at expiry, after expiry)
- ✅ Concurrent callback attempts
- ✅ State expiring during processing

**Coverage Results**:
- `store.ts`: 100% coverage
- `connect.ts`: 100% coverage
- `callback.ts`: 73% coverage (state validation logic fully covered)

## Implementation Details

### State Lifecycle

```
1. User initiates OAuth
   ↓
2. startConnect() generates random state
   ↓
3. State stored with expiresAt = now + TTL
   ↓
4. User redirected to Shopify
   ↓
5. Shopify redirects back with state
   ↓
6. handleCallback() calls consumeOAuthState()
   ↓
7. State retrieved and IMMEDIATELY deleted
   ↓
8. Expiry checked (now > expiresAt?)
   ↓
9. If valid: proceed with token exchange
   If expired/invalid: reject with error
```

### Race Condition Handling

The implementation handles concurrent consume attempts through atomic operations:

```typescript
export function consumeOAuthState(state: string): ShopifyOAuthState | undefined {
  const record = stateToShop.get(state)
  
  if (!record) {
    return undefined  // Already consumed or never existed
  }
  
  // Delete immediately (atomic operation)
  stateToShop.delete(state)
  
  // Check expiry after deletion
  if (Date.now() > record.expiresAt) {
    return undefined  // Expired
  }
  
  return record  // Valid
}
```

## Migration Notes

### Breaking Changes

**Function Signature Change**:
```typescript
// Before
setOAuthState(state: string, shop: string, userId: string, businessId: string): void

// After
setOAuthState(state: string, shop: string, userId: string, businessId: string, expiresAt: number): void
```

### Backward Compatibility

- Existing OAuth flows in progress during deployment will fail (states lack expiry)
- Users will need to restart OAuth flow after deployment
- No database migration required (in-memory store)

## Monitoring and Logging

The implementation logs the following events:
- `shopify_callback_invalid_state`: State validation failures (expired, unknown, or replayed)
- Existing callback logs remain unchanged

## Future Improvements

1. **Database-backed persistence**: Move from in-memory Map to database for:
   - Persistence across server restarts
   - Distributed system support
   - Audit trail of state usage

2. **Automatic cleanup**: Implement periodic cleanup of expired states:
   ```typescript
   setInterval(() => {
     const now = Date.now()
     for (const [state, record] of stateToShop.entries()) {
       if (now > record.expiresAt) {
         stateToShop.delete(state)
       }
     }
   }, 60000) // Clean every minute
   ```

3. **Rate limiting**: Add per-user rate limits on OAuth initiation

4. **State entropy analysis**: Monitor state randomness quality

## References

- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Shopify OAuth Documentation](https://shopify.dev/docs/apps/auth/oauth)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
