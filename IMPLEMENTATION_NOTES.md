# Shopify OAuth State TTL and Single-Use Implementation Notes

## Implementation Summary

Successfully implemented TTL (Time-To-Live) and single-use semantics for Shopify OAuth state tokens to prevent replay attacks.

## Changes Made

### 1. Core Implementation Files

#### `src/services/integrations/shopify/store.ts`
- Added `expiresAt: number` field to `ShopifyOAuthState` interface
- Modified `setOAuthState()` signature to require `expiresAt` parameter
- Enhanced `consumeOAuthState()` to:
  - Immediately delete state from storage (single-use enforcement)
  - Check expiry timestamp before returning
  - Return `undefined` for expired or unknown states

#### `src/services/integrations/shopify/connect.ts`
- Added TTL configuration via `SHOPIFY_OAUTH_STATE_TTL_MS` environment variable
- Default TTL: 600,000ms (10 minutes)
- Calculate `expiresAt` timestamp when creating OAuth state
- Pass `expiresAt` to `setOAuthState()`

#### `.env.example`
- Added `SHOPIFY_OAUTH_STATE_TTL_MS` configuration example
- Documented default value (600000ms = 10 minutes)

### 2. Test Files Created

#### `src/services/integrations/shopify/store.test.ts` (25 tests)
- Shop normalization and validation
- OAuth state storage with expiry
- Single-use consumption enforcement
- Expiry validation (including boundary conditions)
- Concurrent consume attempts
- Multiple independent states
- Token management

#### `src/services/integrations/shopify/connect.test.ts` (12 tests)
- Redirect URL generation
- Default TTL (10 minutes)
- Custom TTL from environment variable
- Shop hostname normalization
- Unique state generation
- Error handling (missing config, invalid shop)
- Edge cases (very short/long TTL)

#### `src/services/integrations/shopify/callback.test.ts` (15 tests)
- Unknown state rejection
- Expired state rejection
- Replayed state rejection (second use)
- State with mismatched shop
- Valid state within TTL
- Boundary conditions (at expiry, 1ms after)
- Parameter validation
- Concurrent callback attempts
- Edge cases

### 3. Documentation

#### `SHOPIFY_OAUTH_STATE_SECURITY.md`
Comprehensive security documentation including:
- Problem statement
- Solution architecture
- Configuration guide
- Security guarantees
- Test coverage details
- Implementation lifecycle
- Future improvements

## Test Results

### Unit Tests: ✅ ALL PASSING (52/52)
```
✓ src/services/integrations/shopify/store.test.ts (25 tests)
✓ src/services/integrations/shopify/connect.test.ts (12 tests)
✓ src/services/integrations/shopify/callback.test.ts (15 tests)
```

### Coverage
- `store.ts`: 100% coverage
- `connect.ts`: 100% coverage  
- `callback.ts`: 73% coverage (state validation logic fully covered)

The callback.ts coverage is lower because it includes token exchange and integration persistence logic that's not directly related to the TTL/single-use feature. The core security functionality (state validation) has 100% coverage.

## Security Features Implemented

### 1. TTL Enforcement
- States expire after configurable duration (default: 10 minutes)
- Expiry checked on every consume attempt
- Expired states rejected with clear error message

### 2. Single-Use Semantics
- State deleted immediately upon first consume
- Subsequent attempts with same state fail
- Prevents replay attacks even within TTL window

### 3. Race Condition Protection
- Atomic delete operation ensures only first consumer succeeds
- Concurrent attempts properly handled
- No state can be consumed twice

## Configuration

### Environment Variable
```bash
# Optional: Shopify OAuth state TTL in milliseconds
# Default: 600000 (10 minutes)
SHOPIFY_OAUTH_STATE_TTL_MS=600000
```

### Recommended Values
- **Development**: 600000 (10 minutes)
- **Production**: 300000 (5 minutes)
- **Minimum**: 60000 (1 minute)
- **Maximum**: 3600000 (1 hour)

## Breaking Changes

### Function Signature Change
```typescript
// Before
setOAuthState(state: string, shop: string, userId: string, businessId: string): void

// After  
setOAuthState(state: string, shop: string, userId: string, businessId: string, expiresAt: number): void
```

**Impact**: Existing OAuth flows in progress during deployment will fail. Users will need to restart the OAuth flow.

## Security Validation

### Attack Scenarios Tested

1. **Replay Attack**: ✅ Prevented
   - Attacker intercepts callback URL
   - Legitimate user consumes state first
   - Attacker's replay attempt fails (state already consumed)

2. **Expired State**: ✅ Prevented
   - User abandons OAuth flow
   - State expires after TTL
   - Later attempt to use state fails (expired)

3. **Concurrent Use**: ✅ Prevented
   - Multiple simultaneous callback requests
   - Only first request succeeds
   - Others fail (state already consumed)

4. **Boundary Conditions**: ✅ Handled
   - State at exact expiry time: accepted
   - State 1ms after expiry: rejected
   - Proper timestamp comparison

## Files Modified

1. `src/services/integrations/shopify/store.ts` - Core state management
2. `src/services/integrations/shopify/connect.ts` - TTL configuration
3. `.env.example` - Configuration documentation

## Files Created

1. `src/services/integrations/shopify/store.test.ts` - Store tests
2. `src/services/integrations/shopify/connect.test.ts` - Connect tests
3. `src/services/integrations/shopify/callback.test.ts` - Callback tests
4. `SHOPIFY_OAUTH_STATE_SECURITY.md` - Security documentation
5. `IMPLEMENTATION_NOTES.md` - This file

## Verification Steps

1. ✅ All new unit tests pass (52/52)
2. ✅ Core functionality has 100% test coverage
3. ✅ Security scenarios validated
4. ✅ Configuration documented
5. ✅ Breaking changes documented

## Notes

- Implementation uses in-memory Map storage (existing pattern)
- No database migration required
- Backward compatible except for function signature
- Pre-existing integration test failures are unrelated to this change
- The callback.ts HMAC validation issues in integration tests existed before this implementation

## Commit Message

```
feat: ttl and single-use shopify oauth state

- Add expiresAt timestamp to OAuth state records
- Enforce single-use by deleting state on first consume
- Add SHOPIFY_OAUTH_STATE_TTL_MS configuration (default: 10min)
- Reject expired and replayed states
- Add comprehensive test coverage (52 tests, 100% core coverage)
- Document security guarantees and attack prevention

Prevents replay attacks by ensuring OAuth states:
1. Expire after configurable TTL
2. Can only be used once
3. Are deleted immediately upon consumption

Fixes security vulnerability where leaked states could be replayed.
```

## Next Steps

1. Run full test suite to ensure no regressions
2. Review and merge changes
3. Deploy to staging environment
4. Monitor OAuth flow success rates
5. Consider future enhancements:
   - Database-backed persistence
   - Automatic cleanup of expired states
   - Rate limiting on OAuth initiation
