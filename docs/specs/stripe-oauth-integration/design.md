# Design Document: Stripe OAuth Integration

## Overview

This design specifies the implementation of Stripe OAuth 2.0 integration for the Veritasor backend. The feature enables users to securely connect their Stripe accounts through OAuth, allowing the application to access Stripe resources on their behalf. The implementation follows the established patterns from existing Shopify and Razorpay integrations.

The OAuth flow consists of two primary endpoints:
- **Connect endpoint** (`POST /api/integrations/stripe/connect`): Initiates the OAuth flow by generating a state token and redirecting to Stripe's authorization page
- **Callback endpoint** (`GET /api/integrations/stripe/callback`): Handles the OAuth callback, exchanges the authorization code for access tokens, and persists the integration

Key security considerations include CSRF protection via state tokens, secure token storage without logging, and proper validation of all OAuth parameters.

## Architecture

The implementation follows a three-layer architecture consistent with existing OAuth integrations:

```
┌─────────────────────────────────────────────────────────────┐
│                     HTTP Layer                               │
│  src/routes/integrations-stripe.ts                          │
│  - Route definitions and Express middleware                  │
│  - Request validation and response formatting                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Service Layer                              │
│  src/services/integrations/stripe/                          │
│  - connect.ts: OAuth flow initiation                        │
│  - callback.ts: OAuth callback handling                     │
│  - store.ts: State token management                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                 Data Access Layer                            │
│  src/repositories/integration.ts                            │
│  - Integration record persistence                           │
│  - Token storage (encrypted in production)                  │
└─────────────────────────────────────────────────────────────┘
```

The architecture separates concerns:
- **Routes**: Handle HTTP-specific concerns (request parsing, response formatting, status codes)
- **Services**: Implement business logic (OAuth flow, token exchange, validation)
- **Repository**: Manage data persistence (integration records, token storage)

This separation allows for independent testing of each layer and makes it easier to swap implementations (e.g., moving from in-memory to database storage).

## Components and Interfaces

### Route Handler (`src/routes/integrations-stripe.ts`)

The route handler exports an Express router with two endpoints:

```typescript
export const integrationsStripeRouter = Router()

// POST /api/integrations/stripe/connect
// Initiates OAuth flow, redirects to Stripe
integrationsStripeRouter.post('/connect', (req: Request, res: Response) => {
  // Validate environment configuration
  // Call startConnect() from service layer
  // Redirect to Stripe authorization URL
})

// GET /api/integrations/stripe/callback
// Handles OAuth callback from Stripe
integrationsStripeRouter.get('/callback', async (req: Request, res: Response) => {
  // Extract query parameters (code, state)
  // Call handleCallback() from service layer
  // Redirect to success URL or return JSON response
})
```

The router is mounted in `src/index.ts` at `/api/integrations/stripe`.

### Connect Service (`src/services/integrations/stripe/connect.ts`)

Responsible for initiating the OAuth flow:

```typescript
export interface ConnectResult {
  redirectUrl: string
  state: string
}

export function startConnect(): ConnectResult {
  // Generate cryptographically secure state token (32 bytes)
  // Store state token in state store with expiration
  // Construct Stripe authorization URL with parameters:
  //   - client_id (from STRIPE_CLIENT_ID)
  //   - redirect_uri (from STRIPE_REDIRECT_URI)
  //   - state (generated token)
  //   - scope (from STRIPE_SCOPES or default)
  //   - response_type=code
  // Return redirect URL and state
}
```

Environment variables:
- `STRIPE_CLIENT_ID`: OAuth client identifier
- `STRIPE_REDIRECT_URI`: Callback URL
- `STRIPE_SCOPES`: Requested permissions (default: "read_write")

### Callback Service (`src/services/integrations/stripe/callback.ts`)

Handles the OAuth callback and token exchange:

```typescript
export interface CallbackParams {
  code: string
  state: string
}

export interface CallbackResult {
  success: boolean
  stripeAccountId?: string
  error?: string
}

export async function handleCallback(params: CallbackParams): Promise<CallbackResult> {
  // Validate required parameters (code, state)
  // Consume state token from store (validates and removes)
  // If state invalid/expired, return error
  // Exchange authorization code for tokens via POST to Stripe token endpoint
  // Extract access_token, refresh_token, stripe_user_id from response
  // Create integration record via repository
  // Return success with Stripe account ID
}
```

Token exchange request to `https://connect.stripe.com/oauth/token`:
```typescript
{
  grant_type: 'authorization_code',
  code: '<authorization_code>',
  client_id: process.env.STRIPE_CLIENT_ID,
  client_secret: process.env.STRIPE_CLIENT_SECRET
}
```

Expected response:
```typescript
{
  access_token: string,
  refresh_token?: string,
  stripe_user_id: string,
  scope: string,
  token_type: 'bearer'
}
```

### State Store (`src/services/integrations/stripe/store.ts`)

Manages OAuth state tokens for CSRF protection:

```typescript
export function setOAuthState(state: string, expiresAt: number): void {
  // Store state token with expiration timestamp
}

export function consumeOAuthState(state: string): boolean {
  // Retrieve state token
  // Check if expired
  // Delete state token (one-time use)
  // Return true if valid, false otherwise
}
```

Implementation uses an in-memory Map with periodic cleanup:
- State tokens expire after 10 minutes
- Cleanup runs every 5 minutes to remove expired tokens
- Each state token can only be used once

### Integration Repository

Uses the existing `src/repositories/integration.ts` interface:

```typescript
await create({
  userId: string,           // From authenticated user context
  provider: 'stripe',       // Fixed value
  externalId: string,       // Stripe account ID (stripe_user_id)
  token: {
    accessToken: string,    // OAuth access token
    refreshToken?: string,  // Optional refresh token
    scope: string,          // Granted scopes
    tokenType: 'bearer'     // Token type
  },
  metadata: {}              // Empty for initial implementation
})
```

## Data Models

### Integration Record

```typescript
{
  id: string,                    // UUID generated by repository
  userId: string,                // User who owns this integration
  provider: 'stripe',            // Fixed value for Stripe integrations
  externalId: string,            // Stripe account ID (stripe_user_id)
  token: {
    accessToken: string,         // OAuth access token (never logged)
    refreshToken?: string,       // Optional refresh token (never logged)
    scope: string,               // Granted permissions
    tokenType: 'bearer'          // Token type
  },
  metadata: {},                  // Reserved for future use
  createdAt: string,             // ISO 8601 timestamp
  updatedAt: string              // ISO 8601 timestamp
}
```

### OAuth State Record (In-Memory)

```typescript
{
  state: string,                 // 32-byte hex-encoded random token
  expiresAt: number,             // Unix timestamp (milliseconds)
}
```

State tokens are stored in a Map and automatically cleaned up after expiration or consumption.


## Correctness Properties

A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.

### Property 1: State Token Entropy

For any generated OAuth state token, the token SHALL be at least 128 bits (16 bytes) in length to ensure cryptographic security against brute-force attacks.

**Validates: Requirements 1.1**

### Property 2: State Token Storage with Expiration

For any OAuth flow initiation, when a state token is generated, it SHALL be stored in the state store with an expiration timestamp that is set to a future time (at least 1 minute from creation).

**Validates: Requirements 1.2, 7.3**

### Property 3: Authorization URL Construction

For any OAuth flow initiation, the generated Stripe authorization URL SHALL contain all required parameters: client_id, redirect_uri, state, scope, and response_type=code.

**Validates: Requirements 1.3**

### Property 4: State Token One-Time Use

For any OAuth state token, after it is consumed during callback processing, attempting to retrieve the same state token SHALL return null or indicate the token does not exist.

**Validates: Requirements 2.2, 7.2**

### Property 5: Token Exchange Request Format

For any valid OAuth callback with authorization code and state, the token exchange request to Stripe SHALL include grant_type=authorization_code, the authorization code, client_id, and client_secret in the request body.

**Validates: Requirements 2.4**

### Property 6: Token Response Parsing

For any successful token exchange response from Stripe, the service SHALL correctly extract and store the access_token, refresh_token (if present), and stripe_user_id from the response.

**Validates: Requirements 2.5, 2.6**

### Property 7: Integration Record Creation

For any successful OAuth callback, the created integration record SHALL have provider set to "stripe", the correct userId, the Stripe account ID as externalId, and a token object containing at minimum the accessToken field.

**Validates: Requirements 2.7**

### Property 8: Token Storage Structure

For any stored integration, the token field SHALL be a structured object containing accessToken as a string, and optionally refreshToken, scope, and tokenType fields.

**Validates: Requirements 3.1**

### Property 9: Token Confidentiality in Errors

For any error response or error message generated during OAuth processing, the response body and message SHALL NOT contain the access_token or refresh_token values.

**Validates: Requirements 3.3**


## Error Handling

The implementation handles errors at multiple levels with appropriate HTTP status codes and user-friendly messages:

### Configuration Errors (HTTP 400)

When required environment variables are missing:
```typescript
{
  error: 'Missing STRIPE_CLIENT_ID or STRIPE_REDIRECT_URI'
}
```

Thrown during connect endpoint processing before redirecting to Stripe.

### Validation Errors (HTTP 400)

When callback parameters are missing or invalid:
```typescript
{
  error: 'Missing code, or state'
}
```

When state token is invalid or expired:
```typescript
{
  error: 'Invalid or expired state'
}
```

When Stripe response is missing access token:
```typescript
{
  error: 'No access token in response'
}
```

### Token Exchange Errors (HTTP 400)

When Stripe rejects the token exchange:
```typescript
{
  error: 'Token exchange failed'
}
```

This occurs when:
- Authorization code is invalid or expired
- Client credentials are incorrect
- Redirect URI doesn't match

### Network Errors (HTTP 502)

When the request to Stripe API fails due to network issues:
```typescript
{
  error: 'Failed to reach Stripe API'
}
```

This occurs when:
- DNS resolution fails
- Connection timeout
- Network unreachable

### Error Handling Principles

1. **Never log tokens**: Access tokens and refresh tokens are never included in log messages
2. **Never expose tokens**: Tokens are never included in error responses or messages
3. **Descriptive messages**: Error messages clearly indicate what went wrong without exposing sensitive data
4. **Appropriate status codes**: Use correct HTTP status codes (400 for client errors, 502 for upstream errors)
5. **Fail securely**: On any error during OAuth flow, reject the request rather than proceeding with partial data

### State Token Cleanup

The state store implements automatic cleanup of expired tokens:
- Cleanup runs every 5 minutes
- Removes all tokens where `expiresAt < Date.now()`
- Prevents memory leaks from abandoned OAuth flows

## Testing Strategy

The testing strategy employs both unit tests and property-based tests to ensure comprehensive coverage of the OAuth implementation.

### Unit Testing

Unit tests focus on specific examples, edge cases, and error conditions:

**Connect Service Tests**:
- Verify state token is generated and stored
- Verify authorization URL contains all required parameters
- Test error handling when environment variables are missing
- Test default scope value when STRIPE_SCOPES is not configured

**Callback Service Tests**:
- Test successful token exchange with valid code and state
- Test error when required parameters are missing
- Test error when state token is invalid
- Test error when state token has expired
- Test error when Stripe API returns error response
- Test error when network request fails
- Test error when response is missing access token
- Test successful redirect when STRIPE_SUCCESS_REDIRECT is configured
- Test JSON response when STRIPE_SUCCESS_REDIRECT is not configured

**State Store Tests**:
- Test state token storage and retrieval
- Test state token expiration
- Test state token consumption (one-time use)
- Test cleanup of expired tokens

**Route Handler Tests**:
- Test POST /connect returns 302 redirect
- Test GET /callback with valid parameters
- Test error responses with appropriate status codes

### Property-Based Testing

Property-based tests verify universal properties across many generated inputs using a PBT library (e.g., fast-check for TypeScript). Each test runs a minimum of 100 iterations.

**Property 1: State Token Entropy**
- Generate multiple state tokens
- Verify each is at least 16 bytes (128 bits)
- Tag: **Feature: stripe-oauth-integration, Property 1: For any generated OAuth state token, the token SHALL be at least 128 bits (16 bytes) in length**

**Property 2: State Token Storage with Expiration**
- Generate random timestamps
- Call connect function
- Verify state is stored with expiration > current time
- Tag: **Feature: stripe-oauth-integration, Property 2: For any OAuth flow initiation, when a state token is generated, it SHALL be stored with an expiration timestamp**

**Property 3: Authorization URL Construction**
- Generate random state tokens
- Call connect function
- Parse returned URL and verify all required parameters present
- Tag: **Feature: stripe-oauth-integration, Property 3: For any OAuth flow initiation, the generated URL SHALL contain all required parameters**

**Property 4: State Token One-Time Use**
- Generate random state tokens
- Store in state store
- Consume token
- Verify subsequent retrieval returns null
- Tag: **Feature: stripe-oauth-integration, Property 4: For any OAuth state token, after consumption, retrieval SHALL return null**

**Property 5: Token Exchange Request Format**
- Generate random authorization codes and states
- Mock Stripe API
- Call callback handler
- Verify request contains all required fields
- Tag: **Feature: stripe-oauth-integration, Property 5: For any valid callback, token exchange request SHALL include required fields**

**Property 6: Token Response Parsing**
- Generate random Stripe API responses with various token formats
- Call callback handler with mocked responses
- Verify all fields are correctly extracted
- Tag: **Feature: stripe-oauth-integration, Property 6: For any successful token response, all fields SHALL be correctly extracted**

**Property 7: Integration Record Creation**
- Generate random user IDs and Stripe responses
- Call callback handler
- Verify integration record has correct provider, userId, externalId, and token structure
- Tag: **Feature: stripe-oauth-integration, Property 7: For any successful callback, integration record SHALL have correct fields**

**Property 8: Token Storage Structure**
- Generate random token responses
- Create integration records
- Verify token field structure matches expected format
- Tag: **Feature: stripe-oauth-integration, Property 8: For any stored integration, token field SHALL be a structured object**

**Property 9: Token Confidentiality in Errors**
- Generate random error scenarios
- Capture error responses
- Verify responses do not contain access_token or refresh_token strings
- Tag: **Feature: stripe-oauth-integration, Property 9: For any error response, SHALL NOT contain token values**

### Integration Testing

Integration tests verify the complete OAuth flow:
- Test full connect → callback flow with mocked Stripe API
- Test integration record is created in repository
- Test state token lifecycle (creation, consumption, expiration)
- Test route mounting and URL paths

### Test Configuration

All property-based tests are configured with:
- Minimum 100 iterations per test
- Seed-based randomization for reproducibility
- Shrinking enabled to find minimal failing cases
- Timeout of 5 seconds per test

### Mocking Strategy

Tests mock external dependencies:
- **Stripe API**: Mock fetch() calls to Stripe endpoints
- **Environment variables**: Use test-specific configuration
- **Time**: Mock Date.now() for expiration testing
- **Crypto**: Use deterministic random for reproducible tests (in specific test cases only)

This dual testing approach ensures both concrete examples work correctly (unit tests) and universal properties hold across all inputs (property-based tests).
