# Implementation Plan: Stripe OAuth Integration

## Overview

This plan implements Stripe OAuth 2.0 integration following the three-layer architecture (routes, services, repository). The implementation includes state token management for CSRF protection, OAuth flow initiation, callback handling with token exchange, and comprehensive property-based testing for all 9 correctness properties.

## Tasks

- [x] 1. Set up project structure and state store service
  - Create directory structure: `src/services/integrations/stripe/`
  - Implement state store with in-memory Map for OAuth state token management
  - Implement `setOAuthState(state: string, expiresAt: number): void` function
  - Implement `consumeOAuthState(state: string): boolean` function with one-time use semantics
  - Add automatic cleanup mechanism for expired tokens (runs every 5 minutes)
  - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ]* 1.1 Write property test for state token entropy
  - **Property 1: State Token Entropy**
  - **Validates: Requirements 1.1**
  - Generate multiple state tokens and verify each is at least 16 bytes (128 bits)

- [ ]* 1.2 Write property test for state token storage with expiration
  - **Property 2: State Token Storage with Expiration**
  - **Validates: Requirements 1.2, 7.3**
  - Verify state tokens are stored with expiration timestamp in the future

- [ ]* 1.3 Write property test for state token one-time use
  - **Property 4: State Token One-Time Use**
  - **Validates: Requirements 2.2, 7.2**
  - Verify consumed tokens cannot be retrieved again

- [x]* 1.4 Write unit tests for state store
  - Test state token storage and retrieval
  - Test state token expiration
  - Test cleanup of expired tokens
  - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [x] 2. Implement OAuth connect service
  - Create `src/services/integrations/stripe/connect.ts`
  - Define `ConnectResult` interface with `redirectUrl` and `state` fields
  - Implement `startConnect(): ConnectResult` function
  - Generate cryptographically secure 32-byte state token using crypto.randomBytes()
  - Store state token with 10-minute expiration
  - Construct Stripe authorization URL with client_id, redirect_uri, state, scope, and response_type=code
  - Read configuration from environment variables (STRIPE_CLIENT_ID, STRIPE_REDIRECT_URI, STRIPE_SCOPES)
  - Use default scope "read_write" if STRIPE_SCOPES not configured
  - _Requirements: 1.1, 1.2, 1.3, 5.1, 5.3, 5.4_

- [ ]* 2.1 Write property test for authorization URL construction
  - **Property 3: Authorization URL Construction**
  - **Validates: Requirements 1.3**
  - Verify generated URLs contain all required parameters

- [ ]* 2.2 Write unit tests for connect service
  - Test state token generation and storage
  - Test authorization URL contains all required parameters
  - Test error handling when environment variables are missing
  - Test default scope value when STRIPE_SCOPES not configured
  - _Requirements: 1.1, 1.2, 1.3, 1.5, 5.4_

- [x] 3. Checkpoint - Verify state store and connect service
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement OAuth callback service
  - Create `src/services/integrations/stripe/callback.ts`
  - Define `CallbackParams` interface with `code` and `state` fields
  - Define `CallbackResult` interface with `success`, `stripeAccountId`, and `error` fields
  - Implement `handleCallback(params: CallbackParams, userId: string): Promise<CallbackResult>` function
  - Validate required parameters (code, state) are present
  - Consume state token from store and validate it exists and hasn't expired
  - Exchange authorization code for tokens via POST to https://connect.stripe.com/oauth/token
  - Include grant_type, code, client_id, and client_secret in token exchange request
  - Extract access_token, refresh_token, stripe_user_id, scope, and token_type from Stripe response
  - Create integration record via Integration_Repository with provider="stripe"
  - Handle errors: missing parameters, invalid state, token exchange failure, network errors, missing access token
  - Never log or expose access_token or refresh_token in errors or logs
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 3.1, 3.2, 3.3, 5.2, 6.1, 6.2, 6.3, 6.4, 6.5_

- [ ]* 4.1 Write property test for token exchange request format
  - **Property 5: Token Exchange Request Format**
  - **Validates: Requirements 2.4**
  - Verify token exchange requests contain all required fields

- [ ]* 4.2 Write property test for token response parsing
  - **Property 6: Token Response Parsing**
  - **Validates: Requirements 2.5, 2.6**
  - Verify all fields are correctly extracted from Stripe responses

- [ ]* 4.3 Write property test for integration record creation
  - **Property 7: Integration Record Creation**
  - **Validates: Requirements 2.7**
  - Verify integration records have correct provider, userId, externalId, and token structure

- [ ]* 4.4 Write property test for token storage structure
  - **Property 8: Token Storage Structure**
  - **Validates: Requirements 3.1**
  - Verify token field is a structured object with required fields

- [ ]* 4.5 Write property test for token confidentiality in errors
  - **Property 9: Token Confidentiality in Errors**
  - **Validates: Requirements 3.3**
  - Verify error responses never contain token values

- [ ]* 4.6 Write unit tests for callback service
  - Test successful token exchange with valid code and state
  - Test error when required parameters are missing
  - Test error when state token is invalid or expired
  - Test error when Stripe API returns error response
  - Test error when network request fails
  - Test error when response is missing access token
  - Test tokens are never logged or exposed in errors
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 3.2, 3.3, 6.1, 6.2, 6.3, 6.4_

- [x] 5. Checkpoint - Verify callback service
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement route handler
  - Create `src/routes/integrations-stripe.ts`
  - Export router instance using Express Router()
  - Export path constant set to "/integrations/stripe"
  - Implement POST /connect endpoint that calls startConnect() and returns 302 redirect
  - Implement GET /callback endpoint that calls handleCallback() and handles response
  - Extract query parameters (code, state) from callback request
  - Validate environment configuration in connect endpoint
  - Return HTTP 400 error if STRIPE_CLIENT_ID or STRIPE_REDIRECT_URI missing
  - Return HTTP 400 error for validation failures (missing parameters, invalid state)
  - Return HTTP 502 error for network failures
  - Redirect to STRIPE_SUCCESS_REDIRECT if configured, otherwise return JSON response
  - Add proper error handling with appropriate status codes
  - _Requirements: 1.4, 1.5, 2.1, 2.3, 2.8, 2.9, 2.10, 4.1, 4.2, 4.3, 4.4, 4.5, 5.5, 6.1, 6.2, 6.3, 6.4, 6.5_

- [ ]* 6.1 Write unit tests for route handler
  - Test POST /connect returns 302 redirect with valid configuration
  - Test POST /connect returns 400 when environment variables missing
  - Test GET /callback with valid parameters returns success
  - Test GET /callback with missing parameters returns 400
  - Test GET /callback with invalid state returns 400
  - Test GET /callback redirects to success URL when configured
  - Test GET /callback returns JSON when success URL not configured
  - Test error responses have appropriate status codes
  - _Requirements: 1.4, 1.5, 2.8, 2.9, 2.10, 4.3, 4.4, 6.3_

- [x] 7. Mount router in main application
  - Import integrationsStripeRouter in `src/index.ts`
  - Mount router at `/api/integrations/stripe` path
  - Verify endpoints are accessible at correct URLs
  - _Requirements: 4.5_

- [ ]* 7.1 Write integration tests for complete OAuth flow
  - Test full connect → callback flow with mocked Stripe API
  - Test integration record is created in repository
  - Test state token lifecycle (creation, consumption, expiration)
  - Test route mounting and URL paths
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.4, 2.5, 2.6, 2.7, 4.5_

- [x] 8. Final checkpoint - Verify complete implementation
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Property-based tests validate universal correctness properties across many generated inputs
- Unit tests validate specific examples and edge cases
- Integration tests verify the complete OAuth flow end-to-end
- All property-based tests should run minimum 100 iterations
- Mock external dependencies (Stripe API, environment variables, time) in tests
- Never log or expose access tokens or refresh tokens in any context
