import { describe, it, expect, beforeEach } from 'vitest'
import * as fc from 'fast-check'
import {
  setOAuthState,
  consumeOAuthState,
  upsertStripeIntegration,
  getStripeIntegration,
  clearStripeIntegrationStore,
  StripeStoreValidationError,
} from '../../../../../src/services/integrations/stripe/store'

/**
 * Property-Based Tests: Stripe OAuth State Store — Metadata Variants
 *
 * Tests cover all metadata shapes that state tokens may carry:
 * - Expiration timestamps (past, present, future)
 * - Token string variants (special chars, unicode, hex, uuid-like)
 * - Boundary values (min/max expiry windows)
 * - Concurrent-style sequential operations
 * - Idempotent storage behaviour
 *
 * Validates: Requirements 1.2, 2.2, 7.2, 7.3, 7.4
 */

describe('Stripe OAuth State Store - Property-Based Tests', () => {

  // ─── Property 1: Token identity preservation ────────────────────────────────
  describe('Property 1: Token Identity — any storable string round-trips correctly', () => {
    it('arbitrary valid state strings are stored and consumed successfully', () => {
      /**
       * For any string that could represent an OAuth state token,
       * storing it with a future expiry and immediately consuming it
       * SHALL return true.
       *
       * Validates: Requirement 1.2
       */
      fc.assert(
        fc.property(
          fc.oneof(
            fc.stringMatching(/^[0-9a-f]{16,64}$/),
            fc.uuid(),
            fc.string({ minLength: 16, maxLength: 64 }),
          ),
          fc.integer({ min: 1, max: 60 }),
          (state, minutesInFuture) => {
            const expiresAt = Date.now() + minutesInFuture * 60 * 1000
            setOAuthState(state, expiresAt)
            expect(consumeOAuthState(state)).toBe(true)
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  // ─── Property 2: State Token Storage with Expiration ────────────────────────
  describe('Property 2: State Token Storage with Expiration', () => {
    it('stores state tokens with expiration timestamp in the future', () => {
      /**
       * Feature: stripe-oauth-integration
       * Property 2: For any OAuth flow initiation, when a state token is generated,
       * it SHALL be stored with an expiration timestamp that is set to a future time
       * (at least 1 minute from creation).
       *
       * Validates: Requirements 1.2, 7.3
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 64 }),
          fc.integer({ min: 1, max: 60 }),
          (state, minutesInFuture) => {
            const now = Date.now()
            const expiresAt = now + minutesInFuture * 60 * 1000
            setOAuthState(state, expiresAt)
            expect(consumeOAuthState(state)).toBe(true)
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  // ─── Property 3: Boundary expiry metadata ───────────────────────────────────
  describe('Property 3: Boundary Expiry Metadata Variants', () => {
    it('token expiring exactly 1 ms in the future is valid', () => {
      /**
       * Edge: minimum positive expiry window.
       * Validates: Requirement 7.3
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 64 }),
          (state) => {
            const expiresAt = Date.now() + 1
            setOAuthState(state, expiresAt)
            expect(consumeOAuthState(state)).toBe(true)
          }
        ),
        { numRuns: 50 }
      )
    })

    it('token with maximum realistic expiry (24 h) is valid', () => {
      /**
       * Edge: upper bound expiry window (24 hours).
       * Validates: Requirement 7.3
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 64 }),
          (state) => {
            const expiresAt = Date.now() + 24 * 60 * 60 * 1000
            setOAuthState(state, expiresAt)
            expect(consumeOAuthState(state)).toBe(true)
          }
        ),
        { numRuns: 50 }
      )
    })

    it('token with expiry in the past is treated as expired', () => {
      /**
       * Boundary: expiry already passed — must return false.
       * Validates: Requirement 7.4
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 64 }),
          (state) => {
            const expiresAt = Date.now() - 1
            setOAuthState(state, expiresAt)
            expect(consumeOAuthState(state)).toBe(false)
          }
        ),
        { numRuns: 50 }
      )
    })
  })

  // ─── Property 4: State Token One-Time Use ───────────────────────────────────
  describe('Property 4: State Token One-Time Use', () => {
    it('consumed tokens cannot be retrieved again', () => {
      /**
       * Feature: stripe-oauth-integration
       * Property 4: After a token is consumed, attempting to consume it again
       * SHALL return false.
       *
       * Validates: Requirements 2.2, 7.2
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 64 }),
          fc.integer({ min: 1, max: 60 }),
          (state, minutesInFuture) => {
            const expiresAt = Date.now() + minutesInFuture * 60 * 1000
            setOAuthState(state, expiresAt)
            expect(consumeOAuthState(state)).toBe(true)
            expect(consumeOAuthState(state)).toBe(false)
          }
        ),
        { numRuns: 100 }
      )
    })

    it('expired tokens return false when consumed', () => {
      /**
       * Additional property: Expired tokens SHALL be treated as non-existent.
       *
       * Validates: Requirement 7.4
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 64 }),
          fc.integer({ min: 1, max: 60 }),
          (state, minutesInPast) => {
            const expiresAt = Date.now() - minutesInPast * 60 * 1000
            setOAuthState(state, expiresAt)
            expect(consumeOAuthState(state)).toBe(false)
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  // ─── Property 5: Idempotent storage (overwrite) ─────────────────────────────
  describe('Property 5: Idempotent Storage — overwriting a token updates expiry', () => {
    it('storing the same token twice uses the second expiry', () => {
      /**
       * If setOAuthState is called twice with the same state string,
       * the second call overwrites the first. The token must be consumable
       * using the second expiry window.
       *
       * Validates: Requirement 1.2 (store idempotency / last-write-wins)
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 64 }),
          fc.integer({ min: 1, max: 30 }),
          fc.integer({ min: 31, max: 60 }),
          (state, firstMinutes, secondMinutes) => {
            const now = Date.now()
            setOAuthState(state, now + firstMinutes * 60 * 1000)
            setOAuthState(state, now + secondMinutes * 60 * 1000)
            expect(consumeOAuthState(state)).toBe(true)
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  // ─── Property 6: Independent token isolation ────────────────────────────────
  describe('Property 6: Independent Token Isolation', () => {
    it('consuming one token does not affect other tokens', () => {
      /**
       * Two distinct tokens stored concurrently SHALL be independently
       * consumable. Consuming token A must not invalidate token B.
       *
       * Validates: Requirements 2.2, 7.2
       */
      fc.assert(
        fc.property(
          fc.string({ minLength: 16, maxLength: 32 }),
          fc.string({ minLength: 33, maxLength: 64 }),
          fc.integer({ min: 1, max: 60 }),
          (stateA, stateB, minutes) => {
            fc.pre(stateA !== stateB)
            const expiresAt = Date.now() + minutes * 60 * 1000
            setOAuthState(stateA, expiresAt)
            setOAuthState(stateB, expiresAt)
            expect(consumeOAuthState(stateA)).toBe(true)
            expect(consumeOAuthState(stateB)).toBe(true)
          }
        ),
        { numRuns: 100 }
      )
    })

    it('unconsumed tokens with different metadata variants remain independent', () => {
      /**
       * Multiple tokens with varying expiry metadata stored together
       * SHALL each be independently consumable exactly once.
       *
       * Validates: Requirements 1.2, 7.3
       */
      fc.assert(
        fc.property(
          fc.uniqueArray(
            fc.record({
              state: fc.string({ minLength: 16, maxLength: 40 }),
              minutes: fc.integer({ min: 1, max: 60 }),
            }),
            { minLength: 2, maxLength: 5, selector: r => r.state }
          ),
          (tokens) => {
            const now = Date.now()
            for (const { state, minutes } of tokens) {
              setOAuthState(state, now + minutes * 60 * 1000)
            }
            for (const { state } of tokens) {
              expect(consumeOAuthState(state)).toBe(true)
              expect(consumeOAuthState(state)).toBe(false)
            }
          }
        ),
        { numRuns: 50 }
      )
    })
  })
})


// ─── Arbitraries ─────────────────────────────────────────────────────────────

/**
 * Generates a realistic Stripe account ID: "acct_" + 16 lowercase hex chars.
 * Mirrors the shape Stripe returns as `stripe_user_id` in OAuth responses.
 */
const stripeUserIdArb = fc
  .stringMatching(/^[0-9a-f]{16}$/)
  .map((s) => `acct_${s}`)

/**
 * Generates a realistic Stripe access token with sk_test_ or sk_live_ prefix.
 */
const accessTokenArb = fc
  .tuple(
    fc.constantFrom('sk_test_', 'sk_live_'),
    fc.stringMatching(/^[0-9a-f]{24}$/),
  )
  .map(([prefix, suffix]) => `${prefix}${suffix}`)

/**
 * Generates a realistic internal business ID.
 */
const businessIdArb = fc
  .stringMatching(/^[0-9a-f]{8}$/)
  .map((s) => `biz_${s}`)

/**
 * Full integration input record (no timestamps — managed by the store).
 */
const integrationInputArb = fc.record({
  stripeUserId: stripeUserIdArb,
  accessToken: accessTokenArb,
  businessId: businessIdArb,
})

// ─── Property tests: upsertStripeIntegration / getStripeIntegration ──────────

describe('Stripe Integration Store — ID Mapping Properties', () => {
  beforeEach(() => {
    clearStripeIntegrationStore()
  })

  // ── Property 7: Round-trip identity ────────────────────────────────────────
  describe('Property 7: Round-trip identity — stored fields are returned unchanged', () => {
    it('getStripeIntegration returns the exact stripeUserId, accessToken, and businessId that were upserted', () => {
      /**
       * For any valid integration input, upserting and then retrieving by
       * stripeUserId SHALL return a record whose mapped fields are identical
       * to the input. The store must not mutate or drop any field.
       */
      fc.assert(
        fc.property(integrationInputArb, ({ stripeUserId, accessToken, businessId }) => {
          upsertStripeIntegration({ stripeUserId, accessToken, businessId })
          const retrieved = getStripeIntegration(stripeUserId)
          expect(retrieved).toBeDefined()
          expect(retrieved!.stripeUserId).toBe(stripeUserId)
          expect(retrieved!.accessToken).toBe(accessToken)
          expect(retrieved!.businessId).toBe(businessId)
        }),
        { numRuns: 100 },
      )
    })
  })

  // ── Property 8: Timestamps are set on creation ──────────────────────────────
  describe('Property 8: Timestamps — createdAt and updatedAt are set on first upsert', () => {
    it('createdAt and updatedAt are numeric and equal on first insert', () => {
      /**
       * A freshly inserted record must have numeric timestamps within the
       * wall-clock window of the call. On first insert, createdAt === updatedAt.
       */
      fc.assert(
        fc.property(integrationInputArb, ({ stripeUserId, accessToken, businessId }) => {
          const before = Date.now()
          const result = upsertStripeIntegration({ stripeUserId, accessToken, businessId })
          const after = Date.now()
          expect(typeof result.createdAt).toBe('number')
          expect(typeof result.updatedAt).toBe('number')
          expect(result.createdAt).toBeGreaterThanOrEqual(before)
          expect(result.createdAt).toBeLessThanOrEqual(after)
          expect(result.createdAt).toBe(result.updatedAt)
        }),
        { numRuns: 100 },
      )
    })
  })

  // ── Property 9: Upsert preserves createdAt ──────────────────────────────────
  describe('Property 9: Upsert preserves createdAt on subsequent writes', () => {
    it('re-upserting with a new accessToken keeps the original createdAt', () => {
      /**
       * The store's idempotent upsert contract: createdAt is set once and
       * never overwritten. updatedAt must be >= the original updatedAt.
       */
      fc.assert(
        fc.property(
          integrationInputArb,
          accessTokenArb,
          ({ stripeUserId, accessToken, businessId }, newToken) => {
            const first = upsertStripeIntegration({ stripeUserId, accessToken, businessId })
            const second = upsertStripeIntegration({ stripeUserId, accessToken: newToken, businessId })
            expect(second.createdAt).toBe(first.createdAt)
            expect(second.updatedAt).toBeGreaterThanOrEqual(first.updatedAt)
            expect(second.accessToken).toBe(newToken)
          },
        ),
        { numRuns: 100 },
      )
    })
  })

  // ── Property 10: Key isolation ───────────────────────────────────────────────
  describe('Property 10: Key isolation — distinct Stripe IDs map to independent records', () => {
    it('upserting two different stripeUserIds does not cross-contaminate their records', () => {
      /**
       * Two integrations with different stripeUserIds must be stored and
       * retrieved independently. Writing one must not affect the other.
       */
      fc.assert(
        fc.property(
          integrationInputArb,
          integrationInputArb,
          (a, b) => {
            fc.pre(a.stripeUserId !== b.stripeUserId)
            upsertStripeIntegration(a)
            upsertStripeIntegration(b)
            const retrievedA = getStripeIntegration(a.stripeUserId)
            const retrievedB = getStripeIntegration(b.stripeUserId)
            expect(retrievedA!.businessId).toBe(a.businessId)
            expect(retrievedB!.businessId).toBe(b.businessId)
            expect(retrievedA!.accessToken).toBe(a.accessToken)
            expect(retrievedB!.accessToken).toBe(b.accessToken)
          },
        ),
        { numRuns: 100 },
      )
    })
  })

  // ── Property 11: Missing record returns undefined ────────────────────────────
  describe('Property 11: Missing record — unknown stripeUserId returns undefined', () => {
    it('getStripeIntegration returns undefined for a stripeUserId that was never upserted', () => {
      /**
       * The store must not fabricate records. Any ID that was never written
       * must return undefined, regardless of its shape.
       */
      fc.assert(
        fc.property(
          fc.stringMatching(/^[0-9a-f]{16}$/).map((s) => `acct_${s}_probe`),
          (unknownId) => {
            expect(getStripeIntegration(unknownId)).toBeUndefined()
          },
        ),
        { numRuns: 50 },
      )
    })
  })

  // ── Property 12: Large / boundary field values ───────────────────────────────
  describe('Property 12: Large and boundary field values are stored without truncation', () => {
    it('accessToken and businessId at maximum realistic lengths round-trip correctly', () => {
      /**
       * Edge case: very long tokens (e.g. from metadata blobs) must not be
       * silently truncated or rejected by the in-memory store.
       */
      fc.assert(
        fc.property(
          stripeUserIdArb,
          fc.stringMatching(/^[0-9a-f]{256}$/).map((s) => `sk_test_${s}`),
          fc.stringMatching(/^[0-9a-f]{64}$/).map((s) => `biz_${s}`),
          (stripeUserId, longToken, longBizId) => {
            upsertStripeIntegration({ stripeUserId, accessToken: longToken, businessId: longBizId })
            const retrieved = getStripeIntegration(stripeUserId)
            expect(retrieved!.accessToken).toBe(longToken)
            expect(retrieved!.businessId).toBe(longBizId)
          },
        ),
        { numRuns: 50 },
      )
    })
  })

  // -- Property 13: Validation rejects empty / non-string inputs ---------------
  describe('Property 13: Validation � invalid inputs throw StripeStoreValidationError', () => {
    it('upsertStripeIntegration throws on empty stripeUserId', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('', '   ', '\t', '\n'),
          accessTokenArb,
          businessIdArb,
          (badId, accessToken, businessId) => {
            expect(() =>
              upsertStripeIntegration({ stripeUserId: badId, accessToken, businessId }),
            ).toThrow(StripeStoreValidationError)
          },
        ),
        { numRuns: 20 },
      )
    })

    it('upsertStripeIntegration throws on empty accessToken', () => {
      fc.assert(
        fc.property(
          stripeUserIdArb,
          fc.constantFrom('', '   '),
          businessIdArb,
          (stripeUserId, badToken, businessId) => {
            expect(() =>
              upsertStripeIntegration({ stripeUserId, accessToken: badToken, businessId }),
            ).toThrow(StripeStoreValidationError)
          },
        ),
        { numRuns: 20 },
      )
    })

    it('upsertStripeIntegration throws on empty businessId', () => {
      fc.assert(
        fc.property(
          stripeUserIdArb,
          accessTokenArb,
          fc.constantFrom('', '   '),
          (stripeUserId, accessToken, badBizId) => {
            expect(() =>
              upsertStripeIntegration({ stripeUserId, accessToken, businessId: badBizId }),
            ).toThrow(StripeStoreValidationError)
          },
        ),
        { numRuns: 20 },
      )
    })

    it('setOAuthState throws on empty state string', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('', '   '),
          fc.integer({ min: 1, max: 60 }).map((m) => Date.now() + m * 60_000),
          (badState, expiresAt) => {
            expect(() => setOAuthState(badState, expiresAt)).toThrow(StripeStoreValidationError)
          },
        ),
        { numRuns: 20 },
      )
    })
  })
})
