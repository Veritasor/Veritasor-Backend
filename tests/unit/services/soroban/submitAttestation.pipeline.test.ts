/**
 * @file submitAttestation.pipeline.test.ts
 * @description Dedicated suite for the public contract of
 * `src/services/soroban/submitAttestation.ts`:
 *
 * - `SorobanSubmissionError` (error taxonomy: name, code, cause)
 * - `SubmitAttestationParams` / `SubmitAttestationResult` shapes
 * - `validateSendTransactionResponse` (INVALID_RESPONSE boundaries)
 * - `submitAttestation` primary state transitions
 *   (unsigned / confirmed / pending) and failure paths
 *   (MISSING_SIGNER, SIGNER_MISMATCH, SUBMIT_FAILED,
 *   SOROBAN_CIRCUIT_BREAKER_OPEN, SOROBAN_NETWORK_ERROR, DEDUPED)
 * - the degraded-mode queue (`enqueueQueuedAttestation` /
 *   `drainQueuedAttestations`)
 *
 * Companion to `submitAttestation.test.ts`, which covers the pure helpers
 * (`waitForConfirmation`, `validateConfirmedResult`, dedupe primitives).
 *
 * Isolation strategy (mirrors `getAttestation.test.ts`): the Soroban RPC
 * methods are stubbed on `rpc.Server.prototype`, which flows through the
 * retry/circuit-breaker Proxy built by `createSorobanRpcServer`, so
 * submissions never touch the network while the real Stellar SDK builds
 * and hashes genuine transactions. Redis is replaced by an in-memory
 * dedupe store via a module mock of `src/redis.js`.
 */

import { afterAll, afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { Account, Keypair, nativeToScVal, rpc, xdr } from '@stellar/stellar-sdk';

// NOTE: `@stellar/stellar-sdk` is deliberately NOT mocked here. Mocks of
// externalized (node_modules) modules can leak across test files sharing a
// vmForks worker; this suite instead stubs `rpc.Server.prototype`, which
// flows through the retry/circuit-breaker Proxy built by
// `createSorobanRpcServer`, so submissions never touch the network while
// the real Stellar SDK builds and hashes genuine transactions. Redis is
// replaced by an in-memory dedupe store via a module mock of `src/redis.js`.

vi.mock('../../../../src/utils/logger.js', () => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const redisMock = vi.hoisted(() => {
  const state = {
    map: new Map<string, string>(),
    failGet: false,
    failSet: false,
  };
  return {
    state,
    client: {
      async get(key: string): Promise<string | null> {
        if (state.failGet) throw new Error('ECONNREFUSED');
        return state.map.get(key) ?? null;
      },
      async set(key: string, value: string, _px: 'PX', _ms: number): Promise<unknown> {
        if (state.failSet) throw new Error('ECONNREFUSED');
        state.map.set(key, value);
        return 'OK';
      },
    },
  };
});

vi.mock('../../../../src/redis.js', () => ({
  getRedisClient: () => redisMock.client,
}));

// NOTE: `src/services/features/flags.js` is deliberately NOT mocked here.
// Module mocks (of local or externalized modules) can fail to bind when test
// files share a vmForks worker, and the real flag path is safe in tests:
// `getBooleanFlag` catches evaluation errors and falls back to the default.

import type {
  SubmitAttestationParams,
  SubmitAttestationResult,
} from '../../../../src/services/soroban/submitAttestation.js';
import {
  assertNotDuplicate,
  computeAttestationDedupeKey,
  drainQueuedAttestations,
  enqueueQueuedAttestation,
  markAsSubmitted,
  resetQueuedAttestationStore,
  SorobanSubmissionError,
  submitAttestation,
  validateSendTransactionResponse,
} from '../../../../src/services/soroban/submitAttestation.js';
import {
  CircuitBreakerState,
  SorobanCircuitBreakerError,
} from '../../../../src/services/soroban/client.js';
import { sorobanRetryBudget } from '../../../../src/services/soroban/retry-budget.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MERKLE_ROOT = 'a'.repeat(64);
const sourceKeypair = Keypair.random();
const otherKeypair = Keypair.random();

const makeParams = (overrides: Partial<SubmitAttestationParams> = {}): SubmitAttestationParams => ({
  business: 'biz-1',
  period: '2026-Q3',
  merkleRoot: MERKLE_ROOT,
  timestamp: 1_720_000_000n,
  version: 'v1',
  sourcePublicKey: sourceKeypair.publicKey(),
  signerSecret: sourceKeypair.secret(),
  ...overrides,
});

/** A confirmed getTransaction payload whose on-chain values match the fixture params. */
const makeSuccessTxInfo = () => ({
  status: 'SUCCESS',
  ledger: 1234,
  returnValue: nativeToScVal({ merkle_root: MERKLE_ROOT, timestamp: 1_720_000_000 }),
});

/** Full Redis key used by the dedupe layer: `attestation:dedupe:<sha256>`. */
const dedupeKey = (params: SubmitAttestationParams): string =>
  `attestation:dedupe:${computeAttestationDedupeKey(params)}`;

/**
 * Installs the default RPC spies on `rpc.Server.prototype`.
 *
 * - `getAccount` returns a real Account for the fixture public key.
 * - `prepareTransaction` is an identity (the caller hands it a fully built
 *   transaction whose hash the SDK computes for real).
 * - `sendTransaction` returns PENDING with the genuine tx hash.
 * - `getTransaction` returns a SUCCESS payload matching the fixture params.
 *
 * Individual tests re-stub via the returned spies. Non-retryable error
 * messages (`ContractError: …`) are used on failure paths so the retry
 * policy inside `createSorobanRpcServer` fails fast and deterministically.
 */
function installDefaultServerSpies(): Record<string, Mock> {
  const spies: Record<string, Mock> = {
    getAccount: vi.fn(async () => new Account(sourceKeypair.publicKey(), '100')),
    prepareTransaction: vi.fn(async (tx: unknown) => tx),
    sendTransaction: vi.fn(async (prepared: { hash(): Uint8Array }) => ({
      status: 'PENDING',
      hash: Buffer.from(prepared.hash()).toString('hex'),
    })),
    getTransaction: vi.fn(async () => makeSuccessTxInfo()),
  };
  for (const [method, impl] of Object.entries(spies)) {
    vi.spyOn(rpc.Server.prototype as Record<string, unknown>, method).mockImplementation(
      impl as never,
    );
  }
  return spies;
}

// ---------------------------------------------------------------------------
// Environment hygiene
// ---------------------------------------------------------------------------

const ORIGINAL_ENV = {
  REDIS_URL: process.env.REDIS_URL,
  SOROBAN_SOURCE_SECRET: process.env.SOROBAN_SOURCE_SECRET,
  SOROBAN_DEGRADED_QUEUE_ENABLED: process.env.SOROBAN_DEGRADED_QUEUE_ENABLED,
  SOROBAN_DEGRADED_QUEUE_MAX_ITEMS: process.env.SOROBAN_DEGRADED_QUEUE_MAX_ITEMS,
};

beforeEach(() => {
  // Force the dedupe layer through the mocked Redis module.
  process.env.REDIS_URL = ORIGINAL_ENV.REDIS_URL ?? 'redis://127.0.0.1:6379';
  delete process.env.SOROBAN_SOURCE_SECRET;
  delete process.env.SOROBAN_DEGRADED_QUEUE_ENABLED;
  delete process.env.SOROBAN_DEGRADED_QUEUE_MAX_ITEMS;

  redisMock.state.map.clear();
  redisMock.state.failGet = false;
  redisMock.state.failSet = false;
  resetQueuedAttestationStore();

  // Fresh prototype spies for every test; module-mock fns reset too.
  vi.restoreAllMocks();
  installDefaultServerSpies();
  // The retry budget is a process-wide singleton shared with client.test.ts;
  // reset it so retry behavior is deterministic regardless of file order.
  sorobanRetryBudget.reset();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

afterAll(() => {
  const restore = (key: keyof typeof ORIGINAL_ENV) => {
    if (ORIGINAL_ENV[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = ORIGINAL_ENV[key];
    }
  };
  restore('REDIS_URL');
  restore('SOROBAN_SOURCE_SECRET');
  restore('SOROBAN_DEGRADED_QUEUE_ENABLED');
  restore('SOROBAN_DEGRADED_QUEUE_MAX_ITEMS');
});

/** Re-stub a prototype spy for the current test. */
const stubServerMethod = (method: string, impl: (...args: never[]) => unknown): Mock => {
  const spy = vi.spyOn(rpc.Server.prototype as Record<string, unknown>, method);
  spy.mockImplementation(impl as never);
  return spy;
};

// ---------------------------------------------------------------------------
// SorobanSubmissionError
// ---------------------------------------------------------------------------

describe('SorobanSubmissionError', () => {
  it('is an Error carrying the expected name, message, and code', () => {
    const error = new SorobanSubmissionError('submission blew up', 'SUBMIT_FAILED');

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect(error.name).toBe('SorobanSubmissionError');
    expect(error.message).toBe('submission blew up');
    expect(error.code).toBe('SUBMIT_FAILED');
  });

  it('preserves the original cause when provided', () => {
    const cause = new Error('ECONNRESET');
    const error = new SorobanSubmissionError('wrapped', 'SOROBAN_NETWORK_ERROR', cause);

    expect(error.cause).toBe(cause);
  });

  it('preserves non-Error payload causes (objects and primitives)', () => {
    const payload = { expected: 'a', actual: 'b' };
    expect(new SorobanSubmissionError('m', 'RESULT_MISMATCH', payload).cause).toBe(payload);
    expect(new SorobanSubmissionError('m', 'X', 42).cause).toBe(42);
  });

  it('leaves cause undefined when omitted', () => {
    const error = new SorobanSubmissionError('m', 'VALIDATION_ERROR');
    expect(error.cause).toBeUndefined();
  });

  it('is distinguishable from plain Errors thrown by the transport', () => {
    const plain = new Error('plain');
    const typed = new SorobanSubmissionError('typed', 'SOROBAN_NETWORK_ERROR');

    expect(plain).not.toBeInstanceOf(SorobanSubmissionError);
    expect((plain as { code?: string }).code).toBeUndefined();
    expect(typed.code).toBe('SOROBAN_NETWORK_ERROR');
  });
});

// ---------------------------------------------------------------------------
// Public type contract: SubmitAttestationParams / SubmitAttestationResult
// ---------------------------------------------------------------------------

describe('SubmitAttestationParams / SubmitAttestationResult contract', () => {
  it('accepts the full documented SubmitAttestationParams shape', () => {
    const params: SubmitAttestationParams = {
      business: 'biz-1',
      period: '2026-Q3',
      merkleRoot: MERKLE_ROOT,
      timestamp: 1_720_000_000n,
      version: 'v1',
      sourcePublicKey: sourceKeypair.publicKey(),
      signerSecret: sourceKeypair.secret(),
      submit: true,
      userId: 'user-1',
    };

    expect(Object.keys(params).sort()).toEqual([
      'business',
      'merkleRoot',
      'period',
      'signerSecret',
      'sourcePublicKey',
      'submit',
      'timestamp',
      'userId',
      'version',
    ]);
  });

  it('accepts both number and bigint timestamps and treats them as equivalent', () => {
    const fromBigint = computeAttestationDedupeKey(makeParams({ timestamp: 1_720_000_000n }));
    const fromNumber = computeAttestationDedupeKey(makeParams({ timestamp: 1_720_000_000 }));

    expect(fromBigint).toBe(fromNumber);
  });

  it('keeps the signerSecret and submit fields optional', () => {
    const minimal: SubmitAttestationParams = {
      business: 'biz-1',
      period: '2026-Q3',
      merkleRoot: MERKLE_ROOT,
      timestamp: 5,
      version: 'v1',
      sourcePublicKey: sourceKeypair.publicKey(),
    };

    expect(minimal.signerSecret).toBeUndefined();
    expect(minimal.submit).toBeUndefined();
    expect(minimal.userId).toBeUndefined();
  });

  it('accepts every documented SubmitAttestationResult status', () => {
    const statuses: SubmitAttestationResult['status'][] = ['pending', 'confirmed', 'unsigned', 'queued'];

    for (const status of statuses) {
      const result: SubmitAttestationResult = { txHash: 'ab'.repeat(32), status };
      expect(result.status).toBe(status);
    }
  });

  it('keeps optional result fields optional', () => {
    const minimal: SubmitAttestationResult = { txHash: 'ab'.repeat(32), status: 'pending' };
    expect(Object.keys(minimal).sort()).toEqual(['status', 'txHash']);
  });
});

// ---------------------------------------------------------------------------
// validateSendTransactionResponse
// ---------------------------------------------------------------------------

const VALID_HASH = 'ab'.repeat(32);

describe('validateSendTransactionResponse', () => {
  it('accepts a well-formed PENDING response', () => {
    expect(() =>
      validateSendTransactionResponse({ status: 'PENDING', hash: VALID_HASH } as any),
    ).not.toThrow();
  });

  it.each(['DUPLICATE', 'ERROR', 'TRY_AGAIN_LATER'] as const)(
    'accepts the documented status %s when the hash is well-formed',
    (status) => {
      expect(() =>
        validateSendTransactionResponse({ status, hash: VALID_HASH } as any),
      ).not.toThrow();
    },
  );

  it.each([null, undefined, 'not-an-object', 42])(
    'throws INVALID_RESPONSE for a non-object response (%p)',
    (response) => {
      let error: unknown;
      try {
        validateSendTransactionResponse(response as any);
      } catch (e) {
        error = e;
      }
      expect(error).toBeInstanceOf(SorobanSubmissionError);
      expect((error as SorobanSubmissionError).code).toBe('INVALID_RESPONSE');
      expect((error as SorobanSubmissionError).message).toContain('invalid response object');
    },
  );

  it('throws INVALID_RESPONSE when the hash is not 64 lowercase hex chars', () => {
    const response = { status: 'PENDING', hash: 'deadbeef' };
    let error: unknown;
    try {
      validateSendTransactionResponse(response as any);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('INVALID_RESPONSE');
    expect((error as SorobanSubmissionError).message).toContain('deadbeef');
    expect((error as SorobanSubmissionError).cause).toBe(response);
  });

  it('rejects uppercase transaction hashes (deterministic canonical form)', () => {
    const response = { status: 'PENDING', hash: VALID_HASH.toUpperCase() };
    expect(() => validateSendTransactionResponse(response as any)).toThrow(SorobanSubmissionError);
  });

  it('throws INVALID_RESPONSE for an unexpected status value', () => {
    let error: unknown;
    try {
      validateSendTransactionResponse({ status: 'FOO', hash: VALID_HASH } as any);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('INVALID_RESPONSE');
    expect((error as SorobanSubmissionError).message).toContain('FOO');
    expect((error as SorobanSubmissionError).cause).toMatchObject({ status: 'FOO' });
  });

  it('throws INVALID_RESPONSE for a missing hash', () => {
    expect(() => validateSendTransactionResponse({ status: 'PENDING' } as any)).toThrow(
      /invalid transaction hash/,
    );
  });
});

// ---------------------------------------------------------------------------
// assertNotDuplicate / markAsSubmitted convenience wrappers
// ---------------------------------------------------------------------------

describe('assertNotDuplicate / markAsSubmitted', () => {
  it('resolves when the attestation has not been submitted (miss)', async () => {
    await expect(assertNotDuplicate(makeParams())).resolves.toBeUndefined();
  });

  it('throws DEDUPED when the attestation was already submitted (hit)', async () => {
    redisMock.state.map.set(dedupeKey(makeParams()), 'some-tx-hash');

    let error: unknown;
    try {
      await assertNotDuplicate(makeParams());
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('DEDUPED');
    expect((error as SorobanSubmissionError).message).toContain('biz-1');
    expect((error as SorobanSubmissionError).message).toContain('2026-Q3');
  });

  it('fails open when the dedupe store is unreachable', async () => {
    redisMock.state.failGet = true;
    await expect(assertNotDuplicate(makeParams())).resolves.toBeUndefined();
  });

  it('markAsSubmitted stores the tx hash under the deterministic dedupe key', async () => {
    const params = makeParams();
    await markAsSubmitted(params, 'tx-hash-1');

    expect(redisMock.state.map.get(dedupeKey(params))).toBe('tx-hash-1');
  });

  it('markAsSubmitted is best-effort: store failures do not throw', async () => {
    redisMock.state.failSet = true;
    await expect(markAsSubmitted(makeParams(), 'tx-hash-2')).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// submitAttestation — input validation and signer guard
// ---------------------------------------------------------------------------

describe('submitAttestation — validation and signer guard', () => {
  it('throws VALIDATION_ERROR for a malformed sourcePublicKey before any RPC call', async () => {
    const getAccount = vi.spyOn(rpc.Server.prototype as Record<string, unknown>, 'getAccount');

    await expect(
      submitAttestation(makeParams({ sourcePublicKey: 'GINVALID' })),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });

    expect(getAccount).not.toHaveBeenCalled();
  });

  it.each([
    ['NaN', Number.NaN],
    ['negative', -1],
    ['infinite', Number.POSITIVE_INFINITY],
  ] as const)('throws VALIDATION_ERROR for a %s timestamp', async (_label, timestamp) => {
    let error: unknown;
    try {
      await submitAttestation(makeParams({ timestamp: timestamp as number }));
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('VALIDATION_ERROR');
    expect((error as SorobanSubmissionError).message).toContain('timestamp');
  });

  it('throws MISSING_SIGNER when neither params.signerSecret nor SOROBAN_SOURCE_SECRET is set', async () => {
    const sendTransaction = vi.spyOn(rpc.Server.prototype as Record<string, unknown>, 'sendTransaction');
    const { signerSecret: _omitted, ...withoutSigner } = makeParams();

    let error: unknown;
    try {
      await submitAttestation(withoutSigner);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('MISSING_SIGNER');
    expect((error as SorobanSubmissionError).message).toContain('No signer secret');
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it('throws SIGNER_MISMATCH when the secret belongs to a different key', async () => {
    await expect(
      submitAttestation(makeParams({ signerSecret: otherKeypair.secret() })),
    ).rejects.toMatchObject({ code: 'SIGNER_MISMATCH' });
  });
});

// ---------------------------------------------------------------------------
// submitAttestation — submission pipeline failures
// ---------------------------------------------------------------------------

describe('submitAttestation — submission pipeline failures', () => {
  it('throws INVALID_RESPONSE when sendTransaction returns a malformed hash', async () => {
    stubServerMethod('sendTransaction', async () => ({ status: 'PENDING', hash: 'nothex' }));

    let error: unknown;
    try {
      await submitAttestation(makeParams());
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('INVALID_RESPONSE');
  });

  it('throws SUBMIT_FAILED when Soroban RPC rejects the transaction (ERROR)', async () => {
    stubServerMethod('sendTransaction', async () => ({ status: 'ERROR', hash: VALID_HASH }));

    let error: unknown;
    try {
      await submitAttestation(makeParams());
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('SUBMIT_FAILED');
    expect((error as SorobanSubmissionError).message).toContain('rejected the transaction');
  });

  it('throws SUBMIT_FAILED when Soroban RPC asks to retry later (TRY_AGAIN_LATER)', async () => {
    stubServerMethod('sendTransaction', async () => ({
      status: 'TRY_AGAIN_LATER',
      hash: VALID_HASH,
    }));

    await expect(submitAttestation(makeParams())).rejects.toMatchObject({
      code: 'SUBMIT_FAILED',
      message: expect.stringContaining('retry later'),
    });
  });

  it('wraps an OPEN circuit breaker as SOROBAN_CIRCUIT_BREAKER_OPEN with the breaker details', async () => {
    stubServerMethod('getAccount', async () => {
      throw new SorobanCircuitBreakerError('circuit open', CircuitBreakerState.OPEN, 'getAccount');
    });

    let error: unknown;
    try {
      await submitAttestation(makeParams());
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('SOROBAN_CIRCUIT_BREAKER_OPEN');
    expect((error as SorobanSubmissionError).message).toContain('open');
    expect((error as SorobanSubmissionError).message).toContain('getAccount');
    expect((error as SorobanSubmissionError).cause).toBeInstanceOf(SorobanCircuitBreakerError);
  });

  it('treats a HALF_OPEN breaker error as a regular network error (only OPEN short-circuits)', async () => {
    stubServerMethod('getAccount', async () => {
      throw new SorobanCircuitBreakerError(
        'half open',
        CircuitBreakerState.HALF_OPEN,
        'getAccount',
      );
    });

    await expect(submitAttestation(makeParams())).rejects.toMatchObject({
      code: 'SOROBAN_NETWORK_ERROR',
    });
  });

  it('wraps generic transport errors as SOROBAN_NETWORK_ERROR and preserves the cause', async () => {
    // Non-retryable message so the RPC retry policy fails fast (deterministic).
    const transportError = new Error('ContractError: simulated transport failure');
    stubServerMethod('getAccount', async () => {
      throw transportError;
    });

    let error: unknown;
    try {
      await submitAttestation(makeParams());
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('SOROBAN_NETWORK_ERROR');
    expect((error as SorobanSubmissionError).message).toContain('Failed to build or submit');
    expect((error as SorobanSubmissionError).cause).toBe(transportError);
  });
});

// ---------------------------------------------------------------------------
// submitAttestation — primary state transitions
// ---------------------------------------------------------------------------

describe('submitAttestation — primary state transitions', () => {
  describe('unsigned (submit: false)', () => {
    it('returns the prepared transaction without signing or sending', async () => {
      const sendTransaction = vi.spyOn(rpc.Server.prototype as Record<string, unknown>, 'sendTransaction');
      const getTransaction = vi.spyOn(rpc.Server.prototype as Record<string, unknown>, 'getTransaction');

      const result = await submitAttestation(makeParams({ submit: false }));

      expect(result.status).toBe('unsigned');
      expect(result.txHash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.unsignedXdr).toEqual(expect.any(String));
      expect(() =>
        xdr.TransactionEnvelope.fromXDR(result.unsignedXdr!, 'base64'),
      ).not.toThrow();
      expect(sendTransaction).not.toHaveBeenCalled();
      expect(getTransaction).not.toHaveBeenCalled();
    });

    it('bypasses the dedupe store even when the attestation is already marked', async () => {
      redisMock.state.map.set(dedupeKey(makeParams()), 'earlier-tx-hash');

      const result = await submitAttestation(makeParams({ submit: false }));

      expect(result.status).toBe('unsigned');
    });
  });

  describe('timestamp boundaries', () => {
    it('floors fractional number timestamps onto the same u64 slot', async () => {
      const floored = await submitAttestation(
        makeParams({ submit: false, timestamp: 1_720_000_000.9 }),
      );
      const exact = await submitAttestation(makeParams({ submit: false, timestamp: 1_720_000_000 }));

      expect(floored.txHash).toBe(exact.txHash);
    });

    it('produces a different transaction for a different timestamp', async () => {
      const a = await submitAttestation(makeParams({ submit: false, timestamp: 1_720_000_000 }));
      const b = await submitAttestation(makeParams({ submit: false, timestamp: 1_720_000_001 }));

      expect(a.txHash).not.toBe(b.txHash);
    });
  });

  describe('confirmed (happy path)', () => {
    it('returns the validated on-chain attestation values', async () => {
      const result = await submitAttestation(makeParams());

      expect(result).toEqual({
        txHash: expect.stringMatching(/^[0-9a-f]{64}$/),
        status: 'confirmed',
        ledger: 1234,
        resultMerkleRoot: MERKLE_ROOT,
        resultTimestamp: 1_720_000_000,
      });
    });

    it('marks the attestation as in-flight in the dedupe store after submission', async () => {
      const params = makeParams();
      const result = await submitAttestation(params);

      // Flush the fire-and-forget markAttestationSubmitted promise.
      await new Promise<void>((resolve) => setImmediate(resolve));

      expect(redisMock.state.map.get(dedupeKey(params))).toBe(result.txHash);
    });

    it('rejects an immediate resubmission of the same attestation with DEDUPED', async () => {
      const params = makeParams();
      const getAccount = vi.spyOn(rpc.Server.prototype as Record<string, unknown>, 'getAccount');

      await submitAttestation(params);
      await new Promise<void>((resolve) => setImmediate(resolve));

      let error: unknown;
      try {
        await submitAttestation(params);
      } catch (e) {
        error = e;
      }
      expect((error as SorobanSubmissionError).code).toBe('DEDUPED');
      // The dedupe check short-circuits before any RPC work.
      expect(getAccount).toHaveBeenCalledTimes(1); // from the first submission only
    });

    it('throws DEDUPED before any RPC call when the attestation was previously marked', async () => {
      const params = makeParams();
      redisMock.state.map.set(dedupeKey(params), 'earlier-tx-hash');
      const getAccount = vi.spyOn(rpc.Server.prototype as Record<string, unknown>, 'getAccount');

      await expect(submitAttestation(params)).rejects.toMatchObject({ code: 'DEDUPED' });
      expect(getAccount).not.toHaveBeenCalled();
    });
  });

  describe('feature-flag integration', () => {
    it('proceeds with submission when userId is present (flag evaluation must not block)', async () => {
      // Exercises the real flags module: without an OpenFeature provider the
      // flag resolves to its default and submission continues unchanged.
      const result = await submitAttestation(makeParams({ userId: 'user-1' }));

      expect(result.status).toBe('confirmed');
    });
  });

  describe('pending (confirmation timeout)', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    it('returns pending when the transaction is never confirmed within the polling window', async () => {
      stubServerMethod('getTransaction', async () => ({ status: 'NOT_FOUND' }));

      const promise = submitAttestation(makeParams());
      await vi.advanceTimersByTimeAsync(40_000);
      const result = await promise;

      expect(result).toEqual({
        txHash: expect.stringMatching(/^[0-9a-f]{64}$/),
        status: 'pending',
      });
      expect(result.ledger).toBeUndefined();
      expect(result.resultMerkleRoot).toBeUndefined();
    });

    it('propagates CONFIRMATION_FAILED when the transaction fails on-chain', async () => {
      stubServerMethod('getTransaction', async () => ({ status: 'FAILED' }));

      let error: unknown;
      try {
        await submitAttestation(makeParams());
      } catch (e) {
        error = e;
      }
      expect(error).toBeInstanceOf(SorobanSubmissionError);
      expect((error as SorobanSubmissionError).code).toBe('CONFIRMATION_FAILED');
    });

    it('propagates RESULT_MISMATCH when the on-chain merkle root differs from the submitted one', async () => {
      stubServerMethod('getTransaction', async () => ({
        status: 'SUCCESS',
        ledger: 1234,
        returnValue: nativeToScVal({ merkle_root: 'f'.repeat(64), timestamp: 1_720_000_000 }),
      }));

      let error: unknown;
      try {
        await submitAttestation(makeParams());
      } catch (e) {
        error = e;
      }
      expect(error).toBeInstanceOf(SorobanSubmissionError);
      expect((error as SorobanSubmissionError).code).toBe('RESULT_MISMATCH');
      expect((error as SorobanSubmissionError).cause).toMatchObject({
        expected: MERKLE_ROOT,
        actual: 'f'.repeat(64),
      });
    });
  });
});

// ---------------------------------------------------------------------------
// Degraded-mode queue
// ---------------------------------------------------------------------------

describe('degraded-mode queue', () => {
  beforeEach(() => {
    process.env.SOROBAN_DEGRADED_QUEUE_ENABLED = 'true';
  });

  afterEach(() => {
    resetQueuedAttestationStore();
  });

  it('refuses to enqueue when the degraded queue is disabled', () => {
    delete process.env.SOROBAN_DEGRADED_QUEUE_ENABLED;

    expect(enqueueQueuedAttestation(makeParams())).toEqual({
      queued: false,
      reason: 'disabled',
    });
  });

  it('rejects items whose business, period, or merkleRoot is blank', () => {
    const result = enqueueQueuedAttestation(makeParams({ business: '   ' }));

    expect(result).toEqual({ queued: false, reason: 'invalid' });
  });

  it('treats the same attestation enqueued twice as a duplicate', () => {
    const first = enqueueQueuedAttestation(makeParams());
    const second = enqueueQueuedAttestation(makeParams());

    expect(first.queued).toBe(true);
    expect(second).toEqual({ queued: false, reason: 'duplicate' });
  });

  it('rejects new items when the queue is full', () => {
    process.env.SOROBAN_DEGRADED_QUEUE_MAX_ITEMS = '1';

    expect(
      enqueueQueuedAttestation(makeParams({ business: 'a', merkleRoot: '1'.repeat(64) })).queued,
    ).toBe(true);
    expect(enqueueQueuedAttestation(makeParams({ business: 'b', merkleRoot: '2'.repeat(64) }))).toEqual({
      queued: false,
      reason: 'queue_full',
    });
  });

  it('normalizes fields and derives the idempotency key from the attestation params', () => {
    // Blank version is trimmed to an empty string: the '1.0.0' fallback only
    // applies when version is nullish, and the key is derived post-normalization.
    const result = enqueueQueuedAttestation(makeParams({ version: '  ' }));

    expect(result.queued).toBe(true);
    expect(result.item).toMatchObject({
      business: 'biz-1',
      period: '2026-Q3',
      merkleRoot: MERKLE_ROOT,
      version: '',
      attempts: 0,
      status: 'queued',
      idempotencyKey: computeAttestationDedupeKey({ ...makeParams(), version: '' }),
    });
  });

  it('returns no results when the queue is empty', async () => {
    await expect(drainQueuedAttestations()).resolves.toEqual([]);
  });

  it('drains a queued attestation to confirmation and removes it from the store', async () => {
    // Fixture merkleRoot so the confirmed on-chain result matches the submitted value.
    enqueueQueuedAttestation(makeParams());

    const results = await drainQueuedAttestations();

    expect(results).toHaveLength(1);
    expect(results[0].result).toMatchObject({ status: 'confirmed' });
    expect(results[0].error).toBeUndefined();

    // The store is empty afterwards.
    await expect(drainQueuedAttestations()).resolves.toEqual([]);
  });

  it('retains failed items with exponential backoff and failed status', async () => {
    // Non-retryable message so the RPC retry policy fails fast (deterministic).
    stubServerMethod('getAccount', async () => {
      throw new Error('ContractError: simulated transport failure');
    });
    enqueueQueuedAttestation(makeParams({ merkleRoot: '4'.repeat(64) }));

    const before = Date.now();
    const results = await drainQueuedAttestations();

    expect(results).toHaveLength(1);
    expect((results[0].error as SorobanSubmissionError).code).toBe('SOROBAN_NETWORK_ERROR');
    expect(results[0].item).toMatchObject({ attempts: 1, status: 'failed' });
    expect(results[0].item!.nextAttemptAt).toBeGreaterThanOrEqual(before + 5_000);

    // Not due yet — an immediate re-drain picks up nothing.
    await expect(drainQueuedAttestations()).resolves.toEqual([]);
  });

  it('drops items permanently when submission fails with VALIDATION_ERROR', async () => {
    enqueueQueuedAttestation(
      makeParams({ merkleRoot: '5'.repeat(64), sourcePublicKey: 'GINVALID' }),
    );

    const results = await drainQueuedAttestations();

    expect((results[0].error as SorobanSubmissionError).code).toBe('VALIDATION_ERROR');
    await expect(drainQueuedAttestations()).resolves.toEqual([]);
  });

  it('drops items permanently when submission fails with DEDUPED', async () => {
    const params = makeParams();
    redisMock.state.map.set(dedupeKey(params), 'earlier-tx-hash');
    enqueueQueuedAttestation(params);

    const results = await drainQueuedAttestations();

    expect((results[0].error as SorobanSubmissionError).code).toBe('DEDUPED');
    await expect(drainQueuedAttestations()).resolves.toEqual([]);
  });

  it('clamps the drain limit to at least one item', async () => {
    enqueueQueuedAttestation(makeParams({ business: 'a', merkleRoot: '7'.repeat(64) }));
    enqueueQueuedAttestation(makeParams({ business: 'b', merkleRoot: '8'.repeat(64) }));

    const results = await drainQueuedAttestations(0);

    expect(results).toHaveLength(1);
  });
});
