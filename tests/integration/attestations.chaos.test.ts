import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { rpc, Keypair, scValToNative, Account } from '@stellar/stellar-sdk';
import * as fc from 'fast-check';
import { app } from '../../src/app.js';
import { businessRepository } from '../../src/repositories/business.js';
import * as attestationRepository from '../../src/repositories/attestationRepository.js';

// Setup Mock for scValToNative from @stellar/stellar-sdk to avoid raw XDR parsing
vi.mock('@stellar/stellar-sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@stellar/stellar-sdk')>();
  return {
    ...actual,
    scValToNative: vi.fn(),
  };
});

const mockScValToNative = vi.mocked(scValToNative);

// Generate matching keypair for testing
const kp = Keypair.random();
const VALID_SOURCE_PUBLIC_KEY = kp.publicKey();
const VALID_SOURCE_SECRET = kp.secret();

const AUTH = { 'x-user-id': 'user_1' };

const BUSINESS = {
  id: 'biz_1',
  userId: 'user_1',
  name: 'Acme Inc',
  email: 'owner@acme.example',
  industry: null,
  description: null,
  website: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
};

const VALID_SUBMIT = {
  period: '2026-01',
  merkleRoot: 'abc123',
};

// Canonical error taxonomy codes
const VALID_CODES = new Set([
  'VALIDATION_ERROR',
  'MISSING_SIGNER',
  'SIGNER_MISMATCH',
  'SUBMIT_FAILED',
  'SOROBAN_NETWORK_ERROR',
  'INVALID_RESPONSE',
  'CONFIRMATION_FAILED',
  'RESULT_VALIDATION_FAILED',
  'RESULT_MISMATCH',
]);

const ORIGINAL_ENV = { ...process.env };
const VALID_TX_HASH = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

// Mock prepared transaction matching all necessary method calls
const mockPreparedTx = {
  hash: () => Buffer.from(VALID_TX_HASH, 'hex'),
  toXDR: () => 'AAAA_fake_xdr',
  sign: () => {},
};

// Dynamic sequences and trackers for prototype method implementations
let activePrepareSequence: string[] = [];
let activeSendSequence: string[] = [];
let activeConfirmSequence: string[] = [];

let prepareIdx = 0;
let sendIdx = 0;
let confirmIdx = 0;

// A targeted flag to bypass the 2000ms ledger confirmation poll delay ONLY when confirmation timeout is actively tested.
// This prevents pg-pool (which has a matching default 2000ms connection timeout) from timing out.
let mockPollDelay = false;

// Compute expected response status and error codes using a deterministic oracle of Soroban execution rules
function computeExpectedOutcome(
  prepareSequence: string[],
  sendSequence: string[],
  confirmSequence: string[]
): { status: number; code?: string; submissionStatus?: string } {
  // 1. Simulate Phase (prepareTransaction)
  let prepareSuccess = false;
  for (let i = 0; i < 3; i++) {
    const outcome = prepareSequence[i] || 'success';
    if (outcome === 'success') {
      prepareSuccess = true;
      break;
    }
  }
  if (!prepareSuccess) {
    return { status: 502, code: 'SOROBAN_NETWORK_ERROR' };
  }

  // 2. Send Phase (sendTransaction)
  let sendSuccess = false;
  let lastSendError = '';
  for (let i = 0; i < 3; i++) {
    const outcome = sendSequence[i] || 'success';
    if (outcome === 'success') {
      sendSuccess = true;
      break;
    } else if (outcome === 'network_error') {
      lastSendError = 'SOROBAN_NETWORK_ERROR';
    } else if (outcome === 'try_again_later') {
      lastSendError = 'SUBMIT_FAILED';
    }
  }
  if (!sendSuccess) {
    return { status: 502, code: lastSendError };
  }

  // 3. Confirm Phase (getTransaction)
  let confirmStatus: 'confirmed' | 'pending' | null = null;
  for (let j = 0; j < 15; j++) {
    const outcome = confirmSequence[j] || 'success';
    if (outcome === 'network_error') {
      return { status: 502, code: 'SOROBAN_NETWORK_ERROR' };
    }
    if (outcome === 'failed') {
      return { status: 502, code: 'CONFIRMATION_FAILED' };
    }
    if (outcome === 'success') {
      confirmStatus = 'confirmed';
      break;
    }
  }
  if (confirmStatus === null) {
    // NOT_FOUND all 15 times = CONFIRMATION_TIMEOUT.
    // submitAttestation returns status: 'pending' (maps to HTTP 201).
    confirmStatus = 'pending';
  }
  return { status: 201, submissionStatus: confirmStatus };
}

describe('POST /api/attestations - Soroban chaos testing', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();

    activePrepareSequence = [];
    activeSendSequence = [];
    activeConfirmSequence = [];
    prepareIdx = 0;
    sendIdx = 0;
    confirmIdx = 0;
    mockPollDelay = false;

    process.env = { ...ORIGINAL_ENV };
    process.env.SOROBAN_SUBMIT_ENABLED = 'true';
    process.env.SOROBAN_SOURCE_PUBLIC_KEY = VALID_SOURCE_PUBLIC_KEY;
    process.env.SOROBAN_SOURCE_SECRET = VALID_SOURCE_SECRET;
    process.env.SOROBAN_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM';
    process.env.SOROBAN_RPC_TIMEOUT_MS = '5000'; // Generous timeout for test reliability
    process.env.SOROBAN_RPC_MAX_RETRIES = '2';
    process.env.SOROBAN_RPC_RETRY_BASE_DELAY_MS = '1';
    process.env.SOROBAN_RPC_RETRY_MAX_DELAY_MS = '1';
    process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '0';

    // Mock Business repository
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(BUSINESS as any);

    // Mock Attestation repository to avoid requiring a running PostgreSQL database
    vi.spyOn(attestationRepository, 'create').mockResolvedValue({
      id: 'att_created_mock',
      businessId: 'biz_1',
      period: '2026-01',
      merkleRoot: 'abc123',
      txHash: VALID_TX_HASH,
      status: 'submitted',
      version: 1,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    });

    vi.spyOn(attestationRepository, 'getById').mockResolvedValue({
      id: 'att_created_mock',
      businessId: 'biz_1',
      period: '2026-01',
      merkleRoot: 'abc123',
      txHash: VALID_TX_HASH,
      status: 'submitted',
      version: 1,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    });

    vi.spyOn(attestationRepository, 'updateStatus').mockResolvedValue({
      id: 'att_created_mock',
      businessId: 'biz_1',
      period: '2026-01',
      merkleRoot: 'abc123',
      txHash: VALID_TX_HASH,
      status: 'revoked',
      version: 2,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    });

    mockScValToNative.mockReturnValue({ merkle_root: 'abc123', timestamp: 1700000000 });

    // Establish dynamic mocks for rpc.Server methods on the prototype
    vi.spyOn(rpc.Server.prototype, 'getAccount').mockResolvedValue(new Account(VALID_SOURCE_PUBLIC_KEY, '123'));

    vi.spyOn(rpc.Server.prototype, 'prepareTransaction').mockImplementation(async () => {
      const outcome = activePrepareSequence[prepareIdx] || 'success';
      prepareIdx++;
      if (outcome === 'network_error') {
        throw Object.assign(new Error('persistent socket error'), { code: 'ECONNRESET' });
      }
      return mockPreparedTx as any;
    });

    vi.spyOn(rpc.Server.prototype, 'sendTransaction').mockImplementation(async () => {
      const outcome = activeSendSequence[sendIdx] || 'success';
      sendIdx++;
      if (outcome === 'network_error') {
        throw Object.assign(new Error('persistent network error'), { code: 'ECONNRESET' });
      }
      if (outcome === 'try_again_later') {
        return { status: 'TRY_AGAIN_LATER', hash: VALID_TX_HASH } as any;
      }
      return { status: 'PENDING', hash: VALID_TX_HASH } as any;
    });

    vi.spyOn(rpc.Server.prototype, 'getTransaction').mockImplementation(async () => {
      const outcome = activeConfirmSequence[confirmIdx] || 'success';
      confirmIdx++;
      if (outcome === 'network_error') {
        throw Object.assign(new Error('network offline'), { code: 'ECONNRESET' });
      }
      if (outcome === 'failed') {
        return { status: 'FAILED' } as any;
      }
      if (outcome === 'not_found') {
        return { status: 'NOT_FOUND' } as any;
      }
      return { status: 'SUCCESS', ledger: 100, returnValue: {} } as any;
    });

    // Bypass confirmation poll delays (2000ms) only when requested, preserving standard setTimeout for db pools & timeouts
    const originalSetTimeout = setTimeout;
    vi.spyOn(global, 'setTimeout').mockImplementation((cb: any, ms: any) => {
      if (ms === 2000 && mockPollDelay) {
        cb();
        return {} as any;
      }
      return originalSetTimeout(cb, ms);
    });
  });

  afterEach(() => {
    mockPollDelay = false;
    process.env = { ...ORIGINAL_ENV };
    vi.restoreAllMocks();
  });

  // Helper to assert security invariants on error responses
  function assertSecurityInvariants(res: any) {
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('localhost');
    expect(bodyStr).not.toContain('rpcUrl');
    expect(bodyStr).not.toContain('stack');
    expect(bodyStr).not.toContain('Error:');
    expect(bodyStr).not.toContain('privateKey');
    expect(bodyStr).not.toContain('secret');
    expect(VALID_CODES.has(res.body.code)).toBe(true);
  }

  // =========================================================================
  // LAYER 1: Explicit Regression Tests
  // =========================================================================

  it('Test 1: handles transient prepareTransaction (simulate) failure followed by success', async () => {
    activePrepareSequence = ['network_error', 'success'];

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-1')
      .send(VALID_SUBMIT);

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
    expect(res.body.submission.status).toBe('confirmed');
    expect(prepareIdx).toBe(2);
  });

  it('Test 2: handles sendTransaction returning TRY_AGAIN_LATER twice, then PENDING', async () => {
    activeSendSequence = ['try_again_later', 'try_again_later', 'success'];

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-2')
      .send(VALID_SUBMIT);

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
    expect(res.body.submission.status).toBe('confirmed');
    expect(sendIdx).toBe(3);
  });

  it('Test 3: handles sendTransaction returning TRY_AGAIN_LATER persistently (exhausted retries)', async () => {
    activeSendSequence = ['try_again_later', 'try_again_later', 'try_again_later'];

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-3')
      .send(VALID_SUBMIT);

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('SUBMIT_FAILED');
    expect(sendIdx).toBe(3); // Initial + 2 retries
    assertSecurityInvariants(res);
  });

  it('Test 4: handles getTransaction returning FAILED (on-chain reversion)', async () => {
    activeConfirmSequence = ['failed'];

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-4')
      .send(VALID_SUBMIT);

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('CONFIRMATION_FAILED');
    assertSecurityInvariants(res);
  });

  it('Test 5: handles getTransaction returning NOT_FOUND persistently (confirmation timeout)', async () => {
    mockPollDelay = true;
    activeConfirmSequence = Array(15).fill('not_found');

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-5')
      .send(VALID_SUBMIT);

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
    expect(res.body.submission.status).toBe('pending');
  });

  // =========================================================================
  // LAYER 2: Property-Based Chaos Tests
  // =========================================================================

  it('Property Test: robustly handles randomized sequences of RPC faults', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          prepareSequence: fc.array(fc.constantFrom('success', 'network_error'), { minLength: 1, maxLength: 3 }),
          sendSequence: fc.array(fc.constantFrom('success', 'try_again_later', 'network_error'), { minLength: 1, maxLength: 3 }),
          confirmSequence: fc.array(fc.constantFrom('success', 'failed', 'not_found', 'network_error'), { minLength: 1, maxLength: 15 }),
          idempotencyKey: fc.stringMatching(/^[0-9a-f]{16}$/),
        }),
        async (chaos) => {
          // Assign the active sequences and reset counters for this property iteration
          activePrepareSequence = chaos.prepareSequence;
          activeSendSequence = chaos.sendSequence;
          activeConfirmSequence = chaos.confirmSequence;
          prepareIdx = 0;
          sendIdx = 0;
          confirmIdx = 0;
          mockPollDelay = chaos.confirmSequence.includes('not_found');

          // Compute expected response shape using the deterministic Oracle
          const expected = computeExpectedOutcome(
            chaos.prepareSequence,
            chaos.sendSequence,
            chaos.confirmSequence
          );

          const res = await request(app)
            .post('/api/attestations')
            .set(AUTH)
            .set('Idempotency-Key', `chaos-prop-${chaos.idempotencyKey}`)
            .send(VALID_SUBMIT);

          // Assert the actual status matches the Oracle
          expect(res.status).toBe(expected.status);

          if (expected.status === 201) {
            expect(res.body.status).toBe('success');
            expect(res.body.submission.status).toBe(expected.submissionStatus);
          } else {
            expect(res.body.code).toBe(expected.code);
            assertSecurityInvariants(res);
          }
        }
      ),
      { numRuns: 30 } // 30 runs is perfect for fast execution and high coverage in property tests
    );
  });
});
