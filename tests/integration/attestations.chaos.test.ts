import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { rpc, Keypair, scValToNative, Account } from '@stellar/stellar-sdk';
import fc from 'fast-check';
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

// A targeted flag to bypass the 2000ms ledger confirmation poll delay ONLY when confirmation timeout is actively tested.
// This prevents pg-pool (which has a matching default 2000ms connection timeout) from timing out.
let mockPollDelay = false;

describe('POST /api/attestations - Soroban chaos testing', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
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

    // Establish default success mocks for rpc.Server methods on the prototype
    vi.spyOn(rpc.Server.prototype, 'getAccount').mockResolvedValue(new Account(VALID_SOURCE_PUBLIC_KEY, '123'));
    vi.spyOn(rpc.Server.prototype, 'prepareTransaction').mockResolvedValue(mockPreparedTx as any);
    vi.spyOn(rpc.Server.prototype, 'sendTransaction').mockResolvedValue({ status: 'PENDING', hash: VALID_TX_HASH } as any);
    vi.spyOn(rpc.Server.prototype, 'getTransaction').mockResolvedValue({ status: 'SUCCESS', ledger: 100, returnValue: {} } as any);

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
    const prepareSpy = vi.spyOn(rpc.Server.prototype, 'prepareTransaction')
      .mockRejectedValueOnce(Object.assign(new Error('temporary socket error'), { code: 'ECONNRESET' }))
      .mockResolvedValueOnce(mockPreparedTx as any);

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-1')
      .send(VALID_SUBMIT);

    if (res.status !== 201) {
      console.log('DEBUG TEST 1 RES:', res.status, res.body);
    }

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
    expect(res.body.submission.status).toBe('confirmed');
    expect(prepareSpy).toHaveBeenCalledTimes(2);
  });

  it('Test 2: handles sendTransaction returning TRY_AGAIN_LATER twice, then PENDING', async () => {
    const sendSpy = vi.spyOn(rpc.Server.prototype, 'sendTransaction')
      .mockResolvedValueOnce({ status: 'TRY_AGAIN_LATER', hash: VALID_TX_HASH } as any)
      .mockResolvedValueOnce({ status: 'TRY_AGAIN_LATER', hash: VALID_TX_HASH } as any)
      .mockResolvedValueOnce({ status: 'PENDING', hash: VALID_TX_HASH } as any);

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-2')
      .send(VALID_SUBMIT);

    if (res.status !== 201) {
      console.log('DEBUG TEST 2 RES:', res.status, res.body);
    }

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
    expect(res.body.submission.status).toBe('confirmed');
    expect(sendSpy).toHaveBeenCalledTimes(3);
  });

  it('Test 3: handles sendTransaction returning TRY_AGAIN_LATER persistently (exhausted retries)', async () => {
    const sendSpy = vi.spyOn(rpc.Server.prototype, 'sendTransaction')
      .mockResolvedValue({ status: 'TRY_AGAIN_LATER', hash: VALID_TX_HASH } as any);

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-3')
      .send(VALID_SUBMIT);

    expect(res.status).toBe(502);
    expect(res.body.code).toBe('SUBMIT_FAILED');
    expect(sendSpy).toHaveBeenCalledTimes(3); // Initial + 2 retries
    assertSecurityInvariants(res);
  });

  it('Test 4: handles getTransaction returning FAILED (on-chain reversion)', async () => {
    vi.spyOn(rpc.Server.prototype, 'getTransaction').mockResolvedValue({
      status: 'FAILED',
    } as any);

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
    vi.spyOn(rpc.Server.prototype, 'getTransaction').mockResolvedValue({
      status: 'NOT_FOUND',
    } as any);

    const res = await request(app)
      .post('/api/attestations')
      .set(AUTH)
      .set('Idempotency-Key', 'chaos-reg-5')
      .send(VALID_SUBMIT);

    if (res.status !== 201) {
      console.log('DEBUG TEST 5 RES:', res.status, res.body);
    }

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
          faultStep: fc.constantFrom('none', 'simulate', 'send_try_again', 'send_network', 'confirm_failed', 'confirm_not_found', 'confirm_network'),
        }),
        async (chaos) => {
          // Reset spy state for each property run
          vi.restoreAllMocks();
          mockPollDelay = (chaos.faultStep === 'confirm_not_found');
          vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(BUSINESS as any);

          // Mock Attestation repository
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

          mockScValToNative.mockReturnValue({ merkle_root: 'abc123', timestamp: 1700000000 });

          // Establish immediate timeouts for confirmation (2000ms) only when testing confirmation timeout
          const originalSetTimeout = setTimeout;
          vi.spyOn(global, 'setTimeout').mockImplementation((cb: any, ms: any) => {
            if (ms === 2000 && mockPollDelay) {
              cb();
              return {} as any;
            }
            return originalSetTimeout(cb, ms);
          });

          // Configure default success path
          vi.spyOn(rpc.Server.prototype, 'getAccount').mockResolvedValue(new Account(VALID_SOURCE_PUBLIC_KEY, '123'));

          const prepareMock = vi.spyOn(rpc.Server.prototype, 'prepareTransaction')
            .mockResolvedValue(mockPreparedTx as any);

          const sendMock = vi.spyOn(rpc.Server.prototype, 'sendTransaction')
            .mockResolvedValue({ status: 'PENDING', hash: VALID_TX_HASH } as any);

          const confirmMock = vi.spyOn(rpc.Server.prototype, 'getTransaction')
            .mockResolvedValue({ status: 'SUCCESS', ledger: 100, returnValue: {} } as any);

          // Inject specific target fault type persistently
          if (chaos.faultStep === 'simulate') {
            prepareMock.mockRejectedValue(Object.assign(new Error('persistent socket error'), { code: 'ECONNRESET' }));
          } else if (chaos.faultStep === 'send_try_again') {
            sendMock.mockResolvedValue({ status: 'TRY_AGAIN_LATER', hash: VALID_TX_HASH } as any);
          } else if (chaos.faultStep === 'send_network') {
            sendMock.mockRejectedValue(Object.assign(new Error('persistent network error'), { code: 'ECONNRESET' }));
          } else if (chaos.faultStep === 'confirm_failed') {
            confirmMock.mockResolvedValue({ status: 'FAILED' } as any);
          } else if (chaos.faultStep === 'confirm_not_found') {
            confirmMock.mockResolvedValue({ status: 'NOT_FOUND' } as any);
          } else if (chaos.faultStep === 'confirm_network') {
            confirmMock.mockRejectedValue(Object.assign(new Error('network offline'), { code: 'ECONNRESET' }));
          }

          // Generate unique idempotency key for this run
          const key = `chaos-prop-${Math.random()}`;

          const res = await request(app)
            .post('/api/attestations')
            .set(AUTH)
            .set('Idempotency-Key', key)
            .send(VALID_SUBMIT);

          // Assert the output outcomes perfectly match our mapped truth table oracle
          if (chaos.faultStep === 'none') {
            expect(res.status).toBe(201);
            expect(res.body.status).toBe('success');
            expect(res.body.submission.status).toBe('confirmed');
          } else if (chaos.faultStep === 'simulate') {
            expect(res.status).toBe(502);
            expect(res.body.code).toBe('SOROBAN_NETWORK_ERROR');
            assertSecurityInvariants(res);
          } else if (chaos.faultStep === 'send_try_again') {
            expect(res.status).toBe(502);
            expect(res.body.code).toBe('SUBMIT_FAILED');
            assertSecurityInvariants(res);
          } else if (chaos.faultStep === 'send_network') {
            expect(res.status).toBe(502);
            expect(res.body.code).toBe('SOROBAN_NETWORK_ERROR');
            assertSecurityInvariants(res);
          } else if (chaos.faultStep === 'confirm_failed') {
            expect(res.status).toBe(502);
            expect(res.body.code).toBe('CONFIRMATION_FAILED');
            assertSecurityInvariants(res);
          } else if (chaos.faultStep === 'confirm_not_found') {
            expect(res.status).toBe(201);
            expect(res.body.status).toBe('success');
            expect(res.body.submission.status).toBe('pending');
          } else if (chaos.faultStep === 'confirm_network') {
            expect(res.status).toBe(502);
            expect(res.body.code).toBe('SOROBAN_NETWORK_ERROR');
            assertSecurityInvariants(res);
          }
        }
      ),
      { numRuns: 30 } // 30 runs is perfect for fast execution and high coverage in property tests
    );
  });
});
