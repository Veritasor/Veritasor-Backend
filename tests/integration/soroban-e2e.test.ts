import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/config/index.js', () => ({
  config: {
    soroban: {
      retryBudgetMaxRetries: 10,
    },
  },
}));

vi.mock('../../src/utils/secret-loader.js', () => ({}));

import {
  Keypair,
  Networks,
  StrKey,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-sdk';
import { createMockSorobanServer } from '../../ops/dev/mock-soroban/server.js';
import {
  submitAttestation,
  SorobanSubmissionError,
  type SubmitAttestationParams,
  type SubmitAttestationResult,
} from '../../src/services/soroban/submitAttestation.js';
import {
  CircuitBreakerState,
  getSorobanCircuitBreaker,
} from '../../src/services/soroban/client.js';
import {
  SorobanRetryBudgetExceededError,
  sorobanRetryBudget,
} from '../../src/services/soroban/retry-budget.js';
import { BatchingQueue } from '../../src/services/soroban/batchingQueue.js';
import { config } from '../../src/config/index.js';

const ORIGINAL_ENV = { ...process.env };
const VALID_CONTRACT_ID = StrKey.encodeContract(Buffer.alloc(32, 7));
const TX_HASH_RE = /^[0-9a-f]{64}$/;

/** Build a valid base64 LedgerEntryData XDR for an account so rpc.Server.getAccount succeeds. */
function buildAccountEntryXdr(publicKey: string, sequence = '100'): string {
  const accountId = Keypair.fromPublicKey(publicKey).xdrPublicKey();
  const entry = new xdr.AccountEntry({
    accountId,
    balance: xdr.Int64.fromString('100000000'),
    seqNum: xdr.SequenceNumber.fromString(sequence),
    numSubEntries: 0,
    inflationDest: null,
    flags: 0,
    homeDomain: '',
    thresholds: Buffer.from([1, 0, 0, 0]),
    signers: [],
    ext: new xdr.AccountEntryExt(0),
  });
  return xdr.LedgerEntryData.account(entry).toXDR('base64');
}

/** Build a valid base64 SorobanTransactionData XDR for simulateTransaction. */
function buildSimulationDataXdr(): string {
  const txData = new xdr.SorobanTransactionData({
    ext: new xdr.SorobanTransactionDataExt(0),
    resources: new xdr.SorobanResources({
      footprint: new xdr.LedgerFootprint({ readOnly: [], readWrite: [] }),
      instructions: 0,
      diskReadBytes: 0,
      writeBytes: 0,
    }),
    resourceFee: xdr.Int64.fromString('100'),
  });
  return txData.toXDR('base64');
}

/** Build a valid base64 TransactionMeta (v3) containing the contract returnValue ScVal. */
function buildResultMetaXdr(merkleRoot: string, timestamp: number): string {
  const returnVal = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('merkle_root'),
      val: xdr.ScVal.scvString(merkleRoot),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('timestamp'),
      val: nativeToScVal(BigInt(timestamp), { type: 'u64' }),
    }),
  ]);
  const sorobanMeta = new xdr.SorobanTransactionMeta({
    ext: new xdr.SorobanTransactionMetaExt(0),
    events: [],
    returnValue: returnVal,
    diagnosticEvents: [],
  });
  const metaV3 = new xdr.TransactionMetaV3({
    ext: new xdr.ExtensionPoint(0),
    txChangesBefore: [],
    operations: [],
    txChangesAfter: [],
    sorobanMeta,
  });
  return new xdr.TransactionMeta(3, metaV3).toXDR('base64');
}

/** Build a valid base64 TransactionResult XDR for getTransaction. */
function buildTransactionResultXdr(): string {
  return new xdr.TransactionResult({
    feeCharged: xdr.Int64.fromString('100'),
    result: xdr.TransactionResultResult.txSuccess([]),
    ext: new xdr.TransactionResultExt(0),
  }).toXDR('base64');
}

/** Build a mock Soroban server wired with valid XDR handlers for real @stellar/stellar-sdk calls. */
function createE2eMockServer(
  sourcePublicKey: string,
  getExpectedAttestation: () => { merkleRoot: string; timestamp: number },
) {
  const accountEntryXdr = buildAccountEntryXdr(sourcePublicKey);
  const simulationDataXdr = buildSimulationDataXdr();
  const transactionResultXdr = buildTransactionResultXdr();

  return createMockSorobanServer({
    confirmDelayMs: 0,
    handlers: {
      getLedgerEntries(
        params: { keys?: string[] },
        ctx: { nextSeq: number },
      ) {
        const key = params?.keys?.[0] ?? '';
        return {
          latestLedger: ctx.nextSeq,
          entries: [
            {
              key,
              xdr: accountEntryXdr,
              lastModifiedLedgerSeq: ctx.nextSeq,
            },
          ],
        };
      },
      simulateTransaction(
        _params: unknown,
        ctx: { nextSeq: number },
      ) {
        return {
          transactionData: simulationDataXdr,
          minResourceFee: '100',
          results: [{ auth: [], xdr: nativeToScVal(null).toXDR('base64') }],
          events: [],
          cost: { cpuInsns: '0', memBytes: '0' },
          latestLedger: ctx.nextSeq,
        };
      },
      getTransaction(
        params: { hash?: string },
        ctx: {
          nextSeq: number;
          txnStore: Map<string, { status: string; createdAt: number; resultXdr?: string | null; resultMetaXdr?: string | null; applicationOrder: number }>;
          defaultHandlers: { getTransaction: (p: { hash?: string }) => Record<string, unknown> };
        },
      ) {
        const hash = params?.hash;
        if (hash && ctx.txnStore.has(hash)) {
          const stored = ctx.txnStore.get(hash)!;
          if (!stored.resultXdr) {
            stored.resultXdr = transactionResultXdr;
          }
          if (!stored.resultMetaXdr) {
            const { merkleRoot, timestamp } = getExpectedAttestation();
            stored.resultMetaXdr = buildResultMetaXdr(merkleRoot, timestamp);
          }
        }
        return ctx.defaultHandlers.getTransaction(params);
      },
    },
  });
}

describe('Soroban E2E integration against mock-soroban server', () => {
  const signer = Keypair.random();
  let expectedAttestation = {
    merkleRoot: 'e2e_merkle_root_001',
    timestamp: 1_700_000_100,
  };

  let mockServer: ReturnType<typeof createMockSorobanServer>;
  let rpcUrl: string;
  let boundPort: number;

  const makeParams = (overrides: Partial<SubmitAttestationParams> = {}): SubmitAttestationParams => ({
    business: 'biz_e2e_1',
    period: '2026-01',
    merkleRoot: expectedAttestation.merkleRoot,
    timestamp: expectedAttestation.timestamp,
    version: '1.0.0',
    sourcePublicKey: signer.publicKey(),
    signerSecret: signer.secret(),
    submit: true,
    ...overrides,
  });

  beforeAll(async () => {
    mockServer = createE2eMockServer(signer.publicKey(), () => expectedAttestation);
    const started = await mockServer.listen(0, '127.0.0.1');
    rpcUrl = started.url;
    boundPort = started.port;
  });

  afterAll(async () => {
    await mockServer.close();
    expect(mockServer.server.listening).toBe(false);
    process.env = { ...ORIGINAL_ENV };
  });

  beforeEach(() => {
    vi.restoreAllMocks();
    sorobanRetryBudget.reset();
    mockServer.resetFailures();
    mockServer.resetRequestCounts();

    process.env.SOROBAN_RPC_URL = rpcUrl;
    process.env.SOROBAN_CONTRACT_ID = VALID_CONTRACT_ID;
    process.env.SOROBAN_NETWORK_PASSPHRASE = Networks.TESTNET;
    process.env.SOROBAN_RPC_TIMEOUT_MS = '2000';
    process.env.SOROBAN_RPC_MAX_RETRIES = '2';
    process.env.SOROBAN_BACKOFF_BASE_MS = '1';
    process.env.SOROBAN_BACKOFF_MAX_MS = '5';
    process.env.SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD = '5';
    process.env.SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS = '1000';
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('binds mock server to an ephemeral port and submits an attestation end-to-end', async () => {
    expect(boundPort).toBeGreaterThan(0);
    expect(process.env.SOROBAN_RPC_URL).toBe(`http://127.0.0.1:${boundPort}`);

    const result = await submitAttestation(makeParams());

    expect(result.status).toBe('confirmed');
    expect(result.txHash).toMatch(TX_HASH_RE);
    expect(result.resultMerkleRoot).toBe(expectedAttestation.merkleRoot);
    expect(result.resultTimestamp).toBe(expectedAttestation.timestamp);
    expect(mockServer.getRequestCount('getLedgerEntries')).toBe(1);
    expect(mockServer.getRequestCount('simulateTransaction')).toBe(1);
    expect(mockServer.getRequestCount('sendTransaction')).toBe(1);
    expect(mockServer.getRequestCount('getTransaction')).toBeGreaterThanOrEqual(1);
  });

  it('processes batched attestations through BatchingQueue against the real Soroban client', async () => {
    const queue = new BatchingQueue<SubmitAttestationParams>(
      {
        maxBatchSize: 2,
        maxLatencyMs: 500,
        backpressureThreshold: 4,
        flushCooldownMs: 1,
      },
      async (items) => {
        for (const item of items) {
          try {
            const res = await submitAttestation(item.payload);
            item.resolve(res);
          } catch (err) {
            item.reject(err);
          }
        }
      },
    );

    const p1 = queue.enqueue<SubmitAttestationResult>(makeParams({ period: '2026-01' }));
    const p2 = queue.enqueue<SubmitAttestationResult>(makeParams({ period: '2026-02' }));

    const [r1, r2] = await Promise.all([p1, p2]);
    await queue.waitForPendingFlush();

    expect(r1.status).toBe('confirmed');
    expect(r2.status).toBe('confirmed');
    expect(r1.txHash).toMatch(TX_HASH_RE);
    expect(r2.txHash).toMatch(TX_HASH_RE);
    expect(r1.txHash).not.toBe(r2.txHash);
    expect(queue.depth).toBe(0);
    expect(mockServer.getRequestCount('sendTransaction')).toBe(2);

    queue.reset();
  });

  it('retries transient RPC failures, tracks retry budget, and recovers on subsequent attempt', async () => {
    expect(sorobanRetryBudget.getRetryCount()).toBe(0);

    // Fail the first 2 sendTransaction RPC requests with HTTP 503; 3rd attempt should succeed.
    mockServer.failNext(2, {
      statusCode: 503,
      message: 'Service temporarily unavailable',
      methods: ['sendTransaction'],
    });

    const result = await submitAttestation(makeParams());

    expect(result.status).toBe('confirmed');
    expect(result.txHash).toMatch(TX_HASH_RE);
    expect(sorobanRetryBudget.getRetryCount()).toBe(2);
    expect(mockServer.getRequestCount('sendTransaction')).toBe(3);
  });

  it('fails fast with SorobanRetryBudgetExceededError when retry budget is exhausted', async () => {
    // Exhaust the global sliding-window retry budget before issuing a failing call.
    const budgetLimit = config.soroban.retryBudgetMaxRetries;
    for (let i = 0; i < budgetLimit; i++) {
      sorobanRetryBudget.recordRetry('sendTransaction');
    }
    expect(sorobanRetryBudget.getRetryCount()).toBe(budgetLimit);

    mockServer.failNext(1, {
      statusCode: 503,
      message: 'Service temporarily unavailable',
      methods: ['sendTransaction'],
    });

    let caught: unknown;
    try {
      await submitAttestation(makeParams());
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(SorobanSubmissionError);
    const submissionErr = caught as SorobanSubmissionError;
    expect(submissionErr.code).toBe('SOROBAN_NETWORK_ERROR');
    expect(submissionErr.cause).toBeInstanceOf(SorobanRetryBudgetExceededError);
  });

  it('opens circuit breaker after threshold failures, rejects immediately while open, and closes on recovery', async () => {
    // Use a dedicated ephemeral mock server so its URL gets a fresh CircuitBreaker with threshold=2.
    const breakerServer = createE2eMockServer(signer.publicKey(), () => expectedAttestation);
    const { url: breakerUrl } = await breakerServer.listen(0, '127.0.0.1');

    try {
      process.env.SOROBAN_RPC_URL = breakerUrl;
      process.env.SOROBAN_RPC_MAX_RETRIES = '0';
      process.env.SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD = '2';
      process.env.SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS = '1000';

      const breaker = getSorobanCircuitBreaker(breakerUrl, {
        circuitBreakerThreshold: 2,
        circuitBreakerResetMs: 1000,
      });
      expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED);

      // Trigger 2 consecutive failures to trip the circuit breaker to OPEN.
      breakerServer.failNext(2, { statusCode: 503, message: 'Service temporarily unavailable' });

      await expect(submitAttestation(makeParams())).rejects.toMatchObject({
        name: 'SorobanSubmissionError',
        code: 'SOROBAN_NETWORK_ERROR',
      });
      expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED);

      await expect(submitAttestation(makeParams())).rejects.toMatchObject({
        name: 'SorobanSubmissionError',
        code: 'SOROBAN_NETWORK_ERROR',
      });
      expect(breaker.getState()).toBe(CircuitBreakerState.OPEN);

      // While OPEN, submitAttestation must fail immediately without contacting the mock server.
      const requestsBeforeOpenCall = breakerServer.getRequestCount();
      await expect(submitAttestation(makeParams())).rejects.toMatchObject({
        name: 'SorobanSubmissionError',
        code: 'SOROBAN_CIRCUIT_BREAKER_OPEN',
      });
      expect(breakerServer.getRequestCount()).toBe(requestsBeforeOpenCall);

      // Advance clock past resetTimeoutMs (1000ms) without real wall-clock waiting.
      const futureNow = Date.now() + 1_500;
      vi.spyOn(Date, 'now').mockReturnValue(futureNow);

      // Next call probes HALF_OPEN against healthy mock and closes the circuit breaker.
      const recovered = await submitAttestation(makeParams());
      expect(recovered.status).toBe('confirmed');
      expect(recovered.txHash).toMatch(TX_HASH_RE);
      expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED);
    } finally {
      await breakerServer.close();
      expect(breakerServer.server.listening).toBe(false);
    }
  });
});
