import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { nativeToScVal } from '@stellar/stellar-sdk';

vi.mock('../../../src/config/index.js', () => ({
  config: {
    soroban: {
      contractId: 'CCJZ5DGAD65NFU3QY6Q6X2R5Q3Y4Q4Z5DGAD65NFU3QY6Q6X2R5Q3Y4',
      rpcUrl: 'https://soroban-testnet.stellar.org',
      networkPassphrase: 'Test SDF Network ; September 2015',
    },
  },
}));

vi.mock('../../../src/db/client.js', () => ({
  pool: {
    connect: vi.fn(),
    end: vi.fn(),
  },
}));

vi.mock('../../../src/services/soroban/client.js', () => ({
  createSorobanRpcServer: vi.fn(),
}));

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

const SAMPLE_MERKLE_ROOT = '0x' + 'a'.repeat(64);
const SAMPLE_TX_HASH = '0x' + 'b'.repeat(64);
const CONTRACT_ID = 'CCJZ5DGAD65NFU3QY6Q6X2R5Q3Y4Q4Z5DGAD65NFU3QY6Q6X2R5Q3Y4';

function makeSymbolScVal(value: string) {
  return nativeToScVal(value, { type: 'symbol' });
}

function makeStringScVal(value: string) {
  return nativeToScVal(value, { type: 'string' });
}

function makeMapScVal(obj: Record<string, unknown>) {
  return nativeToScVal(obj);
}

function makeMockEvent(overrides: {
  business?: string;
  period?: string;
  merkleRoot?: string;
  txHash?: string;
  inSuccessfulContractCall?: boolean;
  ledger?: number;
} = {}) {
  const business = overrides.business ?? 'business-123';
  const period = overrides.period ?? '2026-01';
  const merkleRoot = overrides.merkleRoot ?? SAMPLE_MERKLE_ROOT;
  const txHash = overrides.txHash ?? SAMPLE_TX_HASH;

  return {
    id: `event-${business}-${period}`,
    type: 'contract' as const,
    ledger: overrides.ledger ?? 1000,
    ledgerClosedAt: new Date().toISOString(),
    transactionIndex: 0,
    operationIndex: 0,
    inSuccessfulContractCall: overrides.inSuccessfulContractCall ?? true,
    txHash,
    contractId: CONTRACT_ID,
    topic: [
      makeSymbolScVal('attestation_submitted'),
      makeStringScVal(business),
      makeStringScVal(period),
    ],
    value: makeMapScVal({ merkle_root: merkleRoot, timestamp: 1234567890 }),
  };
}

import {
  loadCheckpoint,
  saveCheckpoint,
  parseEventTopics,
  parseEventValue,
  parseEventFromResponse,
  buildAttestationId,
  shouldProcessEvent,
  fetchEvents,
  upsertAttestation,
  processEvents as processEventsFn,
  main,
} from '../../../scripts/rebuild-indexer.js';

describe('rebuild-indexer', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync('reindex-test-');
  });

  afterEach(() => {
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    vi.clearAllMocks();
  });

  // ─── loadCheckpoint ──────────────────────────────────────────────────────

  describe('loadCheckpoint', () => {
    it('returns null when file does not exist', () => {
      const result = loadCheckpoint('/nonexistent/path.json');
      expect(result).toBeNull();
    });

    it('returns null for corrupt JSON', () => {
      const fp = path.join(tempDir, 'corrupt.json');
      fs.writeFileSync(fp, '{invalid json}', 'utf-8');
      expect(loadCheckpoint(fp)).toBeNull();
    });

    it('returns parsed data for valid checkpoint', () => {
      const fp = path.join(tempDir, 'valid.json');
      const data = { cursor: 'abc-123', lastLedger: 500, processedCount: 42, updatedAt: new Date().toISOString() };
      fs.writeFileSync(fp, JSON.stringify(data), 'utf-8');
      const result = loadCheckpoint(fp);
      expect(result).not.toBeNull();
      expect(result!.cursor).toBe('abc-123');
      expect(result!.lastLedger).toBe(500);
      expect(result!.processedCount).toBe(42);
    });
  });

  // ─── saveCheckpoint ──────────────────────────────────────────────────────

  describe('saveCheckpoint', () => {
    it('writes checkpoint data to file', () => {
      const fp = path.join(tempDir, 'checkpoint.json');
      const data = { cursor: 'cur-1', lastLedger: 100, processedCount: 10, updatedAt: new Date().toISOString() };
      saveCheckpoint(fp, data);
      expect(fs.existsSync(fp)).toBe(true);
      const saved = JSON.parse(fs.readFileSync(fp, 'utf-8'));
      expect(saved.cursor).toBe('cur-1');
      expect(saved.lastLedger).toBe(100);
      expect(saved.processedCount).toBe(10);
    });

    it('creates parent directories if needed', () => {
      const fp = path.join(tempDir, 'nested', 'dir', 'cp.json');
      const data = { cursor: 'c', lastLedger: 1, processedCount: 0, updatedAt: new Date().toISOString() };
      saveCheckpoint(fp, data);
      expect(fs.existsSync(fp)).toBe(true);
    });
  });

  // ─── parseEventTopics ────────────────────────────────────────────────────

  describe('parseEventTopics', () => {
    it('parses valid topics array', () => {
      const topics = [
        makeSymbolScVal('attestation_submitted'),
        makeStringScVal('biz-001'),
        makeStringScVal('2026-Q1'),
      ];
      const result = parseEventTopics(topics);
      expect(result).not.toBeNull();
      expect(result!.business).toBe('biz-001');
      expect(result!.period).toBe('2026-Q1');
    });

    it('returns null for fewer than 3 topics', () => {
      expect(parseEventTopics([makeSymbolScVal('ev')])).toBeNull();
      expect(parseEventTopics([makeSymbolScVal('ev'), makeStringScVal('b')])).toBeNull();
    });

    it('returns null when first topic is not a symbol (non-string-convertible)', () => {
      const topics = [makeMapScVal({}), makeStringScVal('biz'), makeStringScVal('p')];
      const result = parseEventTopics(topics as any);
      expect(result).toBeNull();
    });

    it('returns null when business is empty string', () => {
      const topics = [
        makeSymbolScVal('ev'),
        makeStringScVal(''),
        makeStringScVal('2026-01'),
      ];
      expect(parseEventTopics(topics)).toBeNull();
    });

    it('returns null when period is empty string', () => {
      const topics = [
        makeSymbolScVal('ev'),
        makeStringScVal('biz-1'),
        makeStringScVal(''),
      ];
      expect(parseEventTopics(topics)).toBeNull();
    });

    it('returns null on ScVal conversion error', () => {
      const topics = [{} as any, {} as any, {} as any];
      expect(parseEventTopics(topics)).toBeNull();
    });
  });

  // ─── parseEventValue ─────────────────────────────────────────────────────

  describe('parseEventValue', () => {
    it('parses value with merkle_root and timestamp', () => {
      const value = makeMapScVal({ merkle_root: '0xabc', timestamp: 1234567890 });
      const result = parseEventValue(value);
      expect(result).not.toBeNull();
      expect(result!.merkleRoot).toBe('0xabc');
      expect(result!.timestamp).toBe(1234567890);
    });

    it('parses value with camelCase merkleRoot', () => {
      const value = makeMapScVal({ merkleRoot: '0xdef' });
      const result = parseEventValue(value);
      expect(result).not.toBeNull();
      expect(result!.merkleRoot).toBe('0xdef');
    });

    it('returns null when merkle_root is missing', () => {
      const value = makeMapScVal({ timestamp: 999 });
      expect(parseEventValue(value)).toBeNull();
    });

    it('returns null for non-map value (string)', () => {
      const value = makeStringScVal('hello');
      const result = parseEventValue(value);
      expect(result).toBeNull();
    });

    it('returns null on ScVal conversion error', () => {
      expect(parseEventValue({} as any)).toBeNull();
    });
  });

  // ─── parseEventFromResponse ──────────────────────────────────────────────

  describe('parseEventFromResponse', () => {
    it('parses a valid event response', () => {
      const event = makeMockEvent({ business: 'biz-x', period: '2026-02', merkleRoot: '0xabc' });
      const result = parseEventFromResponse(event as any);
      expect(result).not.toBeNull();
      expect(result!.business).toBe('biz-x');
      expect(result!.period).toBe('2026-02');
      expect(result!.merkleRoot).toBe('0xabc');
      expect(result!.txHash).toBe(SAMPLE_TX_HASH);
    });

    it('returns null when topics cannot be parsed', () => {
      const event = makeMockEvent();
      event.topic = [makeSymbolScVal('ev')];
      const result = parseEventFromResponse(event as any);
      expect(result).toBeNull();
    });

    it('returns null when value cannot be parsed', () => {
      const event = makeMockEvent();
      event.value = makeStringScVal('no-map');
      const result = parseEventFromResponse(event as any);
      expect(result).toBeNull();
    });
  });

  // ─── buildAttestationId ──────────────────────────────────────────────────

  describe('buildAttestationId', () => {
    it('returns colon-delimited composite key', () => {
      expect(buildAttestationId('biz-a', '2026-01')).toBe('biz-a:2026-01');
    });
  });

  // ─── shouldProcessEvent ──────────────────────────────────────────────────

  describe('shouldProcessEvent', () => {
    const parsed = { business: 'biz-1', period: '2026-01', merkleRoot: '0x', txHash: '0x' };

    it('returns true when no filter is set', () => {
      expect(shouldProcessEvent(parsed, undefined)).toBe(true);
    });

    it('returns true when business matches filter', () => {
      expect(shouldProcessEvent(parsed, 'biz-1')).toBe(true);
    });

    it('returns false when business does not match filter', () => {
      expect(shouldProcessEvent(parsed, 'other-biz')).toBe(false);
    });
  });

  // ─── fetchEvents ─────────────────────────────────────────────────────────

  describe('fetchEvents', () => {
    it('fetches events with startLedger when no cursor', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValue({
          events: [makeMockEvent()],
          cursor: 'cursor-1',
          latestLedger: 1500,
        }),
      };

      const result = await fetchEvents(mockServer as any, CONTRACT_ID, {
        startLedger: 100,
        batchSize: 50,
      });

      expect(mockServer.getEvents).toHaveBeenCalledWith({
        filters: [{ type: 'contract', contractIds: [CONTRACT_ID] }],
        startLedger: 100,
        limit: 50,
      });
      expect(result.events).toHaveLength(1);
      expect(result.cursor).toBe('cursor-1');
      expect(result.latestLedger).toBe(1500);
    });

    it('fetches events with cursor when provided', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValue({
          events: [],
          cursor: 'cursor-2',
          latestLedger: 2000,
        }),
      };

      const result = await fetchEvents(mockServer as any, CONTRACT_ID, {
        cursor: 'prev-cursor',
        batchSize: 100,
      });

      expect(mockServer.getEvents).toHaveBeenCalledWith({
        filters: [{ type: 'contract', contractIds: [CONTRACT_ID] }],
        cursor: 'prev-cursor',
        limit: 100,
      });
      expect(result.events).toHaveLength(0);
      expect(result.cursor).toBe('cursor-2');
    });

    it('defaults startLedger to 1 when not provided', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValue({
          events: [],
          cursor: '',
          latestLedger: 10,
        }),
      };

      await fetchEvents(mockServer as any, CONTRACT_ID, { batchSize: 10 });
      expect(mockServer.getEvents).toHaveBeenCalledWith(
        expect.objectContaining({ startLedger: 1 }),
      );
    });
  });

  // ─── upsertAttestation ───────────────────────────────────────────────────

  describe('upsertAttestation', () => {
    it('performs INSERT and returns created action', async () => {
      const mockClient = {
        query: vi.fn().mockResolvedValue({
          rows: [{ id: 'new-id', version: 1 }],
        }),
      };
      const parsed = { business: 'biz-1', period: '2026-01', merkleRoot: '0xabc', txHash: '0xdef' };
      const result = await upsertAttestation(mockClient, parsed);
      expect(result.action).toBe('created');
      expect(mockClient.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO attestations'),
        ['biz-1', '2026-01', '0xabc', '0xdef'],
      );
    });

    it('performs UPDATE and returns updated action', async () => {
      const mockClient = {
        query: vi.fn().mockResolvedValue({
          rows: [{ id: 'existing-id', version: 3 }],
        }),
      };
      const parsed = { business: 'biz-2', period: '2026-02', merkleRoot: '0xnew', txHash: '0xnew' };
      const result = await upsertAttestation(mockClient, parsed);
      expect(result.action).toBe('updated');
    });

    it('returns skipped when no rows returned', async () => {
      const mockClient = {
        query: vi.fn().mockResolvedValue({ rows: [] }),
      };
      const parsed = { business: 'biz-3', period: '2026-03', merkleRoot: '0xabc', txHash: '0xdef' };
      const result = await upsertAttestation(mockClient, parsed);
      expect(result.action).toBe('skipped');
    });
  });

  // ─── processEvents ───────────────────────────────────────────────────────

  describe('processEvents', () => {
    it('processes events and upserts unique attestations', async () => {
      const mockServer = {
        getEvents: vi.fn()
          .mockResolvedValueOnce({
            events: [
              makeMockEvent({ business: 'biz-a', period: '2026-01' }),
              makeMockEvent({ business: 'biz-b', period: '2026-01' }),
            ],
            cursor: 'page-1',
            latestLedger: 500,
          })
          .mockResolvedValueOnce({
            events: [],
            cursor: 'page-2',
            latestLedger: 501,
          }),
      };

      const mockDbClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
      };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 100 },
      );

      expect(stats.totalEvents).toBe(2);
      expect(stats.uniqueAttestations).toBe(2);
      expect(stats.created).toBe(2);
      expect(stats.updated).toBe(0);
      expect(stats.errors).toBe(0);
      expect(mockDbClient.query).toHaveBeenCalledTimes(2);
    });

    it('deduplicates same business+period from different events', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [
            makeMockEvent({ business: 'biz-a', period: '2026-01' }),
            makeMockEvent({ business: 'biz-a', period: '2026-01' }),
          ],
          cursor: 'end',
          latestLedger: 300,
        }),
      };

      const mockDbClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
      };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 100 },
      );

      expect(stats.totalEvents).toBe(2);
      expect(stats.uniqueAttestations).toBe(1);
      expect(stats.created).toBe(1);
      expect(mockDbClient.query).toHaveBeenCalledTimes(1);
    });

    it('filters events by businessId', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [
            makeMockEvent({ business: 'target-biz', period: '2026-01' }),
            makeMockEvent({ business: 'other-biz', period: '2026-01' }),
          ],
          cursor: 'end',
          latestLedger: 400,
        }),
      };

      const mockDbClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
      };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 100, businessId: 'target-biz' },
      );

      expect(stats.totalEvents).toBe(2);
      expect(stats.uniqueAttestations).toBe(1);
      expect(stats.skipped).toBe(1); // the non-matching one
      expect(mockDbClient.query).toHaveBeenCalledTimes(1);
    });

    it('skips events from unsuccessful contract calls', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [
            makeMockEvent({ business: 'biz-a', period: '2026-01', inSuccessfulContractCall: false }),
          ],
          cursor: 'end',
          latestLedger: 500,
        }),
      };

      const mockDbClient = { query: vi.fn() };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 100 },
      );

      expect(stats.totalEvents).toBe(1);
      expect(stats.uniqueAttestations).toBe(0);
      expect(mockDbClient.query).not.toHaveBeenCalled();
    });

    it('handles dry-run mode without writing to DB', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [makeMockEvent({ business: 'biz-dry', period: '2026-01' })],
          cursor: 'end',
          latestLedger: 600,
        }),
      };

      const mockDbClient = { query: vi.fn() };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: true, useCheckpoint: false, batchSize: 100 },
      );

      expect(stats.totalEvents).toBe(1);
      expect(stats.uniqueAttestations).toBe(1);
      expect(stats.created).toBe(1);
      expect(mockDbClient.query).not.toHaveBeenCalled();
    });

    it('handles fetch error gracefully', async () => {
      const mockServer = {
        getEvents: vi.fn().mockRejectedValue(new Error('RPC timeout')),
      };

      const mockDbClient = { query: vi.fn() };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 100 },
      );

      expect(stats.errors).toBe(1);
      expect(stats.totalEvents).toBe(0);
    });

    it('handles upsert error gracefully', async () => {
      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [makeMockEvent({ business: 'biz-err', period: '2026-01' })],
          cursor: 'end',
          latestLedger: 700,
        }),
      };

      const mockDbClient = {
        query: vi.fn().mockRejectedValue(new Error('DB deadlock')),
      };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 100 },
      );

      expect(stats.totalEvents).toBe(1);
      expect(stats.errors).toBe(1);
    });

    it('saves checkpoint periodically', async () => {
      const cpFile = path.join(tempDir, 'cp.json');
      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [makeMockEvent({ business: 'biz-cp', period: '2026-01' })],
          cursor: 'cp-cursor-1',
          latestLedger: 800,
        }),
      };

      const mockDbClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
      };

      await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: true, checkpointFile: cpFile, batchSize: 100 },
      );

      expect(fs.existsSync(cpFile)).toBe(true);
      const cp = JSON.parse(fs.readFileSync(cpFile, 'utf-8'));
      expect(cp.cursor).toBe('cp-cursor-1');
    });

    it('resumes from checkpoint when available', async () => {
      const cpFile = path.join(tempDir, 'resume-cp.json');
      fs.writeFileSync(cpFile, JSON.stringify({
        cursor: 'resume-cur',
        lastLedger: 900,
        processedCount: 50,
        updatedAt: new Date().toISOString(),
      }));

      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [],
          cursor: 'next-cur',
          latestLedger: 1000,
        }),
      };

      const mockDbClient = { query: vi.fn() };

      await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: true, checkpointFile: cpFile, batchSize: 100 },
      );

      expect(mockServer.getEvents).toHaveBeenCalledWith(
        expect.objectContaining({ cursor: 'resume-cur' }),
      );
    });

    it('starts from beginning when checkpoint has no cursor', async () => {
      const cpFile = path.join(tempDir, 'no-cursor-cp.json');
      fs.writeFileSync(cpFile, JSON.stringify({
        cursor: null,
        lastLedger: 500,
        processedCount: 100,
        updatedAt: new Date().toISOString(),
      }));

      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [makeMockEvent({ business: 'biz-fresh', period: '2026-01' })],
          cursor: 'new-cur',
          latestLedger: 600,
        }),
      };

      const mockDbClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
      };

      await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: true, checkpointFile: cpFile, batchSize: 100 },
      );

      expect(mockServer.getEvents).toHaveBeenCalledWith(
        expect.not.objectContaining({ cursor: expect.any(String) }),
      );
    });

    it('continues pagination when events fill a full page', async () => {
      const events = Array.from({ length: 2 }, (_, i) =>
        makeMockEvent({ business: `biz-page-${i}`, period: '2026-01' })
      );

      const mockServer = {
        getEvents: vi.fn()
          .mockResolvedValueOnce({
            events,
            cursor: 'page-1-cur',
            latestLedger: 300,
          })
          .mockResolvedValueOnce({
            events: [makeMockEvent({ business: 'biz-page-next', period: '2026-01' })],
            cursor: 'page-2-cur',
            latestLedger: 301,
          }),
      };

      const mockDbClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
      };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 2 },
      );

      expect(stats.totalEvents).toBe(3);
      expect(stats.uniqueAttestations).toBe(3);
      expect(mockDbClient.query).toHaveBeenCalledTimes(3);
      expect(mockServer.getEvents).toHaveBeenCalledTimes(2);
      expect(mockServer.getEvents).toHaveBeenNthCalledWith(2, expect.objectContaining({ cursor: 'page-1-cur' }));
    });

    it('handles event parse error gracefully without failing the page', async () => {
      const validEvent = makeMockEvent({ business: 'biz-ok', period: '2026-01' });
      const badEvent = makeMockEvent({ business: 'biz-bad', period: '2026-01' });
      badEvent.value = {} as any;

      const mockServer = {
        getEvents: vi.fn().mockResolvedValueOnce({
          events: [badEvent, validEvent],
          cursor: 'end',
          latestLedger: 400,
        }),
      };

      const mockDbClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
      };

      const stats = await processEventsFn(
        mockServer as any,
        mockDbClient,
        CONTRACT_ID,
        { dryRun: false, useCheckpoint: false, batchSize: 100 },
      );

      expect(stats.totalEvents).toBe(2);
      expect(stats.skipped).toBe(1);
      expect(stats.uniqueAttestations).toBe(1);
    });
  });

  // ─── main ────────────────────────────────────────────────────────────────

  describe('main', () => {
    it('throws when contractId is not configured', async () => {
      // Temporarily override config mock
      const configModule = await import('../../../src/config/index.js');
      const originalContractId = (configModule.config as any).soroban.contractId;
      (configModule.config as any).soroban.contractId = '';

      await expect(main({ dryRun: true, useCheckpoint: false })).rejects.toThrow(
        'SOROBAN_CONTRACT_ID is not configured',
      );

      (configModule.config as any).soroban.contractId = originalContractId;
    });

    it('creates soroban server and db client, processes events, and cleans up', async () => {
      const { pool: mockPool } = await import('../../../src/db/client.js');
      const { createSorobanRpcServer: mockCreateServer } = await import(
        '../../../src/services/soroban/client.js'
      );

      const mockQueryClient = {
        query: vi.fn().mockResolvedValue({ rows: [{ id: 'x', version: 1 }] }),
        release: vi.fn(),
      };

      vi.mocked(mockPool.connect).mockResolvedValue(mockQueryClient);

      const mockGetEvents = vi.fn().mockResolvedValueOnce({
        events: [makeMockEvent({ business: 'biz-main', period: '2026-01' })],
        cursor: 'end',
        latestLedger: 100,
      });

      vi.mocked(mockCreateServer).mockReturnValue({
        getEvents: mockGetEvents,
      } as any);

      const stats = await main({ dryRun: false, useCheckpoint: false, batchSize: 100 });

      expect(stats.totalEvents).toBe(1);
      expect(stats.created).toBe(1);
      expect(mockPool.connect).toHaveBeenCalled();
      expect(mockQueryClient.release).toHaveBeenCalled();
      expect(mockPool.end).toHaveBeenCalled();
    });
  });
});
