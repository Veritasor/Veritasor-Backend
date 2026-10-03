#!/usr/bin/env tsx
import { Command } from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scValToNative } from '@stellar/stellar-sdk';
import { rpc, xdr } from '@stellar/stellar-sdk';
import { config } from '../src/config/index.js';
import { pool } from '../src/db/client.js';
import { logger } from '../src/utils/logger.js';
import { createSorobanRpcServer } from '../src/services/soroban/client.js';

const __filename = fileURLToPath(import.meta.url);

export type AttestationStatus = 'pending' | 'submitted' | 'confirmed' | 'failed' | 'revoked';

export interface RebuildOptions {
  dryRun: boolean;
  fromLedger?: number;
  businessId?: string;
  checkpointFile?: string;
  useCheckpoint: boolean;
  batchSize: number;
}

export interface CheckpointData {
  cursor: string | null;
  lastLedger: number;
  processedCount: number;
  updatedAt: string;
}

export interface RebuildStats {
  totalEvents: number;
  uniqueAttestations: number;
  created: number;
  updated: number;
  skipped: number;
  errors: number;
}

export interface ParsedEvent {
  business: string;
  period: string;
  merkleRoot: string;
  txHash: string;
}

const DEFAULT_CHECKPOINT_FILE = '.rebuild-indexer-checkpoint.json';
const MAX_PAGE_SIZE = 100;
const PACKAGE_VERSION = '0.1.0';

export function loadCheckpoint(filePath: string): CheckpointData | null {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw) as CheckpointData;
    if (parsed && typeof parsed.cursor === 'string' && typeof parsed.lastLedger === 'number') {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

export function saveCheckpoint(filePath: string, data: CheckpointData): void {
  const dir = path.dirname(filePath);
  if (dir && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

export function parseEventTopics(topics: xdr.ScVal[]): { business: string; period: string } | null {
  try {
    if (topics.length < 3) return null;

    const eventName = scValToNative(topics[0]);
    if (typeof eventName !== 'string') return null;

    const business = scValToNative(topics[1]);
    const period = scValToNative(topics[2]);

    if (typeof business === 'string' && business.length > 0 &&
        typeof period === 'string' && period.length > 0) {
      return { business, period };
    }
    return null;
  } catch {
    return null;
  }
}

export function parseEventValue(value: xdr.ScVal): { merkleRoot: string; timestamp?: number } | null {
  try {
    const native = scValToNative(value) as Record<string, unknown>;
    if (!native || typeof native !== 'object') return null;

    const merkleRoot = typeof native.merkle_root === 'string'
      ? native.merkle_root
      : typeof native.merkleRoot === 'string'
        ? native.merkleRoot
        : null;

    if (!merkleRoot) return null;

    const timestamp = native.timestamp !== undefined
      ? Number(native.timestamp)
      : undefined;

    return { merkleRoot, timestamp };
  } catch {
    return null;
  }
}

export function parseEventFromResponse(event: rpc.Api.EventResponse): ParsedEvent | null {
  const topics = parseEventTopics(event.topic);
  if (!topics) return null;

  const value = parseEventValue(event.value);
  if (!value) return null;

  return {
    business: topics.business,
    period: topics.period,
    merkleRoot: value.merkleRoot,
    txHash: event.txHash,
  };
}

export function buildAttestationId(businessId: string, period: string): string {
  return `${businessId}:${period}`;
}

export async function fetchEvents(
  server: rpc.Server,
  contractId: string,
  options: {
    startLedger?: number;
    cursor?: string;
    batchSize: number;
  },
): Promise<{ events: rpc.Api.EventResponse[]; cursor: string; latestLedger: number }> {
  const { startLedger, cursor, batchSize } = options;

  const filters: rpc.Api.EventFilter[] = [
    {
      type: 'contract',
      contractIds: [contractId],
    },
  ];

  let request: rpc.Api.GetEventsRequest;

  if (cursor) {
    request = {
      filters,
      cursor,
      limit: batchSize,
    };
  } else {
    request = {
      filters,
      startLedger: startLedger ?? 1,
      limit: batchSize,
    };
  }

  const response = await server.getEvents(request);

  return {
    events: response.events,
    cursor: response.cursor,
    latestLedger: response.latestLedger,
  };
}

export function shouldProcessEvent(
  parsed: ParsedEvent,
  businessIdFilter?: string,
): boolean {
  if (businessIdFilter && parsed.business !== businessIdFilter) {
    return false;
  }
  return true;
}

export async function upsertAttestation(
  client: { query: (sql: string, params?: any[]) => Promise<{ rows: any[] }> },
  parsed: ParsedEvent,
): Promise<{ action: 'created' | 'updated' | 'skipped' }> {
  const sql = `
    INSERT INTO attestations (business_id, period, merkle_root, tx_hash, status, version)
    VALUES ($1, $2, $3, $4, 'confirmed', 1)
    ON CONFLICT (business_id, period) DO UPDATE SET
      merkle_root = EXCLUDED.merkle_root,
      tx_hash = EXCLUDED.tx_hash,
      status = 'confirmed',
      version = attestations.version + 1
    RETURNING id, version
  `;

  const result = await client.query(sql, [
    parsed.business,
    parsed.period,
    parsed.merkleRoot,
    parsed.txHash,
  ]);

  if (result.rows.length === 0) {
    return { action: 'skipped' };
  }

  const row = result.rows[0];
  return { action: row.version === 1 ? 'created' : 'updated' };
}

export async function processEvents(
  server: rpc.Server,
  dbClient: { query: (sql: string, params?: any[]) => Promise<{ rows: any[] }> },
  contractId: string,
  options: RebuildOptions,
): Promise<RebuildStats> {
  const stats: RebuildStats = {
    totalEvents: 0,
    uniqueAttestations: 0,
    created: 0,
    updated: 0,
    skipped: 0,
    errors: 0,
  };

  const seenAttestations = new Set<string>();

  let cursor: string | undefined;
  let startLedger: number | undefined = options.fromLedger;

  if (options.useCheckpoint && options.checkpointFile) {
    const cp = loadCheckpoint(options.checkpointFile);
    if (cp && cp.cursor) {
      cursor = cp.cursor;
      startLedger = undefined;
      logger.info({ cursor: cp.cursor, processedCount: cp.processedCount }, 'Resuming from checkpoint');
    } else if (cp) {
      logger.info({ lastLedger: cp.lastLedger }, 'Checkpoint found but no cursor, starting from beginning');
    }
  }

  let hasMore = true;
  let pageCount = 0;

  while (hasMore) {
    pageCount++;
    logger.info({ page: pageCount, cursor: cursor || 'start' }, 'Fetching events page');

    let fetchResult: { events: rpc.Api.EventResponse[]; cursor: string; latestLedger: number };

    try {
      fetchResult = await fetchEvents(server, contractId, {
        startLedger,
        cursor,
        batchSize: options.batchSize,
      });
    } catch (err) {
      logger.error({ err, page: pageCount }, 'Failed to fetch events page');
      stats.errors++;
      break;
    }

    const { events, cursor: newCursor, latestLedger } = fetchResult;

    if (events.length === 0) {
      logger.info({ latestLedger }, 'No more events to process');
      hasMore = false;
      break;
    }

    for (const event of events) {
      stats.totalEvents++;

      if (!event.inSuccessfulContractCall) {
        continue;
      }

      let parsed: ParsedEvent | null;
      try {
        parsed = parseEventFromResponse(event);
      } catch {
        stats.errors++;
        continue;
      }

      if (!parsed) {
        stats.skipped++;
        continue;
      }

      if (!shouldProcessEvent(parsed, options.businessId)) {
        stats.skipped++;
        continue;
      }

      const attestationId = buildAttestationId(parsed.business, parsed.period);

      if (seenAttestations.has(attestationId)) {
        stats.skipped++;
        continue;
      }
      seenAttestations.add(attestationId);
      stats.uniqueAttestations++;

      if (options.dryRun) {
        logger.info(
          { business: parsed.business, period: parsed.period, merkleRoot: parsed.merkleRoot, txHash: parsed.txHash },
          '[DRY-RUN] Would upsert attestation',
        );
        stats.created++;
      } else {
        try {
          const result = await upsertAttestation(dbClient, parsed);
          if (result.action === 'created') stats.created++;
          else if (result.action === 'updated') stats.updated++;
          else stats.skipped++;
        } catch (err) {
          logger.error(
            { err, business: parsed.business, period: parsed.period },
            'Failed to upsert attestation',
          );
          stats.errors++;
        }
      }
    }

    cursor = newCursor;

    if (options.useCheckpoint && options.checkpointFile) {
      saveCheckpoint(options.checkpointFile, {
        cursor,
        lastLedger: latestLedger,
        processedCount: stats.totalEvents,
        updatedAt: new Date().toISOString(),
      });
    }

    if (events.length < (options.batchSize)) {
      hasMore = false;
    }
  }

  if (options.useCheckpoint && options.checkpointFile && cursor) {
    saveCheckpoint(options.checkpointFile, {
      cursor,
      lastLedger: 0,
      processedCount: stats.totalEvents,
      updatedAt: new Date().toISOString(),
    });
  }

  return stats;
}

function printStats(stats: RebuildStats, dryRun: boolean): void {
  const prefix = dryRun ? '[DRY-RUN] ' : '';
  console.log('');
  console.log(`${prefix}Rebuild complete`);
  console.log(`${prefix}  Total events scanned:  ${stats.totalEvents}`);
  console.log(`${prefix}  Unique attestations:   ${stats.uniqueAttestations}`);
  console.log(`${prefix}  Created:               ${stats.created}`);
  console.log(`${prefix}  Updated:               ${stats.updated}`);
  console.log(`${prefix}  Skipped:               ${stats.skipped}`);
  console.log(`${prefix}  Errors:                ${stats.errors}`);
}

async function initDbClient() {
  const client = await pool.connect();
  return {
    query: async (sql: string, params?: any[]) => {
      return client.query(sql, params);
    },
    release: () => client.release(),
  };
}

async function initSorobanServer(): Promise<rpc.Server> {
  if (!config.soroban.rpcUrl) {
    throw new Error('SOROBAN_RPC_URL is not configured');
  }
  return createSorobanRpcServer(config.soroban.rpcUrl);
}

export async function main(options?: Partial<RebuildOptions>): Promise<RebuildStats> {
  const opts = {
    dryRun: false,
    useCheckpoint: true,
    batchSize: MAX_PAGE_SIZE,
    checkpointFile: DEFAULT_CHECKPOINT_FILE,
    ...options,
  } satisfies RebuildOptions;

  if (!config.soroban.contractId) {
    throw new Error('SOROBAN_CONTRACT_ID is not configured. Set it in your environment.');
  }

  const server = await initSorobanServer();
  const dbClient = await initDbClient();

  try {
    const stats = await processEvents(server, dbClient, config.soroban.contractId, opts);
    return stats;
  } finally {
    dbClient.release();
    await pool.end();
  }
}

if (process.argv[1] === __filename) {
  const program = new Command();

  program
    .name('rebuild-indexer')
    .description('Rebuild attestation indexer from Soroban chain events')
    .version(PACKAGE_VERSION)
    .option('--dry-run', 'Simulate without writing to database')
    .option('--from-ledger <ledger>', 'Start ledger sequence', (v) => {
      const n = parseInt(v, 10);
      if (isNaN(n) || n < 1) throw new Error('--from-ledger must be a positive integer');
      return n;
    })
    .option('--business-id <id>', 'Filter by specific business UUID')
    .option('--checkpoint-file <path>', 'Checkpoint file path', DEFAULT_CHECKPOINT_FILE)
    .option('--no-checkpoint', 'Disable checkpoint/resume')
    .option('--batch-size <size>', 'Events per page (max 100)', (v) => {
      const n = parseInt(v, 10);
      if (isNaN(n) || n < 1 || n > 100) throw new Error('--batch-size must be between 1 and 100');
      return n;
    }, MAX_PAGE_SIZE)
    .action(async (cliOpts) => {
      const options: RebuildOptions = {
        dryRun: cliOpts.dryRun ?? false,
        fromLedger: cliOpts.fromLedger,
        businessId: cliOpts.businessId,
        checkpointFile: cliOpts.checkpointFile,
        useCheckpoint: cliOpts.checkpoint ?? true,
        batchSize: cliOpts.batchSize ?? MAX_PAGE_SIZE,
      };

      try {
        const stats = await main(options);
        printStats(stats, options.dryRun);
        if (stats.errors > 0) {
          process.exit(1);
        }
      } catch (err) {
        console.error('Fatal error:', err instanceof Error ? err.message : err);
        process.exit(1);
      }
    });

  program.parseAsync(process.argv).catch((err) => {
    console.error('Fatal error:', err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
