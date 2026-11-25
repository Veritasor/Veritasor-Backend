import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { GenericContainer, type StartedTestContainer } from 'testcontainers';
import { execSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { getUpSql } from '../../src/db/migrate.js';
import {
  create,
  createWithConflictCheck,
  getById,
  list,
  updateStatus,
} from '../../src/repositories/attestationRepository.js';
import { ConflictError, ConflictErrorType } from '../../src/types/attestation.js';
import type { CreateAttestationInput } from '../../src/types/attestation.js';

vi.mock('../../src/services/soroban/getAttestation.js', () => ({
  getAttestation: vi.fn(),
}));

const POSTGRES_IMAGE = 'postgres:16-alpine';
const POSTGRES_USER = 'test';
const POSTGRES_PASSWORD = 'test';
const POSTGRES_DB = 'veritasor_test';
const ATTESTATION_MIGRATION = '20260225_001_create_attestations_table';

type DockerProbe = (
  command: string,
  options: { stdio: 'pipe'; timeout: number; encoding: 'utf-8' }
) => string;

function probeDocker(run: DockerProbe): boolean {
  try {
    run('docker info --format "{{.ServerVersion}}"', {
      stdio: 'pipe',
      timeout: 5_000,
      encoding: 'utf-8',
    });
    return true;
  } catch {
    return false;
  }
}

function selectSuite<T>(available: boolean, runSuite: T, skipSuite: T): T {
  return available ? runSuite : skipSuite;
}

const dockerAvailable = probeDocker((command, options) =>
  String(execSync(command, options))
);
const describePg = selectSuite(dockerAvailable, describe, describe.skip);

function makeInput(period: string, businessId = randomUUID()): CreateAttestationInput {
  return {
    businessId,
    period,
    merkleRoot: `0x${'a'.repeat(64)}`,
    txHash: `0x${'b'.repeat(64)}`,
    status: 'submitted',
  };
}

async function conflictFrom(promise: Promise<unknown>): Promise<ConflictError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ConflictError) return error;
    throw error;
  }
  throw new Error('Expected a ConflictError');
}

async function setCreatedAt(client: pg.Client, id: string, createdAt: Date): Promise<void> {
  await client.query('UPDATE attestations SET created_at = $1 WHERE id = $2', [createdAt, id]);
}

describe('attestationRepository Postgres suite guard', () => {
  it('selects the real-DB suite only when the Docker probe succeeds', () => {
    const responding: DockerProbe = () => '24.0.0';
    const unavailable: DockerProbe = () => {
      throw new Error('Docker daemon unavailable');
    };

    expect(probeDocker(responding)).toBe(true);
    expect(probeDocker(unavailable)).toBe(false);
    expect(selectSuite(true, 'run', 'skip')).toBe('run');
    expect(selectSuite(false, 'run', 'skip')).toBe('skip');
    expect(typeof dockerAvailable).toBe('boolean');
  });
});

describePg('attestationRepository (real Postgres)', () => {
  let container: StartedTestContainer;
  let databaseUrl: string;
  let client: pg.Client;

  beforeAll(async () => {
    container = await new GenericContainer(POSTGRES_IMAGE)
      .withEnvironment({
        POSTGRES_USER,
        POSTGRES_PASSWORD,
        POSTGRES_DB,
      })
      .withExposedPorts(5432)
      .withStartupTimeout(60_000)
      .start();

    const host = container.getHost();
    const port = container.getMappedPort(5432);
    databaseUrl = `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${host}:${port}/${POSTGRES_DB}`;

    client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    await client.query(await getUpSql(ATTESTATION_MIGRATION));
  }, 120_000);

  afterAll(async () => {
    if (client) await client.end();
    if (container) await container.stop();
  });

  beforeEach(async () => {
    await client.query('TRUNCATE TABLE attestations');
  });

  it('applies the attestation migration to the container', async () => {
    const result = await client.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns WHERE table_name = $1`,
      ['attestations']
    );

    expect(result.rows.map((row) => row.column_name)).toEqual(
      expect.arrayContaining([
        'id',
        'business_id',
        'period',
        'merkle_root',
        'tx_hash',
        'status',
        'version',
        'created_at',
        'updated_at',
      ])
    );
    expect(databaseUrl).toContain(`/${POSTGRES_DB}`);
  });

  it('create persists an attestation with version 1', async () => {
    const input = makeInput('2026-01');

    const created = await create(client, input);

    expect(created).toMatchObject({
      businessId: input.businessId,
      period: input.period,
      merkleRoot: input.merkleRoot,
      txHash: input.txHash,
      status: 'submitted',
      version: 1,
    });
    expect(created.createdAt).toBeInstanceOf(Date);
    expect(created.updatedAt).toBeInstanceOf(Date);

    const persisted = await getById(client, created.id);
    expect(persisted).toMatchObject({
      id: created.id,
      businessId: input.businessId,
      period: input.period,
      status: 'submitted',
      version: 1,
    });
  });

  it('create raises ConflictError for a duplicate business and period', async () => {
    const input = makeInput('2026-02');
    await create(client, input);

    const error = await conflictFrom(create(client, input));

    expect(error).toBeInstanceOf(ConflictError);
    expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
    expect(error.details).toMatchObject({
      businessId: input.businessId,
      period: input.period,
    });
  });

  it('list paginates attestations by creation time and reports the total', async () => {
    const businessId = randomUUID();
    const periods = ['2026-01', '2026-02', '2026-03'];

    for (const [index, period] of periods.entries()) {
      const created = await create(client, makeInput(period, businessId));
      await setCreatedAt(client, created.id, new Date(Date.UTC(2026, 0, 1 + index)));
    }

    const firstPage = await list(client, { businessId }, { limit: 2, offset: 0 });
    expect(firstPage.total).toBe(3);
    expect(firstPage.items.map((item) => item.period)).toEqual(['2026-03', '2026-02']);

    const secondPage = await list(client, { businessId }, { limit: 2, offset: 1 });
    expect(secondPage.total).toBe(3);
    expect(secondPage.items.map((item) => item.period)).toEqual(['2026-02', '2026-01']);

    const unfiltered = await list(client, {}, { limit: 2, offset: 0 });
    expect(unfiltered.total).toBe(3);
    expect(unfiltered.items).toHaveLength(2);
  });

  it('updateStatus increments the version when the expected version matches', async () => {
    const created = await create(client, makeInput('2026-04'));

    const updated = await updateStatus(client, created.id, 'confirmed', created.version);

    expect(updated).toMatchObject({
      id: created.id,
      status: 'confirmed',
      version: 2,
    });

    const persisted = await getById(client, created.id);
    expect(persisted).toMatchObject({ status: 'confirmed', version: 2 });
  });

  it('updateStatus raises ConflictError and leaves the row unchanged for a stale version', async () => {
    const created = await create(client, makeInput('2026-05'));
    await updateStatus(client, created.id, 'submitted', 1);

    const error = await conflictFrom(
      updateStatus(client, created.id, 'revoked', 1)
    );

    expect(error).toBeInstanceOf(ConflictError);
    expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
    expect(error.details).toMatchObject({
      id: created.id,
      expectedVersion: 1,
      currentVersion: 2,
    });

    const persisted = await getById(client, created.id);
    expect(persisted).toMatchObject({ status: 'submitted', version: 2 });
  });

  it('createWithConflictCheck creates a new attestation when no row exists', async () => {
    const input = makeInput('2026-06');

    const created = await createWithConflictCheck(client, input);

    expect(created).toMatchObject({
      businessId: input.businessId,
      period: input.period,
      version: 1,
    });
  });

  it('createWithConflictCheck raises ConflictError when a row already exists', async () => {
    const input = makeInput('2026-07');
    const existing = await create(client, input);

    const error = await conflictFrom(createWithConflictCheck(client, input));

    expect(error).toBeInstanceOf(ConflictError);
    expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
    expect(error.details).toMatchObject({
      businessId: input.businessId,
      period: input.period,
      existingId: existing.id,
    });
  });

  it('createWithConflictCheck returns the existing row when requested', async () => {
    const input = makeInput('2026-08');
    const existing = await create(client, input);

    const result = await createWithConflictCheck(client, input, {
      returnExistingOnConflict: true,
    });

    expect(result.id).toBe(existing.id);
    expect(result.version).toBe(existing.version);
  });
});
