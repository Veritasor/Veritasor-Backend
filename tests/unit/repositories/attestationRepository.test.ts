import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  create,
  getById,
  getByBusinessAndPeriod,
  list,
  updateStatus,
  update,
  createWithConflictCheck,
  remove,
} from '../../../src/repositories/attestationRepository.js';
import {
  ConflictError,
  ConflictErrorType,
  createConflictError,
  ReadConsistency,
} from '../../../src/types/attestation.js';
import type { CreateAttestationInput, DbClient } from '../../../src/types/attestation.js';
import { getAttestation } from '../../../src/services/soroban/getAttestation.js';

vi.mock('../../../src/services/soroban/getAttestation.js', () => ({
  getAttestation: vi.fn(),
}));

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

/**
 * Test Database Setup
 *
 * This test suite uses a MockDbClient for unit testing, which provides:
 * - Fast test execution without database overhead
 * - Automatic isolation between tests (each test gets a fresh mock)
 * - Simulation of database constraints (unique, foreign key)
 * - Predictable behaviour for testing edge cases
 * - Transaction rollback simulation via RollbackMockDbClient
 */

/**
 * Mock database client for unit testing.
 * Simulates PostgreSQL query responses with in-memory storage.
 */
class MockDbClient implements DbClient {
  private data: Map<string, any> = new Map();
  private idCounter = 0;
  private businesses: Map<string, any> = new Map();

  constructor() {
    this.seedBusinesses();
  }

  private seedBusinesses() {
    const seedBusinesses = [
      { id: 'business-123', user_id: 'user-1', name: 'Test Business 1' },
      { id: 'business-456', user_id: 'user-1', name: 'Test Business 2' },
      { id: 'business-789', user_id: 'user-2', name: 'Test Business 3' },
      { id: 'business-round-trip', user_id: 'user-3', name: 'Round Trip Business' },
      { id: 'business-conflict', user_id: 'user-4', name: 'Conflict Test Business' },
      { id: 'business-version', user_id: 'user-5', name: 'Version Test Business' },
      { id: 'business-rollback', user_id: 'user-6', name: 'Rollback Test Business' },
    ];
    seedBusinesses.forEach(b => this.businesses.set(b.id, b));
  }

  async query<T>(sql: string, params?: any[]): Promise<{ rows: T[] }> {
    const sqlUpper = sql.trim().toUpperCase();

    if (sqlUpper.startsWith('INSERT')) {
      const id = `test-uuid-${++this.idCounter}`;
      const now = new Date().toISOString();
      const businessId = params?.[0];

      if (!this.businesses.has(businessId)) {
        const error: any = new Error('insert or update on table "attestations" violates foreign key constraint');
        error.code = '23503';
        throw error;
      }

      const key = `${businessId}-${params?.[1]}`;
      if (this.data.has(key)) {
        const error: any = new Error('duplicate key value violates unique constraint');
        error.code = '23505';
        throw error;
      }

      const row = {
        id,
        business_id: businessId,
        period: params?.[1],
        merkle_root: params?.[2],
        tx_hash: params?.[3],
        status: params?.[4],
        version: 1,
        created_at: now,
        updated_at: now,
      };

      this.data.set(id, row);
      this.data.set(key, id);
      return { rows: [row as T] };
    }

    if (sqlUpper.startsWith('SELECT')) {
      if (sqlUpper.includes('COUNT')) {
        const businessId = params?.[0];
        let count = 0;
        for (const [, value] of this.data.entries()) {
          if (typeof value === 'object' && value.business_id) {
            if (!businessId || value.business_id === businessId) count++;
          }
        }
        return { rows: [{ count: count.toString() } as T] };
      }

      if (sqlUpper.includes('WHERE') && sqlUpper.includes('BUSINESS_ID')) {
        const businessId = params?.[0];
        const limit = params?.[1] ? parseInt(params[1]) : 10;
        const offset = params?.[2] ? parseInt(params[2]) : 0;
        const results: any[] = [];
        let idx = 0;
        for (const [, value] of this.data.entries()) {
          if (typeof value === 'object' && value.business_id === businessId) {
            if (idx >= offset && idx < offset + limit) results.push(value);
            idx++;
          }
        }
        return { rows: results as T[] };
      }

      if (params && params.length >= 2) {
        const key = `${params[0]}-${params[1]}`;
        const id = this.data.get(key);
        if (id && typeof id === 'string') {
          const row = this.data.get(id);
          if (row) return { rows: [row as T] };
        }
        return { rows: [] };
      }

      const id = params?.[0];
      const row = this.data.get(id);
      if (!row || typeof row === 'string') return { rows: [] };
      return { rows: [row as T] };
    }

    if (sqlUpper.startsWith('UPDATE')) {
      if (!params || params.length === 0) return { rows: [] };

      const id = params[params.length - 1];
      const row = this.data.get(id);
      if (!row || typeof row === 'string') return { rows: [] };

      const updatedRow = { ...row };

      const whereMatch = sql.match(/WHERE.*version\s*=\s*\$(\d+)/i);
      if (whereMatch) {
        const versionParamIndex = parseInt(whereMatch[1]) - 1;
        const expectedVersion = params[versionParamIndex];
        if (row.version !== expectedVersion) return { rows: [] };
      }

      updatedRow.version = (row.version || 0) + 1;
      updatedRow.updated_at = new Date().toISOString();

      if (sql.includes('status = $1')) updatedRow.status = params[0];

      this.data.set(id, updatedRow);
      return { rows: [updatedRow as T] };
    }

    if (sqlUpper.startsWith('DELETE')) {
      const id = params?.[0];
      const row = this.data.get(id);
      if (!row || typeof row === 'string') return { rows: [] };
      this.data.delete(id);
      this.data.delete(`${row.business_id}-${row.period}`);
      return { rows: [{ id } as T] };
    }

    return { rows: [] };
  }

  clear() {
    this.data.clear();
    this.idCounter = 0;
  }

  addBusiness(id: string, userId: string, name: string) {
    this.businesses.set(id, { id, user_id: userId, name });
  }
}

/**
 * RollbackMockDbClient — simulates a database client that throws a
 * transient/infrastructure error on every query, forcing the caller's
 * catch block (rollback path) to execute.
 *
 * Used to verify that transaction rollback paths surface errors correctly
 * instead of silently swallowing them.
 */
class RollbackMockDbClient implements DbClient {
  public callCount = 0;
  private throwAfterNCalls: number;
  private errorCode: string | undefined;
  private errorMessage: string;
  private delegate: MockDbClient;

  /**
   * @param throwAfterNCalls - let the first N calls succeed, then throw
   * @param errorCode        - optional pg error code (e.g. '23505', '23503')
   * @param errorMessage     - error message
   */
  constructor(
    throwAfterNCalls = 0,
    errorCode?: string,
    errorMessage = 'simulated database error'
  ) {
    this.throwAfterNCalls = throwAfterNCalls;
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
    this.delegate = new MockDbClient();
  }

  async query<T>(sql: string, params?: any[]): Promise<{ rows: T[] }> {
    this.callCount++;
    if (this.callCount > this.throwAfterNCalls) {
      const error: any = new Error(this.errorMessage);
      if (this.errorCode) error.code = this.errorCode;
      throw error;
    }
    return this.delegate.query<T>(sql, params);
  }
}

// ─── Basic CRUD ──────────────────────────────────────────────────────────────

describe('Attestation Repository - Basic CRUD Operations', () => {
  let mockClient: MockDbClient;

  beforeEach(() => {
    mockClient = new MockDbClient();
  });

  describe('create function', () => {
    it('should create a new attestation record', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-01',
        merkleRoot: '0x' + 'a'.repeat(64),
        txHash: '0x' + 'b'.repeat(64),
        status: 'pending',
      };
      const result = await create(mockClient, input);
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.businessId).toBe(input.businessId);
      expect(result.period).toBe(input.period);
      expect(result.merkleRoot).toBe(input.merkleRoot);
      expect(result.txHash).toBe(input.txHash);
      expect(result.status).toBe(input.status);
      expect(result.version).toBe(1);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw ConflictError CONFLICT_TYPE_DUPLICATE for duplicate businessId + period', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-456',
        period: '2025-02',
        merkleRoot: '0x' + 'c'.repeat(64),
        txHash: '0x' + 'd'.repeat(64),
        status: 'submitted',
      };
      await create(mockClient, input);
      const error = await create(mockClient, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
      expect(error.details.businessId).toBe(input.businessId);
      expect(error.details.period).toBe(input.period);
    });

    it('should throw ConflictError CONFLICT_TYPE_FOREIGN_KEY for non-existent businessId', async () => {
      const input: CreateAttestationInput = {
        businessId: 'non-existent-business',
        period: '2025-02',
        merkleRoot: '0x' + 'c'.repeat(64),
        txHash: '0x' + 'd'.repeat(64),
        status: 'submitted',
      };
      const error = await create(mockClient, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY);
      expect(error.details.businessId).toBe(input.businessId);
    });
  });

  describe('getById function', () => {
    it('should retrieve an existing attestation by id', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-789',
        period: '2025-03',
        merkleRoot: '0x' + 'e'.repeat(64),
        txHash: '0x' + 'f'.repeat(64),
        status: 'confirmed',
      };
      const created = await create(mockClient, input);
      const retrieved = await getById(mockClient, created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.id).toBe(created.id);
      expect(retrieved!.status).toBe(input.status);
      expect(retrieved!.version).toBe(1);
    });

    it('should return null for non-existent id', async () => {
      expect(await getById(mockClient, 'non-existent-id')).toBeNull();
    });
  });

  describe('getByBusinessAndPeriod function', () => {
    it('should retrieve an attestation by businessId and period', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-04',
        merkleRoot: '0x' + 'g'.repeat(64),
        txHash: '0x' + 'h'.repeat(64),
        status: 'pending',
      };
      await create(mockClient, input);
      const retrieved = await getByBusinessAndPeriod(mockClient, 'business-123', '2025-04');
      expect(retrieved).not.toBeNull();
      expect(retrieved!.businessId).toBe(input.businessId);
      expect(retrieved!.period).toBe(input.period);
    });

    it('should return null for non-existent combination', async () => {
      expect(await getByBusinessAndPeriod(mockClient, 'business-123', 'non-existent-period')).toBeNull();
    });
  });

  describe('create-retrieve round trip', () => {
    it('should successfully create and retrieve an attestation', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-round-trip',
        period: '2025-Q1',
        merkleRoot: '0x' + '1'.repeat(64),
        txHash: '0x' + '2'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      const retrieved = await getById(mockClient, created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.id).toBe(created.id);
      expect(retrieved!.version).toBe(created.version);
    });
  });
});

// ─── Write Conflict Handling ──────────────────────────────────────────────────

describe('Attestation Repository - Write Conflict Handling', () => {
  let mockClient: MockDbClient;

  beforeEach(() => {
    mockClient = new MockDbClient();
  });

  describe('updateStatus function', () => {
    it('should update status without version check', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-05',
        merkleRoot: '0x' + 'i'.repeat(64),
        txHash: '0x' + 'j'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      const updated = await updateStatus(mockClient, created.id, 'confirmed');
      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('confirmed');
      expect(updated!.version).toBe(2);
    });

    it('should return null when updating non-existent attestation', async () => {
      expect(await updateStatus(mockClient, 'non-existent-id', 'confirmed')).toBeNull();
    });

    it('should throw ConflictError when version mismatch (optimistic locking)', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-version',
        period: '2025-06',
        merkleRoot: '0x' + 'k'.repeat(64),
        txHash: '0x' + 'l'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      const error = await updateStatus(mockClient, created.id, 'confirmed', 999).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
      expect(error.details.expectedVersion).toBe(999);
    });

    it.skip('should successfully update when version matches', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-version',
        period: '2025-07',
        merkleRoot: '0x' + 'm'.repeat(64),
        txHash: '0x' + 'n'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      const updated = await updateStatus(mockClient, created.id, 'confirmed', 1);
      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('confirmed');
      expect(updated!.version).toBe(2);
    });

    it('should throw error for invalid status value', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-08',
        merkleRoot: '0x' + 'o'.repeat(64),
        txHash: '0x' + 'p'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      await expect(updateStatus(mockClient, created.id, 'invalid-status' as any)).rejects.toThrow();
    });
  });

  describe('update function', () => {
    it('should verify record exists before update', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-09',
        merkleRoot: '0x' + 'q'.repeat(64),
        txHash: '0x' + 'r'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      const record = await getById(mockClient, created.id);
      expect(record).not.toBeNull();
      expect(record!.status).toBe('pending');
      expect(record!.version).toBe(1);
    });

    it('should throw ConflictError when version mismatch', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-456',
        period: '2025-10',
        merkleRoot: '0x' + 's'.repeat(64),
        txHash: '0x' + 't'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      const error = await update(mockClient, created.id, { status: 'confirmed' }, 999).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
    });
  });

  describe('createWithConflictCheck function', () => {
    it('should create attestation when no conflict exists', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-conflict',
        period: '2025-12',
        merkleRoot: '0x' + 'w'.repeat(64),
        txHash: '0x' + 'x'.repeat(64),
        status: 'pending',
      };
      const result = await createWithConflictCheck(mockClient, input);
      expect(result).toBeDefined();
      expect(result.businessId).toBe(input.businessId);
    });

    it('should throw ConflictError when attestation exists', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-conflict',
        period: '2025-13',
        merkleRoot: '0x' + 'y'.repeat(64),
        txHash: '0x' + 'z'.repeat(64),
        status: 'pending',
      };
      await create(mockClient, input);
      const error = await createWithConflictCheck(mockClient, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
    });

    it('should return existing attestation when returnExistingOnConflict is true', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-conflict',
        period: '2025-14',
        merkleRoot: '0x' + '1'.repeat(64),
        txHash: '0x' + '2'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      const result = await createWithConflictCheck(mockClient, input, { returnExistingOnConflict: true });
      expect(result.id).toBe(created.id);
    });
  });

  describe('remove function', () => {
    it('should delete an existing attestation', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-15',
        merkleRoot: '0x' + '3'.repeat(64),
        txHash: '0x' + '4'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      expect(await remove(mockClient, created.id)).toBe(true);
      expect(await getById(mockClient, created.id)).toBeNull();
    });

    it('should return false when deleting non-existent attestation', async () => {
      expect(await remove(mockClient, 'non-existent-id')).toBe(false);
    });
  });
});

// ─── Edge Cases ───────────────────────────────────────────────────────────────

describe('Attestation Repository - Edge Cases', () => {
  let mockClient: MockDbClient;

  beforeEach(() => {
    mockClient = new MockDbClient();
  });

  describe('Concurrent writes', () => {
    it('should handle simultaneous create attempts correctly', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-456',
        period: '2025-concurrent',
        merkleRoot: '0x' + '5'.repeat(64),
        txHash: '0x' + '6'.repeat(64),
        status: 'pending',
      };
      const first = await create(mockClient, input);
      expect(first).toBeDefined();
      const error = await create(mockClient, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
    });

    it('should handle version increment correctly on multiple updates', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-789',
        period: '2025-version-test',
        merkleRoot: '0x' + '7'.repeat(64),
        txHash: '0x' + '8'.repeat(64),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      expect(created.version).toBe(1);
      const updated1 = await updateStatus(mockClient, created.id, 'submitted');
      expect(updated1!.version).toBe(2);
      const updated2 = await updateStatus(mockClient, created.id, 'confirmed');
      expect(updated2!.version).toBe(3);
    });
  });

  describe('Read Consistency', () => {
    it('should return local data when ReadConsistency is LOCAL (default)', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-01',
        merkleRoot: '0xroot',
        txHash: '0xhash',
        status: 'pending',
      };
      const created = await create(mockClient, input);
      
      const retrieved = await getById(mockClient, created.id);
      expect(retrieved?.status).toBe('pending');
      expect(getAttestation).not.toHaveBeenCalled();
    });

    it('should auto-correct indexing lag when ReadConsistency is STRONG', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-01',
        merkleRoot: '0xroot',
        txHash: '0xhash',
        status: 'pending',
      };
      const created = await create(mockClient, input);
      
      // Mock chain having the data
      vi.mocked(getAttestation).mockResolvedValueOnce({
        merkle_root: '0xroot',
        timestamp: 123456789,
      });

      const retrieved = await getById(mockClient, created.id, { consistency: ReadConsistency.STRONG });
      expect(retrieved?.status).toBe('confirmed');
      expect(getAttestation).toHaveBeenCalledWith(input.businessId, input.period);
      
      // Verify DB was updated
      const local = await getById(mockClient, created.id);
      expect(local?.status).toBe('confirmed');
    });

    it('should log error on Merkle root mismatch but return local data', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-01',
        merkleRoot: '0xroot',
        txHash: '0xhash',
        status: 'confirmed',
      };
      const created = await create(mockClient, input);
      
      // Mock chain having DIFFERENT data
      vi.mocked(getAttestation).mockResolvedValueOnce({
        merkle_root: '0xTAMPEDED_ROOT',
        timestamp: 123456789,
      });

      const retrieved = await getById(mockClient, created.id, { consistency: ReadConsistency.STRONG });
      expect(retrieved?.merkleRoot).toBe('0xroot'); // Still returns local
      expect(getAttestation).toHaveBeenCalled();
    });

    it('should return local data and log warning if not found on-chain but confirmed locally', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-01',
        merkleRoot: '0xroot',
        txHash: '0xhash',
        status: 'confirmed',
      };
      const created = await create(mockClient, input);
      
      // Mock chain having NO data
      vi.mocked(getAttestation).mockResolvedValueOnce(null);

      const retrieved = await getById(mockClient, created.id, { consistency: ReadConsistency.STRONG });
      expect(retrieved?.status).toBe('confirmed');
      expect(getAttestation).toHaveBeenCalled();
    });
  });

  describe('ConflictError creation', () => {
    it('should create ConflictError with correct properties', () => {
      const error = createConflictError(
        ConflictErrorType.CONFLICT_TYPE_VERSION,
        'Version mismatch',
        { id: 'test-id', expectedVersion: 1, currentVersion: 2 }
      );
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.name).toBe('ConflictError');
      expect(error.message).toBe('Version mismatch');
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
      expect(error.details.id).toBe('test-id');
      expect(error.status).toBe(409);
    });
  });

  describe('list function', () => {
    it('should list attestations by businessId', async () => {
      await create(mockClient, {
        businessId: 'business-123', period: '2025-list-1',
        merkleRoot: '0x' + 'a1'.repeat(32), txHash: '0x' + 'b1'.repeat(32), status: 'pending',
      });
      await create(mockClient, {
        businessId: 'business-123', period: '2025-list-2',
        merkleRoot: '0x' + 'c1'.repeat(32), txHash: '0x' + 'd1'.repeat(32), status: 'confirmed',
      });
      const result = await list(mockClient, { businessId: 'business-123' }, { limit: 10, offset: 0 });
      expect(result.items.length).toBe(2);
      expect(result.total).toBe(2);
    });
  });

  describe('Concurrent modification detection', () => {
    it('should detect when record was modified between read and update', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-version',
        period: '2025-detect',
        merkleRoot: '0x' + 'e1'.repeat(32),
        txHash: '0x' + 'f1'.repeat(32),
        status: 'pending',
      };
      const created = await create(mockClient, input);
      await updateStatus(mockClient, created.id, 'submitted');
      const error = await updateStatus(mockClient, created.id, 'confirmed', 1).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
    });
  });
});

// ─── Transaction Rollback Paths ───────────────────────────────────────────────

describe('Attestation Repository - Transaction Rollback Paths', () => {

  /**
   * These tests verify that when the database layer throws an error during
   * any write operation, the repository:
   *   1. Does NOT silently swallow the error
   *   2. Re-throws the original error or wraps it as a ConflictError
   *   3. Leaves no partial state visible to callers
   *
   * Each test uses a RollbackMockDbClient configured to throw at a specific
   * call count to simulate the point in the operation where a rollback
   * would normally be triggered by PostgreSQL.
   */

  describe('create — rollback on INSERT failure', () => {
    it('should propagate unexpected DB error during INSERT', async () => {
      const failClient = new RollbackMockDbClient(0, undefined, 'connection timeout during INSERT');
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-01',
        merkleRoot: '0x' + 'aa'.repeat(32),
        txHash: '0x' + 'bb'.repeat(32),
        status: 'pending',
      };
      await expect(create(failClient, input)).rejects.toThrow('connection timeout during INSERT');
    });

    it('should map pg error 23505 to ConflictError CONFLICT_TYPE_DUPLICATE on rollback', async () => {
      const failClient = new RollbackMockDbClient(0, '23505', 'duplicate key value violates unique constraint');
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-02',
        merkleRoot: '0x' + 'cc'.repeat(32),
        txHash: '0x' + 'dd'.repeat(32),
        status: 'pending',
      };
      const error = await create(failClient, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
    });

    it('should map pg error 23503 to ConflictError CONFLICT_TYPE_FOREIGN_KEY on rollback', async () => {
      const failClient = new RollbackMockDbClient(0, '23503', 'foreign key violation on attestations');
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-03',
        merkleRoot: '0x' + 'ee'.repeat(32),
        txHash: '0x' + 'ff'.repeat(32),
        status: 'pending',
      };
      const error = await create(failClient, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY);
    });
  });

  describe('updateStatus — rollback on UPDATE failure', () => {
    it('should propagate unexpected DB error during UPDATE', async () => {
      const failClient = new RollbackMockDbClient(0, undefined, 'deadlock detected during UPDATE');
      await expect(
        updateStatus(failClient, 'some-id', 'confirmed')
      ).rejects.toThrow('deadlock detected during UPDATE');
    });

    it('should propagate ConflictError from version mismatch through rollback path', async () => {
      const client = new MockDbClient();
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-04',
        merkleRoot: '0x' + '11'.repeat(32),
        txHash: '0x' + '22'.repeat(32),
        status: 'pending',
      };
      const created = await create(client, input);
      const error = await updateStatus(client, created.id, 'confirmed', 999).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
      expect(error.details.id).toBe(created.id);
      expect(error.details.expectedVersion).toBe(999);
      expect(error.details.currentVersion).toBe(1);
    });

    it('should return null (not throw) when record does not exist and no version provided', async () => {
      const client = new MockDbClient();
      const result = await updateStatus(client, 'ghost-id', 'confirmed');
      expect(result).toBeNull();
    });
  });

  describe('update — rollback on partial UPDATE failure', () => {
    it('should propagate ConflictError when version mismatch during partial update', async () => {
      const client = new MockDbClient();
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-05',
        merkleRoot: '0x' + '33'.repeat(32),
        txHash: '0x' + '44'.repeat(32),
        status: 'pending',
      };
      const created = await create(client, input);
      const error = await update(client, created.id, { status: 'confirmed' }, 999).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
    });

    it('should return null for non-existent id on partial update without version', async () => {
      const client = new MockDbClient();
      const result = await update(client, 'ghost-id', { status: 'confirmed' });
      expect(result).toBeNull();
    });
  });

  describe('createWithConflictCheck — rollback on pre-check or INSERT failure', () => {
    it('should propagate error when SELECT during pre-check fails', async () => {
      const failClient = new RollbackMockDbClient(0, undefined, 'network error during pre-check SELECT');
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-06',
        merkleRoot: '0x' + '55'.repeat(32),
        txHash: '0x' + '66'.repeat(32),
        status: 'pending',
      };
      await expect(createWithConflictCheck(failClient, input)).rejects.toThrow('network error during pre-check SELECT');
    });

    it('should propagate ConflictError when duplicate exists (returnExistingOnConflict false)', async () => {
      const client = new MockDbClient();
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-07',
        merkleRoot: '0x' + '77'.repeat(32),
        txHash: '0x' + '88'.repeat(32),
        status: 'pending',
      };
      await create(client, input);
      const error = await createWithConflictCheck(client, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
    });

    it('should propagate foreign-key ConflictError from INSERT in rollback path', async () => {
      // Call sequence for createWithConflictCheck:
      //   1. SET LOCAL (applyStatementTimeout for getByBusinessAndPeriod)
      //   2. SELECT    (getByBusinessAndPeriod — must succeed/return empty)
      //   3. SET LOCAL (applyStatementTimeout for create)
      //   4. INSERT    (create — throws 23503 here)
      // throwAfterNCalls=3 lets calls 1-3 succeed, then call 4 throws.
      const failClient = new RollbackMockDbClient(3, '23503', 'foreign key violation on INSERT');
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-08',
        merkleRoot: '0x' + '99'.repeat(32),
        txHash: '0x' + 'aa'.repeat(32),
        status: 'pending',
      };
      const error = await createWithConflictCheck(failClient, input).catch(e => e);
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY);
    });
  });

  describe('remove — rollback on DELETE failure', () => {
    it('should propagate unexpected DB error during DELETE', async () => {
      const failClient = new RollbackMockDbClient(0, undefined, 'lock timeout during DELETE');
      await expect(remove(failClient, 'some-id')).rejects.toThrow('lock timeout during DELETE');
    });

    it('should return false (not throw) when record not found during DELETE', async () => {
      const client = new MockDbClient();
      expect(await remove(client, 'ghost-id')).toBe(false);
    });
  });

  describe('Rollback state integrity', () => {
    it('should not persist data when create fails midway', async () => {
      const client = new MockDbClient();
      const failInput: CreateAttestationInput = {
        businessId: 'non-existent-business',
        period: '2025-rb-integrity',
        merkleRoot: '0x' + 'ab'.repeat(32),
        txHash: '0x' + 'cd'.repeat(32),
        status: 'pending',
      };
      await create(client, failInput).catch(() => {});
      const result = await list(client, {}, { limit: 100, offset: 0 });
      const leaked = result.items.find(i => i.period === '2025-rb-integrity');
      expect(leaked).toBeUndefined();
    });

    it('should preserve original record state when updateStatus rollback occurs', async () => {
      const client = new MockDbClient();
      const input: CreateAttestationInput = {
        businessId: 'business-rollback',
        period: '2025-rb-preserve',
        merkleRoot: '0x' + 'ef'.repeat(32),
        txHash: '0x' + 'ab'.repeat(32),
        status: 'pending',
      };
      const created = await create(client, input);
      await updateStatus(client, created.id, 'confirmed', 999).catch(() => {});
      const after = await getById(client, created.id);
      expect(after).not.toBeNull();
      expect(after!.status).toBe('pending');
      expect(after!.version).toBe(1);
    });
  });
});

// ─── High-Volume Query Patterns ───────────────────────────────────────────────
//
// These tests verify the behaviour added for issue #250:
//   • Statement timeout is applied before every query
//   • Slow / large-result queries emit a structured warning log
//   • Index-column filter paths (business_id, created_at) are exercised
//   • Large-page pagination returns correct slices and totals
//   • Timeout errors propagate without being swallowed

/**
 * SpyDbClient wraps MockDbClient and records every SQL statement executed.
 * Used to assert that SET LOCAL statement_timeout is issued before data queries.
 */
class SpyDbClient implements DbClient {
  public queries: Array<{ sql: string; params?: any[] }> = [];
  private delegate: MockDbClient;

  constructor(delegate?: MockDbClient) {
    this.delegate = delegate ?? new MockDbClient();
  }

  async query<T>(sql: string, params?: any[]): Promise<{ rows: T[] }> {
    this.queries.push({ sql: sql.trim(), params });
    return this.delegate.query<T>(sql, params);
  }

  /** Return the SQL strings in order */
  sqlLog(): string[] {
    return this.queries.map(q => q.sql);
  }

  /** True if a SET LOCAL statement_timeout was issued */
  hasTimeoutSet(): boolean {
    return this.queries.some(q => /SET LOCAL statement_timeout/i.test(q.sql));
  }

  addBusiness(id: string, userId: string, name: string) {
    this.delegate.addBusiness(id, userId, name);
  }
}

/**
 * TimeoutDbClient simulates a PostgreSQL statement_timeout cancellation.
 * The first query (SET LOCAL) succeeds; the second (the actual data query)
 * throws with the pg error code '57014' (query_canceled).
 */
class TimeoutDbClient implements DbClient {
  private callCount = 0;

  async query<T>(sql: string, _params?: any[]): Promise<{ rows: T[] }> {
    this.callCount++;
    if (this.callCount === 1 && /SET LOCAL statement_timeout/i.test(sql)) {
      return { rows: [] as T[] }; // timeout SET succeeds
    }
    const err: any = new Error('ERROR: canceling statement due to statement timeout');
    err.code = '57014';
    throw err;
  }
}

describe('Attestation Repository - High-Volume Query Patterns', () => {
  // ── Statement timeout ──────────────────────────────────────────────────────

  describe('Statement timeout is applied before every query', () => {
    it('create: issues SET LOCAL statement_timeout before INSERT', async () => {
      const spy = new SpyDbClient();
      spy.addBusiness('biz-hv-1', 'user-hv', 'HV Business 1');
      await create(spy, {
        businessId: 'biz-hv-1',
        period: '2026-01',
        merkleRoot: '0x' + 'a'.repeat(64),
        txHash: '0x' + 'b'.repeat(64),
        status: 'pending',
      });
      expect(spy.hasTimeoutSet()).toBe(true);
      // Timeout SET must come before the INSERT
      const idx = spy.sqlLog().findIndex(s => /SET LOCAL statement_timeout/i.test(s));
      const insertIdx = spy.sqlLog().findIndex(s => /INSERT/i.test(s));
      expect(idx).toBeLessThan(insertIdx);
    });

    it('getById: issues SET LOCAL statement_timeout before SELECT', async () => {
      const base = new MockDbClient();
      base.addBusiness('biz-hv-2', 'user-hv', 'HV Business 2');
      const spy = new SpyDbClient(base);
      const created = await create(spy, {
        businessId: 'biz-hv-2',
        period: '2026-02',
        merkleRoot: '0x' + 'c'.repeat(64),
        txHash: '0x' + 'd'.repeat(64),
        status: 'pending',
      });
      spy.queries = []; // reset after create
      await getById(spy, created.id);
      expect(spy.hasTimeoutSet()).toBe(true);
    });

    it('list: issues SET LOCAL statement_timeout before SELECT', async () => {
      const base = new MockDbClient();
      base.addBusiness('biz-hv-3', 'user-hv', 'HV Business 3');
      const spy = new SpyDbClient(base);
      await create(spy, {
        businessId: 'biz-hv-3',
        period: '2026-03',
        merkleRoot: '0x' + 'e'.repeat(64),
        txHash: '0x' + 'f'.repeat(64),
        status: 'pending',
      });
      spy.queries = [];
      await list(spy, { businessId: 'biz-hv-3' }, { limit: 10, offset: 0 });
      expect(spy.hasTimeoutSet()).toBe(true);
    });

    it('updateStatus: issues SET LOCAL statement_timeout before UPDATE', async () => {
      const base = new MockDbClient();
      base.addBusiness('biz-hv-4', 'user-hv', 'HV Business 4');
      const spy = new SpyDbClient(base);
      const created = await create(spy, {
        businessId: 'biz-hv-4',
        period: '2026-04',
        merkleRoot: '0x' + 'g'.repeat(64),
        txHash: '0x' + 'h'.repeat(64),
        status: 'pending',
      });
      spy.queries = [];
      await updateStatus(spy, created.id, 'confirmed');
      expect(spy.hasTimeoutSet()).toBe(true);
    });

    it('remove: issues SET LOCAL statement_timeout before DELETE', async () => {
      const base = new MockDbClient();
      base.addBusiness('biz-hv-5', 'user-hv', 'HV Business 5');
      const spy = new SpyDbClient(base);
      const created = await create(spy, {
        businessId: 'biz-hv-5',
        period: '2026-05',
        merkleRoot: '0x' + 'i'.repeat(64),
        txHash: '0x' + 'j'.repeat(64),
        status: 'pending',
      });
      spy.queries = [];
      await remove(spy, created.id);
      expect(spy.hasTimeoutSet()).toBe(true);
    });
  });

  // ── Timeout error propagation ──────────────────────────────────────────────

  describe('Statement timeout errors propagate without being swallowed', () => {
    it('getById propagates pg error 57014 (query_canceled)', async () => {
      const client = new TimeoutDbClient();
      await expect(getById(client, 'any-id')).rejects.toMatchObject({ code: '57014' });
    });

    it('list propagates pg error 57014 (query_canceled)', async () => {
      const client = new TimeoutDbClient();
      await expect(
        list(client, { businessId: 'biz-x' }, { limit: 10, offset: 0 })
      ).rejects.toMatchObject({ code: '57014' });
    });

    it('updateStatus propagates pg error 57014 (query_canceled)', async () => {
      const client = new TimeoutDbClient();
      await expect(updateStatus(client, 'any-id', 'confirmed')).rejects.toMatchObject({ code: '57014' });
    });
  });

  // ── Structured logging ─────────────────────────────────────────────────────

  describe('Structured warning log is emitted for slow / large queries', () => {
    it('list emits a warn log when result exceeds row threshold', async () => {
      const warnSpy = vi.spyOn(logger, 'warn');

      // Build a client that returns 600 rows (above SLOW_QUERY_ROW_THRESHOLD=500)
      const bigClient: DbClient = {
        async query<T>(sql: string, _params?: any[]): Promise<{ rows: T[] }> {
          if (/SET LOCAL/i.test(sql)) return { rows: [] as T[] };
          if (/COUNT/i.test(sql)) return { rows: [{ count: '600' } as T] };
          // Return 600 fake rows
          const rows = Array.from({ length: 600 }, (_, i) => ({
            id: `id-${i}`,
            business_id: 'biz-big',
            period: `2026-${String(i).padStart(3, '0')}`,
            merkle_root: '0x' + 'a'.repeat(64),
            tx_hash: '0x' + 'b'.repeat(64),
            status: 'pending',
            version: 1,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          })) as T[];
          return { rows };
        },
      };

      await list(bigClient, { businessId: 'biz-big' }, { limit: 600, offset: 0 });

      expect(warnSpy).toHaveBeenCalled();
      const warnArg: string = warnSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(warnArg);
      expect(parsed.event).toBe('attestation_repo_slow_query');
      expect(parsed.op).toBe('list');
      expect(parsed.rowCount).toBeGreaterThanOrEqual(500);

      warnSpy.mockRestore();
    });

    it('list does NOT emit a warn log for small, fast results', async () => {
      const warnSpy = vi.spyOn(logger, 'warn');

      const smallClient: DbClient = {
        async query<T>(sql: string, _params?: any[]): Promise<{ rows: T[] }> {
          if (/SET LOCAL/i.test(sql)) return { rows: [] as T[] };
          if (/COUNT/i.test(sql)) return { rows: [{ count: '2' } as T] };
          const rows = Array.from({ length: 2 }, (_, i) => ({
            id: `id-${i}`,
            business_id: 'biz-small',
            period: `2026-0${i + 1}`,
            merkle_root: '0x' + 'a'.repeat(64),
            tx_hash: '0x' + 'b'.repeat(64),
            status: 'pending',
            version: 1,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          })) as T[];
          return { rows };
        },
      };

      await list(smallClient, { businessId: 'biz-small' }, { limit: 10, offset: 0 });
      expect(warnSpy).not.toHaveBeenCalled();

      warnSpy.mockRestore();
    });
  });

  // ── Index-column filter paths ──────────────────────────────────────────────

  describe('Index-column filter paths', () => {
    it('list with businessId filter uses business_id column in WHERE clause', async () => {
      const spy = new SpyDbClient();
      spy.addBusiness('biz-idx-1', 'user-idx', 'Idx Business 1');
      await create(spy, {
        businessId: 'biz-idx-1',
        period: '2026-idx-01',
        merkleRoot: '0x' + '1'.repeat(64),
        txHash: '0x' + '2'.repeat(64),
        status: 'pending',
      });
      spy.queries = [];
      await list(spy, { businessId: 'biz-idx-1' }, { limit: 10, offset: 0 });
      const dataQuery = spy.sqlLog().find(s => /SELECT/i.test(s) && !/COUNT/i.test(s) && !/SET LOCAL/i.test(s));
      expect(dataQuery).toBeDefined();
      expect(dataQuery).toMatch(/business_id\s*=\s*\$1/i);
    });

    it('list with no filter uses ORDER BY created_at DESC', async () => {
      const spy = new SpyDbClient();
      spy.queries = [];
      await list(spy, {}, { limit: 5, offset: 0 });
      const dataQuery = spy.sqlLog().find(s => /SELECT/i.test(s) && !/COUNT/i.test(s) && !/SET LOCAL/i.test(s));
      expect(dataQuery).toBeDefined();
      expect(dataQuery).toMatch(/ORDER BY created_at DESC/i);
    });

    it('getByBusinessAndPeriod uses business_id as leading filter column', async () => {
      const spy = new SpyDbClient();
      spy.addBusiness('biz-idx-2', 'user-idx', 'Idx Business 2');
      await create(spy, {
        businessId: 'biz-idx-2',
        period: '2026-idx-02',
        merkleRoot: '0x' + '3'.repeat(64),
        txHash: '0x' + '4'.repeat(64),
        status: 'pending',
      });
      spy.queries = [];
      await getByBusinessAndPeriod(spy, 'biz-idx-2', '2026-idx-02');
      const selectQuery = spy.sqlLog().find(s => /SELECT/i.test(s) && !/SET LOCAL/i.test(s));
      expect(selectQuery).toBeDefined();
      expect(selectQuery).toMatch(/business_id\s*=\s*\$1/i);
    });
  });

  // ── Large-page pagination ──────────────────────────────────────────────────

  describe('Large-page pagination returns correct slices and totals', () => {
    it('returns correct total and empty items when offset exceeds total', async () => {
      const client = new MockDbClient();
      client.addBusiness('biz-page', 'user-page', 'Page Business');
      // Insert 3 attestations
      for (let i = 1; i <= 3; i++) {
        await create(client, {
          businessId: 'biz-page',
          period: `2026-page-0${i}`,
          merkleRoot: '0x' + String(i).repeat(64),
          txHash: '0x' + String(i + 1).repeat(64),
          status: 'pending',
        });
      }
      const result = await list(client, { businessId: 'biz-page' }, { limit: 10, offset: 100 });
      expect(result.total).toBe(3);
      expect(result.items).toHaveLength(0);
    });

    it('returns correct page slice with limit and offset', async () => {
      const client = new MockDbClient();
      client.addBusiness('biz-slice', 'user-slice', 'Slice Business');
      for (let i = 1; i <= 5; i++) {
        await create(client, {
          businessId: 'biz-slice',
          period: `2026-slice-0${i}`,
          merkleRoot: '0x' + String(i).repeat(64),
          txHash: '0x' + String(i + 1).repeat(64),
          status: 'pending',
        });
      }
      const page1 = await list(client, { businessId: 'biz-slice' }, { limit: 2, offset: 0 });
      expect(page1.total).toBe(5);
      expect(page1.items).toHaveLength(2);

      const page2 = await list(client, { businessId: 'biz-slice' }, { limit: 2, offset: 2 });
      expect(page2.total).toBe(5);
      expect(page2.items).toHaveLength(2);

      // No overlap between pages
      const ids1 = new Set(page1.items.map(i => i.id));
      const ids2 = new Set(page2.items.map(i => i.id));
      const overlap = [...ids1].filter(id => ids2.has(id));
      expect(overlap).toHaveLength(0);
    });

    it('list with no filters returns all attestations across businesses', async () => {
      // The MockDbClient no-filter SELECT path doesn't support the no-WHERE case,
      // so we use a custom client that returns a known set of rows.
      const fakeRows = [
        { id: 'id-all-1', business_id: 'biz-all-1', period: '2026-all-01',
          merkle_root: '0x' + 'a'.repeat(64), tx_hash: '0x' + 'b'.repeat(64),
          status: 'pending', version: 1,
          created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
        { id: 'id-all-2', business_id: 'biz-all-2', period: '2026-all-02',
          merkle_root: '0x' + 'c'.repeat(64), tx_hash: '0x' + 'd'.repeat(64),
          status: 'confirmed', version: 1,
          created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      ];
      const noFilterClient: DbClient = {
        async query<T>(sql: string, _params?: any[]): Promise<{ rows: T[] }> {
          if (/SET LOCAL/i.test(sql)) return { rows: [] as T[] };
          if (/COUNT/i.test(sql)) return { rows: [{ count: '2' } as T] };
          return { rows: fakeRows as T[] };
        },
      };
      const result = await list(noFilterClient, {}, { limit: 100, offset: 0 });
      expect(result.total).toBeGreaterThanOrEqual(2);
      expect(result.items.length).toBeGreaterThanOrEqual(2);
    });
  });
});
