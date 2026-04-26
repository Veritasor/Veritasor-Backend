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
      const failClient = new RollbackMockDbClient(1, '23503', 'foreign key violation on INSERT');
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
