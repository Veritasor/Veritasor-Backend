import { describe, it, expect, beforeEach } from 'vitest';
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
} from '../../../src/types/attestation.js';
import type { CreateAttestationInput, DbClient, Attestation, AttestationFilters } from '../../../src/types/attestation.js';

/**
 * Test Database Setup
 * 
 * This test suite uses a MockDbClient for unit testing, which provides:
 * - Fast test execution without database overhead
 * - Automatic isolation between tests (each test gets a fresh mock)
 * - Simulation of database constraints (unique, foreign key)
 * - Predictable behavior for testing edge cases
 * 
 * The mock approach is sufficient for unit testing repository logic, type conversions,
 * and error handling. Each test gets a fresh MockDbClient instance via beforeEach,
 * ensuring complete isolation without needing database transactions.
 * 
 * For integration tests with a real PostgreSQL database, transaction-based isolation
 * would be implemented as follows:
 * 
 * ```typescript
 * import { Pool } from 'pg';
 * 
 * let pool: Pool;
 * let client: PoolClient;
 * 
 * beforeAll(async () => {
 *   pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
 *   // Create seed data for businesses table (foreign key relationships)
 *   await pool.query(`
 *     INSERT INTO businesses (id, user_id, name) VALUES
 *     ('test-business-1', 'test-user-1', 'Test Business 1'),
 *     ('test-business-2', 'test-user-2', 'Test Business 2')
 *   `);
 * });
 * 
 * beforeEach(async () => {
 *   client = await pool.connect();
 *   await client.query('BEGIN'); // Start transaction
 * });
 * 
 * afterEach(async () => {
 *   await client.query('ROLLBACK'); // Rollback transaction for isolation
 *   client.release();
 * });
 * 
 * afterAll(async () => {
 *   await pool.end();
 * });
 * ```
 * 
 * This transaction-based approach ensures:
 * - Each test runs in an isolated transaction
 * - Changes are rolled back after each test
 * - Tests don't affect each other or leave test data
 * - Real database constraints and triggers are tested
 */

/**
 * Mock database client for unit testing
 * Simulates PostgreSQL query responses with in-memory storage
 * Provides automatic test isolation via fresh instances in beforeEach
 */
class MockDbClient implements DbClient {
  private data: Map<string, any> = new Map();
  private idCounter = 0;
  private businesses: Map<string, any> = new Map();

  constructor() {
    // Seed data for businesses table (simulates foreign key relationships)
    this.seedBusinesses();
  }

  /**
   * Create seed data for businesses table
   * This simulates the foreign key relationships that would exist in a real database
   */
  private seedBusinesses() {
    const seedBusinesses = [
      { id: 'business-123', user_id: 'user-1', name: 'Test Business 1' },
      { id: 'business-456', user_id: 'user-1', name: 'Test Business 2' },
      { id: 'business-789', user_id: 'user-2', name: 'Test Business 3' },
      { id: 'business-round-trip', user_id: 'user-3', name: 'Round Trip Business' },
      { id: 'business-conflict', user_id: 'user-4', name: 'Conflict Test Business' },
      { id: 'business-version', user_id: 'user-5', name: 'Version Test Business' },
    ];

    seedBusinesses.forEach(business => {
      this.businesses.set(business.id, business);
    });
  }

  async query<T>(sql: string, params?: any[]): Promise<{ rows: T[] }> {
    const sqlUpper = sql.trim().toUpperCase();
    
    // Handle INSERT queries
    if (sqlUpper.startsWith('INSERT')) {
      const id = `test-uuid-${++this.idCounter}`;
      const now = new Date().toISOString();
      
      const businessId = params![0];
      
      // Simulate foreign key constraint check
      if (!this.businesses.has(businessId)) {
        const error: any = new Error('insert or update on table "attestations" violates foreign key constraint');
        error.code = '23503';
        throw error;
      }
      
      const row = {
        id,
        business_id: businessId,
        period: params![1],
        merkle_root: params![2],
        tx_hash: params![3],
        status: params![4],
        version: 1,
        created_at: now,
        updated_at: now,
      };
      
      // Check for duplicate businessId + period (unique constraint)
      const key = `${businessId}-${params![1]}`;
      if (this.data.has(key)) {
        const error: any = new Error('duplicate key value violates unique constraint');
        error.code = '23505';
        throw error;
      }
      
      this.data.set(id, row);
      this.data.set(key, id);
      
      return { rows: [row as T] };
    }
    
    // Handle SELECT queries
    if (sqlUpper.startsWith('SELECT')) {
      // Check for business_id + period query
      if (params && params.length >= 2) {
        const key = `${params[0]}-${params[1]}`;
        const id = this.data.get(key);
        if (id && typeof id === 'string') {
          const row = this.data.get(id);
          if (row) {
            return { rows: [row as T] };
          }
        }
        return { rows: [] };
      }
      
      // Check for id query
      const id = params![0];
      const row = this.data.get(id);
      
      if (!row || typeof row === 'string') {
        return { rows: [] };
      }
      
      return { rows: [row as T] };
    }
    
    // Handle UPDATE queries
    if (sqlUpper.startsWith('UPDATE')) {
      if (!params || params.length === 0) {
        return { rows: [] };
      }
      
      const id = params[params.length - 1];
      const row = this.data.get(id);
      
      if (!row || typeof row === 'string') {
        return { rows: [] };
      }
      
      // Update the row with new values
      const updatedRow = { ...row };
      
      // Check if we're doing a versioned update
      if (sql.includes('WHERE id') && sql.includes('version')) {
        // Version check is in the WHERE clause
        const expectedVersion = params[params.length - 2];
        if (row.version !== expectedVersion) {
          return { rows: [] }; // Version mismatch
        }
      }
      
      // Increment version
      updatedRow.version = (row.version || 0) + 1;
      updatedRow.updated_at = new Date().toISOString();
      
      // Update status if present
      if (sql.includes('status = $1')) {
        updatedRow.status = params![0];
      }
      
      // Update merkle_root if present
      if (sql.includes('merkle_root')) {
        const merkleIndex = sql.split('merkle_root').length > 1 ? 
          sql.substring(0, sql.indexOf('merkle_root')).split('$').length - 1 : -1;
        if (merkleIndex > 0 && params![merkleIndex]) {
          updatedRow.merkle_root = params![merkleIndex];
        }
      }
      
      // Update tx_hash if present
      if (sql.includes('tx_hash')) {
        const txIndex = sql.split('tx_hash').length > 1 ? 
          sql.substring(0, sql.indexOf('tx_hash')).split('$').length - 1 : -1;
        if (txIndex > 0 && params![txIndex]) {
          updatedRow.tx_hash = params![txIndex];
        }
      }
      
      this.data.set(id, updatedRow);
      
      return { rows: [updatedRow as T] };
    }
    
    // Handle DELETE queries
    if (sqlUpper.startsWith('DELETE')) {
      const id = params![0];
      const row = this.data.get(id);
      
      if (!row || typeof row === 'string') {
        return { rows: [] };
      }
      
      // Remove from data store
      const key = `${row.business_id}-${row.period}`;
      this.data.delete(id);
      this.data.delete(key);
      
      return { rows: [{ id } as T] };
    }
    
    return { rows: [] };
  }

  /**
   * Clear all attestation data (simulates transaction rollback)
   * Businesses seed data is preserved
   */
  clear() {
    this.data.clear();
    this.idCounter = 0;
  }

  /**
   * Add a business to the seed data (for testing foreign key relationships)
   */
  addBusiness(id: string, userId: string, name: string) {
    this.businesses.set(id, { id, user_id: userId, name });
  }
}

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

    it('should throw ConflictError with CONFLICT_TYPE_DUPLICATE for duplicate businessId + period', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-456',
        period: '2025-02',
        merkleRoot: '0x' + 'c'.repeat(64),
        txHash: '0x' + 'd'.repeat(64),
        status: 'submitted',
      };

      // Create first attestation
      await create(mockClient, input);

      // Try to create duplicate
      const error = await create(mockClient, input).catch(e => e);
      
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
      expect(error.details.businessId).toBe(input.businessId);
      expect(error.details.period).toBe(input.period);
    });

    it('should throw ConflictError with CONFLICT_TYPE_FOREIGN_KEY for non-existent businessId', async () => {
      const input: CreateAttestationInput = {
        businessId: 'non-existent-business',
        period: '2025-02',
        merkleRoot: '0x' + 'c'.repeat(64),
        txHash: '0x' + 'd'.repeat(64),
        status: 'submitted',
      };

      // Try to create attestation with invalid businessId
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
      expect(retrieved!.businessId).toBe(input.businessId);
      expect(retrieved!.period).toBe(input.period);
      expect(retrieved!.merkleRoot).toBe(input.merkleRoot);
      expect(retrieved!.txHash).toBe(input.txHash);
      expect(retrieved!.status).toBe(input.status);
      expect(retrieved!.version).toBe(1);
    });

    it('should return null for non-existent id', async () => {
      const result = await getById(mockClient, 'non-existent-id');
      expect(result).toBeNull();
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

    it('should return null for non-existent businessId + period combination', async () => {
      const result = await getByBusinessAndPeriod(mockClient, 'business-123', 'non-existent-period');
      expect(result).toBeNull();
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

      // Create
      const created = await create(mockClient, input);
      expect(created.id).toBeDefined();

      // Retrieve
      const retrieved = await getById(mockClient, created.id);
      expect(retrieved).not.toBeNull();
      
      // Verify all fields match
      expect(retrieved!.id).toBe(created.id);
      expect(retrieved!.businessId).toBe(created.businessId);
      expect(retrieved!.period).toBe(created.period);
      expect(retrieved!.merkleRoot).toBe(created.merkleRoot);
      expect(retrieved!.txHash).toBe(created.txHash);
      expect(retrieved!.status).toBe(created.status);
      expect(retrieved!.version).toBe(created.version);
      expect(retrieved!.createdAt.getTime()).toBe(created.createdAt.getTime());
      expect(retrieved!.updatedAt.getTime()).toBe(created.updatedAt.getTime());
    });
  });
});

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
      const result = await updateStatus(mockClient, 'non-existent-id', 'confirmed');
      expect(result).toBeNull();
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
      
      // Try to update with wrong expected version
      const error = await updateStatus(mockClient, created.id, 'confirmed', 999).catch(e => e);
      
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
      expect(error.details.expectedVersion).toBe(999);
    });

    it('should successfully update when version matches', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-version',
        period: '2025-07',
        merkleRoot: '0x' + 'm'.repeat(64),
        txHash: '0x' + 'n'.repeat(64),
        status: 'pending',
      };

      const created = await create(mockClient, input);
      
      // Update with correct version
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
    it('should update attestation fields without version check', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-09',
        merkleRoot: '0x' + 'q'.repeat(64),
        txHash: '0x' + 'r'.repeat(64),
        status: 'pending',
      };

      const created = await create(mockClient, input);
      const updated = await update(mockClient, created.id, { status: 'submitted' });

      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('submitted');
      expect(updated!.version).toBe(2);
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

    it('should throw error when no valid fields to update', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-789',
        period: '2025-11',
        merkleRoot: '0x' + 'u'.repeat(64),
        txHash: '0x' + 'v'.repeat(64),
        status: 'pending',
      };

      const created = await create(mockClient, input);
      
      // Try to update non-updatable field
      await expect(update(mockClient, created.id, { id: 'new-id' } as any)).rejects.toThrow('No valid fields to update');
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
      expect(result.period).toBe(input.period);
    });

    it('should throw ConflictError when attestation exists and returnExistingOnConflict is false', async () => {
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
      const deleted = await remove(mockClient, created.id);
      
      expect(deleted).toBe(true);
      
      // Verify it's gone
      const retrieved = await getById(mockClient, created.id);
      expect(retrieved).toBeNull();
    });

    it('should return false when deleting non-existent attestation', async () => {
      const deleted = await remove(mockClient, 'non-existent-id');
      expect(deleted).toBe(false);
    });
  });
});

describe('Attestation Repository - Edge Cases and Error Handling', () => {
  let mockClient: MockDbClient;

  beforeEach(() => {
    mockClient = new MockDbClient();
  });

  describe('Concurrent write simulation', () => {
    it('should handle simultaneous create attempts correctly', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-456',
        period: '2025-concurrent',
        merkleRoot: '0x' + '5'.repeat(64),
        txHash: '0x' + '6'.repeat(64),
        status: 'pending',
      };

      // First create succeeds
      const first = await create(mockClient, input);
      expect(first).toBeDefined();

      // Second create fails with conflict
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

      // First update
      const updated1 = await updateStatus(mockClient, created.id, 'submitted');
      expect(updated1!.version).toBe(2);

      // Second update
      const updated2 = await updateStatus(mockClient, created.id, 'confirmed');
      expect(updated2!.version).toBe(3);

      // Third update
      const updated3 = await updateStatus(mockClient, created.id, 'failed');
      expect(updated3!.version).toBe(4);
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
      expect(error.details.expectedVersion).toBe(1);
      expect(error.details.currentVersion).toBe(2);
      expect(error.status).toBe(409);
    });
  });

  describe('list function', () => {
    it('should list attestations by businessId', async () => {
      // Create multiple attestations for the same business
      const input1: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-list-1',
        merkleRoot: '0x' + 'a1'.repeat(32),
        txHash: '0x' + 'b1'.repeat(32),
        status: 'pending',
      };
      const input2: CreateAttestationInput = {
        businessId: 'business-123',
        period: '2025-list-2',
        merkleRoot: '0x' + 'c1'.repeat(32),
        txHash: '0x' + 'd1'.repeat(32),
        status: 'confirmed',
      };

      await create(mockClient, input1);
      await create(mockClient, input2);

      const result = await list(mockClient, { businessId: 'business-123' }, { limit: 10, offset: 0 });
      
      expect(result.items.length).toBe(2);
      expect(result.total).toBe(2);
    });

    it('should return empty list for business with no attestations', async () => {
      const result = await list(mockClient, { businessId: 'business-with-no-records' }, { limit: 10, offset: 0 });
      
      expect(result.items.length).toBe(0);
      expect(result.total).toBe(0);
    });
  });

  describe('updateStatus with concurrent modification detection', () => {
    it('should detect when record was modified between read and update', async () => {
      const input: CreateAttestationInput = {
        businessId: 'business-version',
        period: '2025-detect',
        merkleRoot: '0x' + 'e1'.repeat(32),
        txHash: '0x' + 'f1'.repeat(32),
        status: 'pending',
      };

      const created = await create(mockClient, input);
      
      // Simulate another process updating the record
      await updateStatus(mockClient, created.id, 'submitted');
      
      // Now try to update with original version - should fail
      const error = await updateStatus(mockClient, created.id, 'confirmed', 1).catch(e => e);
      
      expect(error).toBeInstanceOf(ConflictError);
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
    });
  });
});

/**
 * Test Isolation Strategy
 * 
 * This test suite achieves test isolation through the following mechanisms:
 * 
 * 1. **Mock-Based Isolation (Current Approach)**:
 *    - Each test gets a fresh MockDbClient instance via beforeEach
 *    - The mock maintains in-memory state that is automatically cleared between tests
 *    - Seed data (businesses) is recreated for each test instance
 *    - This provides fast, reliable isolation without database overhead
 * 
 * 2. **Transaction-Based Isolation (For Integration Tests)**:
 *    When testing against a real PostgreSQL database, use this pattern:
 *    - Start a transaction before each test (BEGIN)
 *    - Run the test within the transaction
 *    - Rollback the transaction after each test (ROLLBACK)
 *    - This ensures no test data persists between tests
 *    - Real database constraints and triggers are validated
 * 
 * 3. **Seed Data Management**:
 *    - The MockDbClient includes seed data for the businesses table
 *    - This simulates foreign key relationships required by attestations
 *    - For integration tests, seed data would be inserted in beforeAll
 *    - Seed data should use predictable IDs for test assertions
 * 
 * 4. **Benefits of Current Approach**:
 *    - Fast test execution (no database I/O)
 *    - No external dependencies (no database required)
 *    - Predictable behavior (no timing issues)
 *    - Easy to debug (in-memory state inspection)
 *    - Sufficient for unit testing repository logic
 * 
 * 5. **When to Use Integration Tests**:
 *    - Testing complex SQL queries (JOINs, subqueries)
 *    - Validating database constraints and triggers
 *    - Testing transaction behavior and isolation levels
 *    - Performance testing with realistic data volumes
 *    - End-to-end testing of the full stack
 */
