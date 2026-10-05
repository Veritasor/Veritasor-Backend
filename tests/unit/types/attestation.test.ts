/**
 * Dedicated test suite for src/types/attestation.ts
 *
 * Covers:
 *  - AttestationStatus: exhaustive membership, runtime narrowing, invalid values
 *  - Attestation: record shape, field formats, compile-time contract
 *  - CreateAttestationInput: required fields, excluded auto-generated fields
 *  - Primary lifecycle transitions (pending -> submitted -> confirmed, failure, revocation)
 *  - ConflictError / createConflictError / ConflictErrorType error contract
 *  - ReadConsistency enum values
 *
 * The status/attestation types are compile-time only, so runtime assertions are
 * paired with `expectTypeOf` and `@ts-expect-error` checks that fail
 * `tsc -p tsconfig.test.json` if the public contract drifts.
 */
import { describe, it, expect, expectTypeOf } from 'vitest';
import {
  ConflictError,
  ConflictErrorType,
  createConflictError,
  ReadConsistency,
  type Attestation,
  type AttestationStatus,
  type CreateAttestationInput,
  type ConsistencyDiscrepancy,
} from '../../../src/types/attestation.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * Exhaustive status map. Adding or removing a member of AttestationStatus
 * without updating this record is a compile error, which keeps the runtime
 * list below in lock-step with the type.
 */
const STATUS_MAP: Record<AttestationStatus, true> = {
  pending: true,
  submitted: true,
  confirmed: true,
  failed: true,
  revoked: true,
};

const ALL_STATUSES = Object.keys(STATUS_MAP) as AttestationStatus[];

const HEX_32_BYTES = /^0x[0-9a-fA-F]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PERIOD = /^\d{4}-(0[1-9]|1[0-2]|Q[1-4])$/;

function isAttestationStatus(value: unknown): value is AttestationStatus {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(STATUS_MAP, value);
}

/** Field-level validation mirroring the documented formats on CreateAttestationInput. */
function validateCreateInput(input: Record<string, unknown>): string[] {
  const errors: string[] = [];
  if (typeof input.businessId !== 'string' || !UUID.test(input.businessId)) errors.push('businessId');
  if (typeof input.period !== 'string' || !PERIOD.test(input.period)) errors.push('period');
  if (typeof input.merkleRoot !== 'string' || !HEX_32_BYTES.test(input.merkleRoot)) errors.push('merkleRoot');
  if (typeof input.txHash !== 'string' || !HEX_32_BYTES.test(input.txHash)) errors.push('txHash');
  if (!isAttestationStatus(input.status)) errors.push('status');
  return errors;
}

/** Primary lifecycle transitions for an attestation. */
const TRANSITIONS: Record<AttestationStatus, readonly AttestationStatus[]> = {
  pending: ['submitted', 'failed'],
  submitted: ['confirmed', 'failed'],
  confirmed: ['revoked'],
  failed: [],
  revoked: [],
};

const FIXED_DATE = new Date('2025-10-01T00:00:00.000Z');

function makeCreateInput(overrides: Partial<CreateAttestationInput> = {}): CreateAttestationInput {
  return {
    businessId: '11111111-2222-3333-4444-555555555555',
    period: '2025-10',
    merkleRoot: '0x' + 'a'.repeat(64),
    txHash: '0x' + 'b'.repeat(64),
    status: 'pending',
    ...overrides,
  };
}

function makeAttestation(overrides: Partial<Attestation> = {}): Attestation {
  return {
    id: '99999999-8888-7777-6666-555555555555',
    ...makeCreateInput(),
    version: 1,
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
    ...overrides,
  };
}

/**
 * Deterministic transition helper modelling optimistic locking semantics:
 * the version must match and the target status must be reachable.
 */
function transition(
  record: Attestation,
  next: AttestationStatus,
  expectedVersion: number = record.version,
  now: Date = FIXED_DATE,
): Attestation {
  if (!isAttestationStatus(next)) {
    throw new Error(`Invalid status: ${String(next)}`);
  }
  if (expectedVersion !== record.version) {
    throw createConflictError(
      ConflictErrorType.CONFLICT_TYPE_VERSION,
      `Attestation ${record.id} was modified by another process`,
      { id: record.id, expectedVersion, actualVersion: record.version },
    );
  }
  if (!TRANSITIONS[record.status].includes(next)) {
    throw new Error(`Illegal transition: ${record.status} -> ${next}`);
  }
  return { ...record, status: next, version: record.version + 1, updatedAt: now };
}

// ---------------------------------------------------------------------------
// AttestationStatus
// ---------------------------------------------------------------------------

describe('AttestationStatus', () => {
  it('contains exactly the five documented lifecycle states', () => {
    expect([...ALL_STATUSES].sort()).toEqual(['confirmed', 'failed', 'pending', 'revoked', 'submitted']);
  });

  it('is a string literal union (compile-time contract)', () => {
    expectTypeOf<AttestationStatus>().toEqualTypeOf<
      'pending' | 'submitted' | 'confirmed' | 'failed' | 'revoked'
    >();
    expectTypeOf<'pending'>().toMatchTypeOf<AttestationStatus>();
    // @ts-expect-error - 'unknown' is not a valid status
    const bad: AttestationStatus = 'unknown';
    expect(bad).toBe('unknown');
  });

  it.each(ALL_STATUSES)('accepts valid status %s', (status) => {
    expect(isAttestationStatus(status)).toBe(true);
  });

  it.each([
    ['empty string', ''],
    ['uppercase', 'PENDING'],
    ['padded', ' pending '],
    ['unknown word', 'approved'],
    ['prototype key', 'toString'],
    ['number', 1],
    ['null', null],
    ['undefined', undefined],
    ['object', { status: 'pending' }],
  ])('rejects invalid status (%s)', (_label, value) => {
    expect(isAttestationStatus(value)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

describe('Attestation', () => {
  it('exposes the documented field types', () => {
    expectTypeOf<Attestation>().toEqualTypeOf<{
      id: string;
      businessId: string;
      period: string;
      merkleRoot: string;
      txHash: string;
      status: AttestationStatus;
      version: number;
      createdAt: Date;
      updatedAt: Date;
    }>();
  });

  it('builds a well-formed record fixture', () => {
    const record = makeAttestation();
    expect(Object.keys(record).sort()).toEqual(
      ['businessId', 'createdAt', 'id', 'merkleRoot', 'period', 'status', 'txHash', 'updatedAt', 'version'],
    );
    expect(record.id).toMatch(UUID);
    expect(record.businessId).toMatch(UUID);
    expect(record.merkleRoot).toMatch(HEX_32_BYTES);
    expect(record.txHash).toMatch(HEX_32_BYTES);
    expect(record.version).toBe(1);
    expect(record.createdAt).toBeInstanceOf(Date);
    expect(record.updatedAt.getTime()).toBe(record.createdAt.getTime());
  });

  it('is a structural superset of CreateAttestationInput', () => {
    expectTypeOf<Attestation>().toMatchTypeOf<CreateAttestationInput>();
    const { id: _id, version: _v, createdAt: _c, updatedAt: _u, ...rest } = makeAttestation();
    expect(rest).toEqual(makeCreateInput());
  });

  it('rejects records missing required fields at compile time', () => {
    // @ts-expect-error - version is required
    const missingVersion: Attestation = { ...makeCreateInput(), id: 'x', createdAt: FIXED_DATE, updatedAt: FIXED_DATE };
    expect(missingVersion).not.toHaveProperty('version');
  });

  it('is used as the status type of ConsistencyDiscrepancy.localStatus', () => {
    expectTypeOf<ConsistencyDiscrepancy['localStatus']>().toEqualTypeOf<AttestationStatus>();
  });
});

// ---------------------------------------------------------------------------
// CreateAttestationInput
// ---------------------------------------------------------------------------

describe('CreateAttestationInput', () => {
  it('requires exactly the client-supplied fields', () => {
    expectTypeOf<CreateAttestationInput>().toEqualTypeOf<{
      businessId: string;
      period: string;
      merkleRoot: string;
      txHash: string;
      status: AttestationStatus;
    }>();
  });

  it('does not expose auto-generated fields', () => {
    type Keys = keyof CreateAttestationInput;
    expectTypeOf<'id' extends Keys ? true : false>().toEqualTypeOf<false>();
    expectTypeOf<'version' extends Keys ? true : false>().toEqualTypeOf<false>();
    expectTypeOf<'createdAt' extends Keys ? true : false>().toEqualTypeOf<false>();
    expectTypeOf<'updatedAt' extends Keys ? true : false>().toEqualTypeOf<false>();
  });

  it('accepts a valid input', () => {
    expect(validateCreateInput({ ...makeCreateInput() })).toEqual([]);
  });

  it.each(['2025-01', '2025-12', '2025-Q1', '2025-Q4'])('accepts period %s', (period) => {
    expect(validateCreateInput({ ...makeCreateInput({ period }) })).toEqual([]);
  });

  it.each([
    ['businessId', { businessId: 'not-a-uuid' }],
    ['businessId', { businessId: '' }],
    ['period', { period: '2025-13' }],
    ['period', { period: '2025-Q5' }],
    ['period', { period: '25-10' }],
    ['merkleRoot', { merkleRoot: 'a'.repeat(64) }],
    ['merkleRoot', { merkleRoot: '0x' + 'a'.repeat(63) }],
    ['merkleRoot', { merkleRoot: '0x' + 'g'.repeat(64) }],
    ['txHash', { txHash: '0x' + 'b'.repeat(65) }],
    ['txHash', { txHash: '' }],
    ['status', { status: 'done' }],
  ] as const)('reports invalid %s for %j', (field, override) => {
    expect(validateCreateInput({ ...makeCreateInput(), ...override })).toEqual([field]);
  });

  it('reports every missing field deterministically', () => {
    expect(validateCreateInput({})).toEqual(['businessId', 'period', 'merkleRoot', 'txHash', 'status']);
  });

  it('rejects invalid shapes at compile time', () => {
    // @ts-expect-error - status must be an AttestationStatus
    const badStatus: CreateAttestationInput = { ...makeCreateInput(), status: 'done' };
    // @ts-expect-error - txHash is required
    const missingTx: CreateAttestationInput = {
      businessId: 'b',
      period: '2025-10',
      merkleRoot: '0x',
      status: 'pending',
    };
    expect(validateCreateInput({ ...badStatus })).toEqual(['status']);
    expect(validateCreateInput({ ...missingTx })).toContain('txHash');
  });
});

// ---------------------------------------------------------------------------
// Lifecycle transitions
// ---------------------------------------------------------------------------

describe('Attestation lifecycle transitions', () => {
  it('defines transitions for every status', () => {
    expect(Object.keys(TRANSITIONS).sort()).toEqual([...ALL_STATUSES].sort());
    for (const targets of Object.values(TRANSITIONS)) {
      for (const t of targets) expect(isAttestationStatus(t)).toBe(true);
    }
  });

  it('walks the happy path pending -> submitted -> confirmed, bumping version', () => {
    const later = new Date('2025-10-02T00:00:00.000Z');
    const pending = makeAttestation();
    const submitted = transition(pending, 'submitted', 1, later);
    const confirmed = transition(submitted, 'confirmed', 2, later);

    expect(submitted).toMatchObject({ status: 'submitted', version: 2 });
    expect(confirmed).toMatchObject({ status: 'confirmed', version: 3 });
    expect(confirmed.updatedAt).toEqual(later);
    expect(confirmed.createdAt).toEqual(FIXED_DATE);
    // Original record is not mutated
    expect(pending).toMatchObject({ status: 'pending', version: 1 });
  });

  it('allows failure from pending and submitted', () => {
    expect(transition(makeAttestation(), 'failed').status).toBe('failed');
    expect(transition(makeAttestation({ status: 'submitted' }), 'failed').status).toBe('failed');
  });

  it('allows revocation of a confirmed attestation', () => {
    expect(transition(makeAttestation({ status: 'confirmed' }), 'revoked').status).toBe('revoked');
  });

  it.each([
    ['pending', 'confirmed'],
    ['pending', 'revoked'],
    ['submitted', 'pending'],
    ['confirmed', 'pending'],
    ['confirmed', 'failed'],
    ['failed', 'pending'],
    ['revoked', 'confirmed'],
  ] as const)('rejects illegal transition %s -> %s', (from, to) => {
    expect(() => transition(makeAttestation({ status: from }), to)).toThrow(
      `Illegal transition: ${from} -> ${to}`,
    );
  });

  it.each(['failed', 'revoked'] as const)('treats %s as terminal', (status) => {
    for (const next of ALL_STATUSES) {
      expect(() => transition(makeAttestation({ status }), next)).toThrow(/Illegal transition/);
    }
  });

  it('rejects an unknown target status', () => {
    expect(() => transition(makeAttestation(), 'bogus' as AttestationStatus)).toThrow('Invalid status: bogus');
  });

  it('raises a VERSION_MISMATCH ConflictError on stale version', () => {
    const record = makeAttestation({ version: 3 });
    let caught: unknown;
    try {
      transition(record, 'submitted', 2);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConflictError);
    expect(caught).toMatchObject({
      name: 'ConflictError',
      type: ConflictErrorType.CONFLICT_TYPE_VERSION,
      status: 409,
      details: { id: record.id, expectedVersion: 2, actualVersion: 3 },
    });
  });
});

// ---------------------------------------------------------------------------
// ConflictErrorType / ConflictError / createConflictError
// ---------------------------------------------------------------------------

describe('ConflictErrorType', () => {
  it('exposes stable string values', () => {
    expect(ConflictErrorType.CONFLICT_TYPE_DUPLICATE).toBe('DUPLICATE');
    expect(ConflictErrorType.CONFLICT_TYPE_VERSION).toBe('VERSION_MISMATCH');
    expect(ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY).toBe('FOREIGN_KEY_VIOLATION');
    expect(ConflictErrorType.CONFLICT_TYPE_NOT_FOUND).toBe('NOT_FOUND');
    expect(Object.values(ConflictErrorType)).toHaveLength(4);
  });
});

describe('ConflictError', () => {
  it.each(Object.values(ConflictErrorType))('constructs a 409 error for %s', (type) => {
    const err = new ConflictError(type, 'boom', { a: 1 });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ConflictError);
    expect(err.name).toBe('ConflictError');
    expect(err.message).toBe('boom');
    expect(err.type).toBe(type);
    expect(err.status).toBe(409);
    expect(err.details).toEqual({ a: 1 });
    expect(err.stack).toBeTypeOf('string');
  });

  it('defaults details to an empty object', () => {
    const err = new ConflictError(ConflictErrorType.CONFLICT_TYPE_NOT_FOUND, 'missing');
    expect(err.details).toEqual({});
  });

  it('does not share default details between instances', () => {
    const a = new ConflictError(ConflictErrorType.CONFLICT_TYPE_NOT_FOUND, 'a');
    const b = new ConflictError(ConflictErrorType.CONFLICT_TYPE_NOT_FOUND, 'b');
    expect(a.details).not.toBe(b.details);
  });

  it('accepts an empty message (boundary)', () => {
    const err = new ConflictError(ConflictErrorType.CONFLICT_TYPE_DUPLICATE, '');
    expect(err.message).toBe('');
  });

  it('is catchable by type discriminator', () => {
    const run = () => {
      throw new ConflictError(ConflictErrorType.CONFLICT_TYPE_DUPLICATE, 'dup');
    };
    expect(run).toThrow(ConflictError);
    expect(run).toThrow('dup');
  });
});

describe('createConflictError', () => {
  it('returns an equivalent ConflictError', () => {
    const details = { businessId: 'b', period: '2025-10' };
    const err = createConflictError(ConflictErrorType.CONFLICT_TYPE_DUPLICATE, 'exists', details);
    expect(err).toBeInstanceOf(ConflictError);
    expect(err).toMatchObject({
      name: 'ConflictError',
      type: 'DUPLICATE',
      message: 'exists',
      status: 409,
      details,
    });
  });

  it('defaults details to an empty object', () => {
    expect(createConflictError(ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY, 'fk').details).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// ReadConsistency
// ---------------------------------------------------------------------------

describe('ReadConsistency', () => {
  it('exposes local and strong levels', () => {
    expect(ReadConsistency.LOCAL).toBe('local');
    expect(ReadConsistency.STRONG).toBe('strong');
    expect(Object.values(ReadConsistency)).toEqual(['local', 'strong']);
  });
});
