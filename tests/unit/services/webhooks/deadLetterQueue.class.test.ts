/**
 * Regression suite for DeadLetterQueue class failure handling (#1017)
 *
 * Exercises the explicit throw branches in:
 *   - archiveEntry   (line ~172: entry not found, line ~176: already archived)
 *   - restoreEntry   (line ~205: entry not found, ~210: not archived, ~215: no archive location)
 *
 * Also covers the neighbouring success paths and boundary inputs so that
 * silent behaviour changes are caught by CI.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ---------------------------------------------------------------------------
// vi.mock factories are hoisted to the top of the file by vitest.
// They must not reference variables declared in module scope — only literal
// vi.fn() / vi.fn().mockXxx() constructs are safe inside the factory.
// ---------------------------------------------------------------------------

// The db export is mocked as a callable (knex-style) function.
// Each test re-programmes it via mockReturnValueOnce().
vi.mock('../../../../src/db/client.js', () => ({
  db: vi.fn(),
}))

// S3Client is used as a constructor (new S3Client(…)) so we need a class mock.
vi.mock('@aws-sdk/client-s3', () => ({
  S3Client: vi.fn(),
  PutObjectCommand: vi.fn(),
  GetObjectCommand: vi.fn(),
}))

// KMSClient is used as a constructor (new KMSClient(…)) so we need a class mock.
vi.mock('@aws-sdk/client-kms', () => ({
  KMSClient: vi.fn(),
  EncryptCommand: vi.fn(),
  DecryptCommand: vi.fn(),
}))

vi.mock('../../../../src/utils/logger.js', () => ({
  Logger: vi.fn().mockImplementation(function () {
    return {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }
  }),
}))

// ---------------------------------------------------------------------------
// Imports — must come after vi.mock() registrations.
// ---------------------------------------------------------------------------
import { DeadLetterQueue } from '../../../../src/services/webhooks/deadLetterQueue.js'
import { db as dbImport } from '../../../../src/db/client.js'
import { S3Client } from '@aws-sdk/client-s3'
import { KMSClient } from '@aws-sdk/client-kms'

// Typed convenience aliases.
const db = vi.mocked(dbImport) as ReturnType<typeof vi.fn>
const MockedS3Client = vi.mocked(S3Client)
const MockedKMSClient = vi.mocked(KMSClient)

// ---------------------------------------------------------------------------
// Builder factory
//
// DeadLetterQueue uses the knex-style pattern:
//   db('table').where(...).first()   → Promise<row | undefined>
//   db('table').where(...).update({}) → Promise<number>
//   await db('table').where(...).limit(n) → Promise<row[]>   (no .first())
//
// We create a fresh builder per call so tests are fully isolated.
// Crucially we do NOT add a `.then` method: adding `.then` makes the object
// a "thenable" which confuses Promise resolution.
// ---------------------------------------------------------------------------

function makeBuilder(firstResult: unknown, arrayResult: unknown[] = []) {
  const builder: Record<string, ReturnType<typeof vi.fn>> = {}

  // Chain methods return `this` so calls can be chained arbitrarily.
  for (const m of ['where', 'select', 'count', 'orderBy', 'limit', 'offset', 'clone']) {
    builder[m] = vi.fn().mockReturnThis()
  }

  // Terminal methods return Promises.
  builder.first = vi.fn().mockResolvedValue(firstResult)
  builder.update = vi.fn().mockResolvedValue(1)

  // When the builder is awaited directly (no terminal call), return arrayResult.
  // We achieve this by making the builder itself a Promise-like via a custom
  // Symbol.toStringTag but NOT adding .then — instead we use a Proxy so that
  // awaiting the builder works only when the test needs it.
  // For simplicity we skip that complexity: the only "awaited directly" usage
  // is in archiveOldEntries which we don't cover here.

  return builder
}

// ---------------------------------------------------------------------------
// Minimal DLQEntry row as returned by the database.
// ---------------------------------------------------------------------------
function makeDbEntry(overrides: Record<string, unknown> = {}) {
  return {
    id: 'entry-001',
    type: 'payment.failed',
    payload: { amount: 100 },
    error: 'timeout',
    attempts: 1,
    created_at: new Date('2026-01-01T00:00:00Z'),
    updated_at: new Date('2026-01-02T00:00:00Z'),
    archived: false,
    archive_location: null,
    archive_encrypted: false,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// EventEmitter stream compatible with the private `streamToBuffer` helper.
// ---------------------------------------------------------------------------
function makeReadableStream(data: Buffer) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const EventEmitter = require('events').EventEmitter
  const stream = new EventEmitter()
  process.nextTick(() => {
    stream.emit('data', data)
    stream.emit('end')
  })
  return stream
}

// ---------------------------------------------------------------------------
// Per-test setup: fresh DLQ instance with controlled AWS client spies.
// ---------------------------------------------------------------------------
let dlq: DeadLetterQueue
let s3Send: ReturnType<typeof vi.fn>
let kmsSend: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.clearAllMocks()

  s3Send = vi.fn().mockResolvedValue({})
  kmsSend = vi.fn().mockResolvedValue({})

  // Use `function` keyword so vitest treats these as proper constructors.
  MockedS3Client.mockImplementation(function (this: any) {
    this.send = s3Send
  } as any)
  MockedKMSClient.mockImplementation(function (this: any) {
    this.send = kmsSend
  } as any)

  // No KMS key → encryptEntry falls back to plain Buffer.from(json).
  delete process.env.DLQ_ARCHIVE_KMS_KEY_ID

  dlq = new DeadLetterQueue()
})

// ===========================================================================
// archiveEntry — failure paths (the regression branches from #1017)
// ===========================================================================

describe('DeadLetterQueue.archiveEntry', () => {

  // ── regression branch: line ~172 ─────────────────────────────────────
  it('throws "not found" when the entry does not exist', async () => {
    db.mockReturnValueOnce(makeBuilder(undefined))

    await expect(dlq.archiveEntry('missing-id')).rejects.toThrow(
      'DLQ entry missing-id not found',
    )
  })

  // ── regression branch: line ~176 ─────────────────────────────────────
  it('throws "already archived" when the entry is already archived', async () => {
    db.mockReturnValueOnce(
      makeBuilder(makeDbEntry({ archived: true, archive_location: 's3://b/k.enc' })),
    )

    await expect(dlq.archiveEntry('entry-001')).rejects.toThrow(
      'DLQ entry entry-001 already archived',
    )
  })

  // ── success path ─────────────────────────────────────────────────────
  it('returns an s3:// URL when the entry exists and is not yet archived', async () => {
    db.mockReturnValueOnce(makeBuilder(makeDbEntry({ archived: false }))) // SELECT
    db.mockReturnValueOnce(makeBuilder(undefined))                        // UPDATE

    const result = await dlq.archiveEntry('entry-001')

    expect(result).toMatch(/^s3:\/\//)
    expect(s3Send).toHaveBeenCalledTimes(1)
  })

  // ── boundary: empty string entry ID ──────────────────────────────────
  it('throws "not found" for an empty-string entry ID', async () => {
    db.mockReturnValueOnce(makeBuilder(undefined))

    await expect(dlq.archiveEntry('')).rejects.toThrow('DLQ entry  not found')
  })

  // ── boundary: null payload ────────────────────────────────────────────
  it('archives an entry whose payload is null without throwing', async () => {
    db.mockReturnValueOnce(makeBuilder(makeDbEntry({ archived: false, payload: null })))
    db.mockReturnValueOnce(makeBuilder(undefined))

    const result = await dlq.archiveEntry('entry-001')
    expect(result).toMatch(/^s3:\/\//)
  })
})

// ===========================================================================
// restoreEntry — failure paths (the regression branches from #1017)
// ===========================================================================

describe('DeadLetterQueue.restoreEntry', () => {

  // ── regression branch: line ~205 ─────────────────────────────────────
  it('throws "not found" when the entry does not exist', async () => {
    db.mockReturnValueOnce(makeBuilder(undefined))

    await expect(dlq.restoreEntry('ghost-id')).rejects.toThrow(
      'DLQ entry ghost-id not found',
    )
  })

  // ── regression branch: "is not archived" ────────────────────────────
  it('throws "is not archived" when the entry has never been archived', async () => {
    db.mockReturnValueOnce(makeBuilder(makeDbEntry({ archived: false })))

    await expect(dlq.restoreEntry('entry-001')).rejects.toThrow(
      'DLQ entry entry-001 is not archived',
    )
  })

  // ── regression branch: "has no archive location" ─────────────────────
  it('throws "has no archive location" when archived but location is null', async () => {
    db.mockReturnValueOnce(
      makeBuilder(makeDbEntry({ archived: true, archive_location: null })),
    )

    await expect(dlq.restoreEntry('entry-001')).rejects.toThrow(
      'DLQ entry entry-001 has no archive location',
    )
  })

  // ── success path ─────────────────────────────────────────────────────
  it('returns a DLQEntry with archived=false on a successful restore', async () => {
    const archivedEntry = makeDbEntry({
      archived: true,
      archive_location: 's3://veritasor-dlq-archive/dlq/2026-01-01/uuid.enc',
      archive_encrypted: false,
    })

    const stored = JSON.stringify({
      id: 'entry-001',
      type: 'payment.failed',
      payload: { amount: 100 },
      error: 'timeout',
      attempts: 2,
      created_at: new Date('2026-01-01').toISOString(),
      updated_at: new Date('2026-01-02').toISOString(),
    })

    db.mockReturnValueOnce(makeBuilder(archivedEntry)) // SELECT
    db.mockReturnValueOnce(makeBuilder(undefined))      // UPDATE

    s3Send.mockResolvedValueOnce({ Body: makeReadableStream(Buffer.from(stored)) })

    const restored = await dlq.restoreEntry('entry-001')

    expect(restored.archived).toBe(false)
    expect(restored.archive_location).toBeNull()
    expect(restored.id).toBe('entry-001')
    expect(restored.attempts).toBe(2)
  })

  // ── success path with requeue ─────────────────────────────────────────
  it('completes without throwing when restoreToQueue is true', async () => {
    const archivedEntry = makeDbEntry({
      archived: true,
      archive_location: 's3://veritasor-dlq-archive/dlq/2026-01-01/uuid.enc',
      archive_encrypted: false,
    })

    const stored = JSON.stringify({
      id: 'entry-001',
      type: 'payment.failed',
      payload: { amount: 100 },
      error: 'timeout',
      attempts: 1,
      created_at: new Date('2026-01-01').toISOString(),
      updated_at: new Date('2026-01-02').toISOString(),
    })

    db.mockReturnValueOnce(makeBuilder(archivedEntry))
    db.mockReturnValueOnce(makeBuilder(undefined))
    s3Send.mockResolvedValueOnce({ Body: makeReadableStream(Buffer.from(stored)) })

    const restored = await dlq.restoreEntry('entry-001', {
      entryId: 'entry-001',
      restoreToQueue: true,
    })

    expect(restored.archived).toBe(false)
  })

  // ── boundary: empty string entry ID ──────────────────────────────────
  it('throws "not found" for an empty-string entry ID', async () => {
    db.mockReturnValueOnce(makeBuilder(undefined))

    await expect(dlq.restoreEntry('')).rejects.toThrow('DLQ entry  not found')
  })

  // ── boundary: empty-string archive_location (falsy but not null) ──────
  it('throws "has no archive location" when archive_location is an empty string', async () => {
    db.mockReturnValueOnce(
      makeBuilder(makeDbEntry({ archived: true, archive_location: '' })),
    )

    await expect(dlq.restoreEntry('entry-001')).rejects.toThrow(
      'DLQ entry entry-001 has no archive location',
    )
  })
})

// ===========================================================================
// Error contract: all thrown messages must include the entry ID
// ===========================================================================

describe('Error contract — thrown messages include the entry ID', () => {
  const ID = 'trace-id-777'

  it('archiveEntry "not found" contains the entry ID', async () => {
    db.mockReturnValueOnce(makeBuilder(undefined))
    const err = await dlq.archiveEntry(ID).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toContain(ID)
  })

  it('archiveEntry "already archived" contains the entry ID', async () => {
    db.mockReturnValueOnce(makeBuilder(makeDbEntry({ id: ID, archived: true })))
    const err = await dlq.archiveEntry(ID).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toContain(ID)
  })

  it('restoreEntry "not found" contains the entry ID', async () => {
    db.mockReturnValueOnce(makeBuilder(undefined))
    const err = await dlq.restoreEntry(ID).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toContain(ID)
  })

  it('restoreEntry "is not archived" contains the entry ID', async () => {
    db.mockReturnValueOnce(makeBuilder(makeDbEntry({ id: ID, archived: false })))
    const err = await dlq.restoreEntry(ID).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toContain(ID)
  })

  it('restoreEntry "has no archive location" contains the entry ID', async () => {
    db.mockReturnValueOnce(
      makeBuilder(makeDbEntry({ id: ID, archived: true, archive_location: null })),
    )
    const err = await dlq.restoreEntry(ID).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toContain(ID)
  })
})
