import crypto from 'node:crypto'
import { db } from '../../db/client.js'

export const MAX_PAYLOAD_SIZE = 100 * 1024 // 100KB
export const DEFAULT_QUARANTINE_THRESHOLD = 3
export const UNKNOWN_INTEGRATION_SHARD = 'unknown'

export interface DeadLetterEntry {
  id?: number
  provider: string
  integration: string
  event_id: string
  payload_hash: string
  error_code: string
  attempt_count: number
  created_at?: Date
  updated_at?: Date
}

export interface QuarantinedLetter {
  id?: number
  provider: string
  integration: string
  event_id: string
  payload_hash: string
  error_code: string
  fingerprint: string
  attempt_count: number
  quarantine_reason?: string
  quarantined_at?: Date
  released_at?: Date | null
  released_by?: string | null
}

export interface DLQWorkerResult {
  processed: number
  succeeded: number
  failed: number
  errors: Array<{ eventId: string; error: string }>
}

export function resolveIntegrationShard(provider?: string, integration?: string): string {
  if (integration && typeof integration === 'string' && integration.trim().length > 0) {
    return integration.trim().toLowerCase()
  }
  if (provider && typeof provider === 'string' && provider.trim().length > 0) {
    return provider.trim().toLowerCase()
  }
  return UNKNOWN_INTEGRATION_SHARD
}

export function computePayloadHash(payload: any): string {
  const rawString = typeof payload === 'string' ? payload : JSON.stringify(payload)

  if (Buffer.byteLength(rawString) > MAX_PAYLOAD_SIZE) {
    throw new Error('Payload too large')
  }

  return crypto.createHash('sha256').update(rawString).digest('hex')
}

export function computeFailureFingerprint(
  provider: string,
  payloadHash: string,
  errorCode: string
): string {
  const rawString = `${provider}:${payloadHash}:${errorCode}`
  return crypto.createHash('sha256').update(rawString).digest('hex')
}

export function resolveFingerprintCollision(
  fingerprint: string,
  storedPayloadHash: string | null,
  currentPayloadHash: string
): string {
  if (storedPayloadHash && storedPayloadHash !== currentPayloadHash) {
    return crypto
      .createHash('sha256')
      .update(`${fingerprint}:${currentPayloadHash}`)
      .digest('hex')
  }
  return fingerprint
}

export async function getFingerprintCount(fingerprint: string): Promise<number> {
  const result = await db.query(
    'SELECT failure_count FROM webhook_failure_fingerprints WHERE fingerprint = $1',
    [fingerprint]
  )
  if (!result || (result.rowCount ?? 0) === 0) {
    return 0
  }
  return Number(result.rows[0].failure_count ?? 0)
}

export async function saveDeadLetter(
  provider: string,
  eventId: string,
  payload: any,
  error: unknown,
  threshold: number = DEFAULT_QUARANTINE_THRESHOLD,
  integration?: string
): Promise<{ status: 'saved' | 'quarantined'; attemptCount: number; fingerprint: string; integration: string }> {
  const shard = resolveIntegrationShard(provider, integration)
  const payloadHash = computePayloadHash(payload)
  const errorCode = error instanceof Error ? (error as any).code ?? error.message : String(error)
  const rawFingerprint = computeFailureFingerprint(provider, payloadHash, errorCode)

  let fingerprint = rawFingerprint
  let fingerprintCount = 1

  const fpCheck = await db.query(
    'SELECT payload_hash, failure_count FROM webhook_failure_fingerprints WHERE fingerprint = $1',
    [rawFingerprint]
  )

  if (fpCheck && (fpCheck.rowCount ?? 0) > 0 && fpCheck.rows[0]) {
    const existing = fpCheck.rows[0]
    if (existing.payload_hash && existing.payload_hash !== payloadHash) {
      // Fingerprint collision detected -> resolve collision using collision guard
      fingerprint = resolveFingerprintCollision(rawFingerprint, existing.payload_hash, payloadHash)
      const saltedCheck = await db.query(
        'SELECT failure_count FROM webhook_failure_fingerprints WHERE fingerprint = $1',
        [fingerprint]
      )
      if (saltedCheck && (saltedCheck.rowCount ?? 0) > 0 && saltedCheck.rows[0]) {
        fingerprintCount = Number(saltedCheck.rows[0].failure_count) + 1
      }
    } else {
      fingerprintCount = Number(existing.failure_count ?? 0) + 1
    }
  }

  await db.query(
    `INSERT INTO webhook_failure_fingerprints (fingerprint, provider, payload_hash, error_code, failure_count, first_seen_at, last_seen_at)
     VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
     ON CONFLICT (fingerprint)
     DO UPDATE SET
       failure_count = EXCLUDED.failure_count,
       last_seen_at = NOW()`,
    [fingerprint, provider, payloadHash, errorCode, fingerprintCount]
  )

  const dlCheck = await db.query(
    'SELECT attempt_count FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  const currentAttempts = dlCheck && (dlCheck.rowCount ?? 0) > 0 && dlCheck.rows[0]
    ? Number(dlCheck.rows[0].attempt_count) + 1
    : 1
  const effectiveAttempts = Math.max(currentAttempts, fingerprintCount)

  if (effectiveAttempts >= threshold) {
    await db.query(
      'DELETE FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
      [provider, eventId]
    )

    await db.query(
      `INSERT INTO webhook_quarantine (provider, integration, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'poison_pill_threshold_exceeded', NOW())
       ON CONFLICT (provider, event_id)
       DO UPDATE SET
         attempt_count = EXCLUDED.attempt_count,
         fingerprint = EXCLUDED.fingerprint,
         integration = EXCLUDED.integration,
         quarantined_at = NOW()`,
      [provider, shard, eventId, payloadHash, errorCode, fingerprint, effectiveAttempts]
    )

    return { status: 'quarantined', attemptCount: effectiveAttempts, fingerprint, integration: shard }
  }

  await db.query(
    `INSERT INTO webhook_dead_letters (provider, integration, event_id, payload_hash, error_code, attempt_count, updated_at)
     VALUES ($1, $2, $3, $4, $5, 1, NOW())
     ON CONFLICT (provider, event_id)
     DO UPDATE SET
       attempt_count = webhook_dead_letters.attempt_count + 1,
       error_code = EXCLUDED.error_code,
       integration = EXCLUDED.integration,
       updated_at = NOW()`,
    [provider, shard, eventId, payloadHash, errorCode]
  )

  return { status: 'saved', attemptCount: effectiveAttempts, fingerprint, integration: shard }
}

export async function getDeadLetter(
  provider: string,
  eventId: string
): Promise<DeadLetterEntry | null> {
  const result = await db.query(
    'SELECT id, provider, integration, event_id, payload_hash, error_code, attempt_count, created_at, updated_at FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  if (!result || (result.rowCount ?? 0) === 0) {
    return null
  }
  return result.rows[0] as DeadLetterEntry
}

export async function deleteDeadLetter(provider: string, eventId: string): Promise<void> {
  await db.query(
    'DELETE FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
}

export async function getDeadLettersByShard(
  integration: string,
  limit: number = 50
): Promise<DeadLetterEntry[]> {
  const shard = resolveIntegrationShard(undefined, integration)
  const result = await db.query(
    'SELECT id, provider, integration, event_id, payload_hash, error_code, attempt_count, created_at, updated_at FROM webhook_dead_letters WHERE integration = $1 ORDER BY created_at ASC LIMIT $2',
    [shard, limit]
  )
  return (result?.rows ?? []) as DeadLetterEntry[]
}

export async function listDeadLetterShards(): Promise<{ integration: string; count: number }[]> {
  const result = await db.query(
    'SELECT integration, COUNT(*)::int AS count FROM webhook_dead_letters GROUP BY integration ORDER BY count DESC'
  )
  return (result?.rows ?? []) as { integration: string; count: number }[]
}

export class DLQShardWorker {
  public readonly integration: string

  constructor(
    integration: string,
    private readonly handler: (entry: DeadLetterEntry) => Promise<boolean>
  ) {
    this.integration = resolveIntegrationShard(undefined, integration)
  }

  public async fetchBatch(limit: number = 50): Promise<DeadLetterEntry[]> {
    return getDeadLettersByShard(this.integration, limit)
  }

  public async processBatch(limit: number = 50): Promise<DLQWorkerResult> {
    const entries = await this.fetchBatch(limit)
    const result: DLQWorkerResult = {
      processed: entries.length,
      succeeded: 0,
      failed: 0,
      errors: [],
    }

    for (const entry of entries) {
      try {
        const success = await this.handler(entry)
        if (success) {
          await deleteDeadLetter(entry.provider, entry.event_id)
          result.succeeded++
        } else {
          result.failed++
          result.errors.push({
            eventId: entry.event_id,
            error: 'Handler returned false',
          })
        }
      } catch (err: any) {
        result.failed++
        result.errors.push({
          eventId: entry.event_id,
          error: err instanceof Error ? err.message : String(err),
        })
      }
    }

    return result
  }
}

export function createDLQShardWorker(
  integration: string,
  handler: (entry: DeadLetterEntry) => Promise<boolean>
): DLQShardWorker {
  return new DLQShardWorker(integration, handler)
}

export async function isQuarantined(provider: string, eventId: string): Promise<boolean> {
  const result = await db.query(
    'SELECT 1 FROM webhook_quarantine WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  return Boolean(result && (result.rowCount ?? 0) > 0)
}

export async function getQuarantinedLetter(
  provider: string,
  eventId: string
): Promise<QuarantinedLetter | null> {
  const result = await db.query(
    'SELECT id, provider, integration, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at, released_at, released_by FROM webhook_quarantine WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  if (!result || (result.rowCount ?? 0) === 0) {
    return null
  }
  return result.rows[0] as QuarantinedLetter
}

export async function listQuarantinedLetters(
  provider?: string,
  integration?: string
): Promise<QuarantinedLetter[]> {
  if (integration) {
    const shard = resolveIntegrationShard(undefined, integration)
    const result = await db.query(
      'SELECT id, provider, integration, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at, released_at, released_by FROM webhook_quarantine WHERE integration = $1 ORDER BY quarantined_at DESC',
      [shard]
    )
    return (result?.rows ?? []) as QuarantinedLetter[]
  }
  if (provider) {
    const result = await db.query(
      'SELECT id, provider, integration, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at, released_at, released_by FROM webhook_quarantine WHERE provider = $1 ORDER BY quarantined_at DESC',
      [provider]
    )
    return (result?.rows ?? []) as QuarantinedLetter[]
  }
  const result = await db.query(
    'SELECT id, provider, integration, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at, released_at, released_by FROM webhook_quarantine ORDER BY quarantined_at DESC'
  )
  return (result?.rows ?? []) as QuarantinedLetter[]
}

export async function releaseQuarantinedLetter(
  provider: string,
  eventId: string,
  releasedBy?: string
): Promise<boolean> {
  const existing = await getQuarantinedLetter(provider, eventId)
  if (!existing) {
    return false
  }

  await db.query(
    'DELETE FROM webhook_quarantine WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )

  await db.query(
    'DELETE FROM webhook_failure_fingerprints WHERE fingerprint = $1',
    [existing.fingerprint]
  )

  return true
}

export async function purgeQuarantinedLetter(provider: string, eventId: string): Promise<boolean> {
  const result = await db.query(
    'DELETE FROM webhook_quarantine WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  return (result?.rowCount ?? 0) > 0
}
