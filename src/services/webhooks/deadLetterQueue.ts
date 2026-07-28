import crypto from 'node:crypto'
import { db } from '../../db/client.js'

export const MAX_PAYLOAD_SIZE = 100 * 1024 // 100KB
export const DEFAULT_QUARANTINE_THRESHOLD = 3

export interface QuarantinedLetter {
  id?: number
  provider: string
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
  threshold: number = DEFAULT_QUARANTINE_THRESHOLD
): Promise<{ status: 'saved' | 'quarantined'; attemptCount: number; fingerprint: string }> {
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
      `INSERT INTO webhook_quarantine (provider, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'poison_pill_threshold_exceeded', NOW())
       ON CONFLICT (provider, event_id)
       DO UPDATE SET
         attempt_count = EXCLUDED.attempt_count,
         fingerprint = EXCLUDED.fingerprint,
         quarantined_at = NOW()`,
      [provider, eventId, payloadHash, errorCode, fingerprint, effectiveAttempts]
    )

    return { status: 'quarantined', attemptCount: effectiveAttempts, fingerprint }
  }

  await db.query(
    `INSERT INTO webhook_dead_letters (provider, event_id, payload_hash, error_code, attempt_count, updated_at)
     VALUES ($1, $2, $3, $4, 1, NOW())
     ON CONFLICT (provider, event_id)
     DO UPDATE SET
       attempt_count = webhook_dead_letters.attempt_count + 1,
       error_code = EXCLUDED.error_code,
       updated_at = NOW()`,
    [provider, eventId, payloadHash, errorCode]
  )

  return { status: 'saved', attemptCount: effectiveAttempts, fingerprint }
}

export async function getDeadLetter(
  provider: string,
  eventId: string
): Promise<{ payload_hash: string; attempt_count?: number } | null> {
  const result = await db.query(
    'SELECT payload_hash, attempt_count FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  if (!result || (result.rowCount ?? 0) === 0) {
    return null
  }
  return result.rows[0] as { payload_hash: string; attempt_count?: number }
}

export async function deleteDeadLetter(provider: string, eventId: string): Promise<void> {
  await db.query(
    'DELETE FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
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
    'SELECT id, provider, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at, released_at, released_by FROM webhook_quarantine WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  if (!result || (result.rowCount ?? 0) === 0) {
    return null
  }
  return result.rows[0] as QuarantinedLetter
}

export async function listQuarantinedLetters(provider?: string): Promise<QuarantinedLetter[]> {
  if (provider) {
    const result = await db.query(
      'SELECT id, provider, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at, released_at, released_by FROM webhook_quarantine WHERE provider = $1 ORDER BY quarantined_at DESC',
      [provider]
    )
    return (result?.rows ?? []) as QuarantinedLetter[]
  }
  const result = await db.query(
    'SELECT id, provider, event_id, payload_hash, error_code, fingerprint, attempt_count, quarantine_reason, quarantined_at, released_at, released_by FROM webhook_quarantine ORDER BY quarantined_at DESC'
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
