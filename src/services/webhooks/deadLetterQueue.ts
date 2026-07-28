import crypto from 'node:crypto'
import { db } from '../../db/client.js'
import { webhookDlqOldestEntryAge } from '../../metrics.js'

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

export interface DlqBackpressureState {
  tokens: number;
  pauseUntil: number;
}

const backpressureMap = new Map<string, DlqBackpressureState>();

export function getBackpressureState(provider: string): DlqBackpressureState {
  let state = backpressureMap.get(provider);
  if (!state) {
    state = { tokens: 100, pauseUntil: 0 };
    backpressureMap.set(provider, state);
  }
  return state;
}

export function updateRateLimitFromHeaders(
  provider: string,
  headers: Record<string, string>,
  statusCode: number
): void {
  const state = getBackpressureState(provider);
  
  const getHeader = (name: string): string | null => {
    const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
    return key ? headers[key] : null;
  }

  const retryAfter = getHeader('retry-after');
  if (statusCode === 429 && retryAfter) {
    let delayMs = 0;
    if (!isNaN(Number(retryAfter))) {
      delayMs = Number(retryAfter) * 1000;
    } else {
      const date = new Date(retryAfter).getTime();
      if (!isNaN(date)) {
        delayMs = Math.max(0, date - Date.now());
      }
    }
    if (delayMs > 0) {
      state.pauseUntil = Date.now() + delayMs;
      state.tokens = 0;
      return;
    }
  }

  if (statusCode === 429) {
    state.pauseUntil = Date.now() + 60000; // Default 1 min pause
    state.tokens = 0;
    return;
  }

  const remaining = getHeader('x-ratelimit-remaining') || getHeader('ratelimit-remaining');
  if (remaining) {
    const r = parseInt(remaining, 10);
    if (!isNaN(r)) {
      state.tokens = r;
      if (r <= 0) {
        const reset = getHeader('x-ratelimit-reset') || getHeader('ratelimit-reset');
        if (reset) {
          const resetTime = parseInt(reset, 10);
          if (!isNaN(resetTime)) {
            const resetMs = resetTime < 1e10 ? resetTime * 1000 : resetTime;
            state.pauseUntil = resetMs;
          }
        }
      }
    }
  }
}

export async function acquireReplayPermit(provider: string): Promise<void> {
  const state = getBackpressureState(provider);

  while (true) {
    const now = Date.now();
    
    if (now < state.pauseUntil) {
      const delay = state.pauseUntil - now;
      await new Promise(resolve => setTimeout(resolve, delay));
      continue;
    }

    if (state.tokens <= 0) {
      state.tokens = 1; 
    }

    state.tokens--;
    return;
  }
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

export async function scanOldestDlqEntryAge(): Promise<void> {
  const result = await db.query(
    `SELECT provider, EXTRACT(EPOCH FROM (NOW() - MIN(updated_at))) as age_seconds
     FROM webhook_dead_letters
     GROUP BY provider`
  )

  webhookDlqOldestEntryAge.reset()
  if (result && result.rows) {
    for (const row of result.rows) {
      webhookDlqOldestEntryAge.labels(row.provider).set(Number(row.age_seconds))
    }
  }
}

export interface DlqAgeScannerHandle {
  stop: () => void;
}

export function startDlqAgeScanner(intervalMs = 60_000): DlqAgeScannerHandle {
  scanOldestDlqEntryAge().catch((err) => {
    console.warn(`[DLQ Scanner] Initial scan failed: ${err instanceof Error ? err.message : String(err)}`)
  })
  
  const timer = setInterval(() => {
    scanOldestDlqEntryAge().catch((err) => {
      console.warn(`[DLQ Scanner] Periodic scan failed: ${err instanceof Error ? err.message : String(err)}`)
    })
  }, intervalMs)
  
  timer.unref()

  return {
    stop: () => clearInterval(timer)
  }
}
