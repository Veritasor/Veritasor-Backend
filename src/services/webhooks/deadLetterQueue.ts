import crypto from 'node:crypto'
import { db } from '../../db/client.js'
import { webhookDlqOldestEntryAge } from '../../metrics.js'

export const MAX_PAYLOAD_SIZE = 100 * 1024 // 100KB

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

export async function saveDeadLetter(
  provider: string,
  eventId: string,
  payload: any,
  error: unknown
): Promise<void> {
  const payloadHash = computePayloadHash(payload)
  const errorCode = error instanceof Error ? (error as any).code ?? error.message : String(error)
  
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
}

export async function getDeadLetter(provider: string, eventId: string): Promise<{ payload_hash: string } | null> {
  const result = await db.query(
    'SELECT payload_hash FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
    [provider, eventId]
  )
  if (!result || (result.rowCount ?? 0) === 0) {
    return null
  }
  return result.rows[0] as { payload_hash: string }
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
