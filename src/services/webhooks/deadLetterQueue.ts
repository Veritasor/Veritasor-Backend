import crypto from 'node:crypto'
import { db } from '../../db/client.js'
import { webhookDlqOldestEntryAge } from '../../metrics.js'

export const MAX_PAYLOAD_SIZE = 100 * 1024 // 100KB

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
