import { db } from '../../db/client.js';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { randomUUID, createHash } from 'crypto';
import { Logger } from '../../utils/logger';

export interface DeadLetter {
  id: number;
  provider: string;
  event_id: string;
  payload_hash: string;
  error_code: string;
  attempt_count: number;
  created_at: Date;
  updated_at: Date;
  integration: string;
}

export interface QuarantinedLetter {
  id: number;
  provider: string;
  event_id: string;
  payload_hash: string;
  error_code: string;
  fingerprint: string;
  attempt_count: number;
  quarantine_reason: string;
  quarantined_at: Date;
  released_at: Date | null;
  released_by: string | null;
  integration: string;
}

export interface DeadLetterShard {
  integration: string;
  count: number;
}

interface DLQEntry {
  id: string;
  type: string;
  payload: any;
  error: string;
  attempts: number;
  created_at: Date;
  updated_at: Date;
  archived: boolean;
  archive_location?: string;
  archive_encrypted?: boolean;
}

interface ArchiveOptions {
  ttlDays?: number;
  batchSize?: number;
  archiveBucket?: string;
  archivePrefix?: string;
}

interface RestoreOptions {
  entryId: string;
  restoreToQueue?: boolean;
}

export class DeadLetterQueue {
  private s3Client: S3Client;
  private kmsClient: KMSClient;
  private logger: Logger;
  private config: {
    bucket: string;
    prefix: string;
    ttlDays: number;
    batchSize: number;
    kmsKeyId: string;
  };

  constructor() {
    this.s3Client = new S3Client({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.kmsClient = new KMSClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.logger = new Logger('DLQ');
    this.config = {
      bucket: process.env.DLQ_ARCHIVE_BUCKET || 'veritasor-dlq-archive',
      prefix: process.env.DLQ_ARCHIVE_PREFIX || 'dlq/',
      ttlDays: parseInt(process.env.DLQ_TTL_DAYS || '30', 10),
      batchSize: parseInt(process.env.DLQ_ARCHIVE_BATCH_SIZE || '100', 10),
      kmsKeyId: process.env.DLQ_ARCHIVE_KMS_KEY_ID || '',
    };
  }

  /**
   * Get DLQ entries with pagination
   */
  async getEntries(options: {
    page?: number;
    pageSize?: number;
    type?: string;
    archived?: boolean;
    startDate?: Date;
    endDate?: Date;
  }): Promise<{ entries: DLQEntry[]; total: number }> {
    const { page = 1, pageSize = 50, type, archived, startDate, endDate } = options;
    const offset = (page - 1) * pageSize;

    let query = db('dead_letter_queue')
      .select('*');

    if (type) {
      query = query.where('type', type);
    }

    if (archived !== undefined) {
      query = query.where('archived', archived);
    }

    if (startDate) {
      query = query.where('created_at', '>=', startDate);
    }

    if (endDate) {
      query = query.where('created_at', '<=', endDate);
    }

    const countResult = await query.clone().count('* as total').first();
    const total = parseInt(countResult?.total || '0', 10);

    const entries = await query
      .orderBy('created_at', 'desc')
      .limit(pageSize)
      .offset(offset);

    return { entries, total };
  }

  /**
   * Archive DLQ entries past TTL
   */
  async archiveOldEntries(options?: ArchiveOptions): Promise<{
    archived: number;
    failed: number;
    total: number;
  }> {
    const ttlDays = options?.ttlDays || this.config.ttlDays;
    const batchSize = options?.batchSize || this.config.batchSize;
    const archiveBucket = options?.archiveBucket || this.config.bucket;
    const archivePrefix = options?.archivePrefix || this.config.prefix;

    this.logger.info(`Starting DLQ archive job (TTL: ${ttlDays} days)`);

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - ttlDays);

    let archived = 0;
    let failed = 0;
    let total = 0;

    // Get entries to archive
    const entries = await db('dead_letter_queue')
      .where('created_at', '<', cutoffDate)
      .where('archived', false)
      .limit(batchSize);

    total = entries.length;

    for (const entry of entries) {
      try {
        const archiveKey = this.generateArchiveKey(entry);
        const encryptedData = await this.encryptEntry(entry);
        const s3Url = await this.uploadToS3(archiveBucket, archiveKey, encryptedData);

        // Update database with archive location
        await db('dead_letter_queue')
          .where('id', entry.id)
          .update({
            archived: true,
            archive_location: s3Url,
            archive_encrypted: true,
            updated_at: new Date(),
          });

        archived++;
        this.logger.debug(`Archived DLQ entry ${entry.id} to ${s3Url}`);
      } catch (error) {
        failed++;
        this.logger.error(`Failed to archive entry ${entry.id}:`, error);
      }
    }

    this.logger.info(`Archive job complete: ${archived} archived, ${failed} failed, ${total} processed`);
    return { archived, failed, total };
  }

  /**
   * Archive a single DLQ entry
   */
  async archiveEntry(entryId: string): Promise<string> {
    const entry = await db('dead_letter_queue')
      .where('id', entryId)
      .first();

    if (!entry) {
      throw new Error(`DLQ entry ${entryId} not found`);
    }

    if (entry.archived) {
      throw new Error(`DLQ entry ${entryId} already archived`);
    }

    const archiveKey = this.generateArchiveKey(entry);
    const encryptedData = await this.encryptEntry(entry);
    const s3Url = await this.uploadToS3(this.config.bucket, archiveKey, encryptedData);

    await db('dead_letter_queue')
      .where('id', entryId)
      .update({
        archived: true,
        archive_location: s3Url,
        archive_encrypted: true,
        updated_at: new Date(),
      });

    this.logger.info(`Archived DLQ entry ${entryId} to ${s3Url}`);
    return s3Url;
  }

  /**
   * Restore a DLQ entry from archive
   */
  async restoreEntry(entryId: string, options: RestoreOptions = {}): Promise<DLQEntry> {
    const entry = await db('dead_letter_queue')
      .where('id', entryId)
      .first();

    if (!entry) {
      throw new Error(`DLQ entry ${entryId} not found`);
    }

    if (!entry.archived) {
      throw new Error(`DLQ entry ${entryId} is not archived`);
    }

    if (!entry.archive_location) {
      throw new Error(`DLQ entry ${entryId} has no archive location`);
    }

    // Decrypt the entry
    const decrypted = await this.downloadAndDecrypt(entry.archive_location);

    const restoredEntry: DLQEntry = {
      ...entry,
      ...decrypted,
      archived: false,
      archive_location: null,
      archive_encrypted: false,
      updated_at: new Date(),
    };

    // Update database
    await db('dead_letter_queue')
      .where('id', entryId)
      .update({
        archived: false,
        archive_location: null,
        archive_encrypted: false,
        payload: decrypted.payload,
        error: decrypted.error,
        attempts: decrypted.attempts || 0,
        updated_at: new Date(),
      });

    // Optionally requeue
    if (options.restoreToQueue) {
      await this.requeue(restoredEntry);
    }

    this.logger.info(`Restored DLQ entry ${entryId}`);
    return restoredEntry;
  }

  /**
   * Get archive statistics
   */
  async getArchiveStats(): Promise<{
    totalArchived: number;
    totalActive: number;
    archiveSizeBytes: number;
    oldestEntry: Date | null;
    newestEntry: Date | null;
  }> {
    const [totalArchivedResult, totalActiveResult] = await Promise.all([
      db('dead_letter_queue').where('archived', true).count('* as total').first(),
      db('dead_letter_queue').where('archived', false).count('* as total').first(),
    ]);

    const [oldestResult, newestResult] = await Promise.all([
      db('dead_letter_queue')
        .where('archived', true)
        .orderBy('created_at', 'asc')
        .select('created_at')
        .first(),
      db('dead_letter_queue')
        .where('archived', true)
        .orderBy('created_at', 'desc')
        .select('created_at')
        .first(),
    ]);

    return {
      totalArchived: parseInt(totalArchivedResult?.total || '0', 10),
      totalActive: parseInt(totalActiveResult?.total || '0', 10),
      archiveSizeBytes: 0, // Would need to calculate from S3
      oldestEntry: oldestResult?.created_at || null,
      newestEntry: newestResult?.created_at || null,
    };
  }

  // ============================================
  // Private Methods
  // ============================================

  private generateArchiveKey(entry: any): string {
    const date = entry.created_at.toISOString().split('T')[0];
    const uuid = randomUUID();
    return `${this.config.prefix}${date}/${uuid}.json.enc`;
  }

  private async encryptEntry(entry: any): Promise<Buffer> {
    const payload = JSON.stringify({
      id: entry.id,
      type: entry.type,
      payload: entry.payload,
      error: entry.error,
      attempts: entry.attempts,
      created_at: entry.created_at,
      updated_at: entry.updated_at,
    });

    if (this.config.kmsKeyId) {
      const command = new EncryptCommand({
        KeyId: this.config.kmsKeyId,
        Plaintext: Buffer.from(payload),
        EncryptionContext: {
          service: 'veritasor',
          component: 'dlq-archive',
        },
      });
      const result = await this.kmsClient.send(command);
      return Buffer.from(result.CiphertextBlob || '');
    }

    // Fallback to base64 encoding if no KMS
    return Buffer.from(payload);
  }

  private async uploadToS3(bucket: string, key: string, data: Buffer): Promise<string> {
    const command = new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: data,
      StorageClass: 'DEEP_ARCHIVE',
      ServerSideEncryption: this.config.kmsKeyId ? 'aws:kms' : 'AES256',
      SSEKMSKeyId: this.config.kmsKeyId || undefined,
      Metadata: {
        'dlq-archived': new Date().toISOString(),
      },
    });

    await this.s3Client.send(command);
    return `s3://${bucket}/${key}`;
  }

  private async downloadAndDecrypt(s3Url: string): Promise<any> {
    const { bucket, key } = this.parseS3Url(s3Url);

    const getCommand = new GetObjectCommand({
      Bucket: bucket,
      Key: key,
    });

    const response = await this.s3Client.send(getCommand);
    const data = await this.streamToBuffer(response.Body);

    let decrypted: Buffer;

    if (this.config.kmsKeyId) {
      const decryptCommand = new DecryptCommand({
        CiphertextBlob: data,
        EncryptionContext: {
          service: 'veritasor',
          component: 'dlq-archive',
        },
      });
      const result = await this.kmsClient.send(decryptCommand);
      decrypted = Buffer.from(result.Plaintext || '');
    } else {
      decrypted = data;
    }

    return JSON.parse(decrypted.toString());
  }

  private parseS3Url(url: string): { bucket: string; key: string } {
    const match = url.match(/^s3:\/\/([^/]+)\/(.+)$/);
    if (!match) {
      throw new Error(`Invalid S3 URL: ${url}`);
    }
    return { bucket: match[1], key: match[2] };
  }

  private async streamToBuffer(stream: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => resolve(Buffer.concat(chunks)));
      stream.on('error', reject);
    });
  }

  private async requeue(entry: DLQEntry): Promise<void> {
    // Implement requeue logic here
    // This would push the entry back to the processing queue
    this.logger.info(`Requeued DLQ entry ${entry.id}`);
  }
}

/**
 * Hash a JSON payload using a stable serialization independent of object key order.
 */
export function computePayloadHash(payload: unknown): string {
  const serialized = JSON.stringify(payload ?? {});
  if (serialized === undefined) {
    throw new TypeError('Payload cannot be serialized as JSON');
  }

  const parsed = JSON.parse(serialized) as unknown;
  const sortObjectKeys = (value: unknown): unknown => {
    if (Array.isArray(value)) {
      return value.map(sortObjectKeys);
    }
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value)
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
          .map(([key, nestedValue]) => [key, sortObjectKeys(nestedValue)]),
      );
    }
    return value;
  };
  const canonicalPayload = JSON.stringify(sortObjectKeys(parsed));
  if (canonicalPayload === undefined) {
    throw new TypeError('Payload cannot be serialized as JSON');
  }

  return createHash('sha256')
    .update(canonicalPayload)
    .digest('hex');
}

export async function getDeadLetter(
  provider: string,
  eventId: string,
): Promise<DeadLetter | null> {
  const result = await db.query<DeadLetter>(
    `SELECT id, provider, event_id, payload_hash, error_code, attempt_count,
            created_at, updated_at, integration
     FROM webhook_dead_letters
     WHERE provider = $1 AND event_id = $2`,
    [provider, eventId],
  );
  return result.rows[0] ?? null;
}

export async function deleteDeadLetter(provider: string, eventId: string): Promise<boolean> {
  const result = await db.query<{ id: number }>(
    `DELETE FROM webhook_dead_letters
     WHERE provider = $1 AND event_id = $2
     RETURNING id`,
    [provider, eventId],
  );
  return result.rows.length > 0;
}

export async function isQuarantined(provider: string, eventId: string): Promise<boolean> {
  const result = await db.query<{ is_quarantined: boolean }>(
    `SELECT EXISTS (
       SELECT 1
       FROM webhook_quarantine
       WHERE provider = $1 AND event_id = $2 AND released_at IS NULL
     ) AS is_quarantined`,
    [provider, eventId],
  );
  return result.rows[0]?.is_quarantined ?? false;
}

export async function listQuarantinedLetters(
  provider?: string,
  integration?: string,
): Promise<QuarantinedLetter[]> {
  const conditions = ['released_at IS NULL'];
  const params: string[] = [];

  if (provider !== undefined) {
    params.push(provider);
    conditions.push(`provider = $${params.length}`);
  }
  if (integration !== undefined) {
    params.push(integration);
    conditions.push(`integration = $${params.length}`);
  }

  const result = await db.query<QuarantinedLetter>(
    `SELECT id, provider, event_id, payload_hash, error_code, fingerprint,
            attempt_count, quarantine_reason, quarantined_at, released_at,
            released_by, integration
     FROM webhook_quarantine
     WHERE ${conditions.join(' AND ')}
     ORDER BY quarantined_at DESC`,
    params,
  );
  return result.rows;
}

export async function releaseQuarantinedLetter(
  provider: string,
  eventId: string,
  releasedBy: string,
): Promise<boolean> {
  const result = await db.query<{ id: number }>(
    `UPDATE webhook_quarantine
     SET released_at = NOW(), released_by = $3
     WHERE provider = $1 AND event_id = $2 AND released_at IS NULL
     RETURNING id`,
    [provider, eventId, releasedBy],
  );
  return result.rows.length > 0;
}

export async function purgeQuarantinedLetter(
  provider: string,
  eventId: string,
): Promise<boolean> {
  const result = await db.query<{ id: number }>(
    `DELETE FROM webhook_quarantine
     WHERE provider = $1 AND event_id = $2
     RETURNING id`,
    [provider, eventId],
  );
  return result.rows.length > 0;
}

export async function listDeadLetterShards(): Promise<DeadLetterShard[]> {
  const result = await db.query<DeadLetterShard>(
    `SELECT integration, COUNT(*)::int AS count
     FROM webhook_dead_letters
     GROUP BY integration
     ORDER BY integration`,
  );
  return result.rows;
}

/**
 * Persist a failed webhook event to the dead-letter table.
 *
 * Captures the raw event id, a SHA-256 hash of the payload body, the error code
 * and the attempt count so operators can later replay the event. Upserts on
 * (provider, event_id) so a retried event increments `attempt_count` rather
 * than creating a duplicate row.
 */
export async function saveDeadLetter(
  provider: string,
  eventId: string,
  payload: unknown,
  error: unknown,
  attempts = 1,
): Promise<void> {
  const payloadHash = computePayloadHash(payload);

  const errorCode =
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof (error as { code?: unknown }).code === 'string'
      ? (error as { code: string }).code
      : error instanceof Error
        ? error.name
        : 'unknown';

  await db('webhook_dead_letters')
    .insert({
      provider,
      event_id: eventId,
      payload_hash: payloadHash,
      error_code: errorCode,
      attempt_count: attempts,
      integration: provider,
    })
    .onConflict(['provider', 'event_id'])
    .merge({
      provider,
      payload_hash: payloadHash,
      error_code: errorCode,
      attempt_count: attempts,
      integration: provider,
      updated_at: new Date(),
    });
}

export interface DeadLetterRecord {
  id: number;
  provider: string;
  event_id: string;
  payload_hash: string;
  error_code: string;
  attempt_count: number;
  integration: string;
  created_at: Date;
  updated_at: Date;
}

export interface QuarantinedLetterRecord {
  id: number;
  provider: string;
  event_id: string;
  payload_hash: string;
  error_code: string;
  fingerprint: string;
  attempt_count: number;
  quarantine_reason: string;
  integration: string;
  quarantined_at: Date;
  released_at: Date | null;
  released_by: string | null;
}

function canonicalizePayload(value: unknown, ancestors = new Set<object>()): unknown {
  if (Array.isArray(value)) {
    if (ancestors.has(value)) {
      throw new TypeError('Cannot hash circular payload');
    }
    ancestors.add(value);
    const canonical = value.map((item) => canonicalizePayload(item, ancestors));
    ancestors.delete(value);
    return canonical;
  }

  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (ancestors.has(value)) {
    throw new TypeError('Cannot hash circular payload');
  }
  ancestors.add(value);

  const toJSON = (value as { toJSON?: () => unknown }).toJSON;
  const canonical = typeof toJSON === 'function'
    ? canonicalizePayload(toJSON.call(value), ancestors)
    : Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [
          key,
          canonicalizePayload((value as Record<string, unknown>)[key], ancestors),
        ]),
    );

  ancestors.delete(value);
  return canonical;
}

/**
 * Hash JSON-compatible webhook payloads using stable, recursively sorted keys.
 */
export function computePayloadHash(payload: unknown): string {
  const serialized = JSON.stringify(canonicalizePayload(payload));
  if (serialized === undefined) {
    throw new TypeError('Payload is not JSON serializable');
  }
  return createHash('sha256').update(serialized).digest('hex');
}

/**
 * Find a dead-letter entry by provider and event ID.
 */
export async function getDeadLetter(
  provider: string,
  eventId: string,
): Promise<DeadLetterRecord | null> {
  const result = await db.query<DeadLetterRecord>(
    `SELECT id, provider, event_id, payload_hash, error_code, attempt_count,
            integration, created_at, updated_at
       FROM webhook_dead_letters
      WHERE provider = $1 AND event_id = $2
      LIMIT 1`,
    [provider, eventId],
  );
  return result.rows[0] ?? null;
}

/**
 * Delete a dead-letter entry by provider and event ID.
 */
export async function deleteDeadLetter(provider: string, eventId: string): Promise<void> {
  await db.query(
    `DELETE FROM webhook_dead_letters
      WHERE provider = $1 AND event_id = $2`,
    [provider, eventId],
  );
}

/**
 * Check whether an event has an active (unreleased) quarantine entry.
 */
export async function isQuarantined(provider: string, eventId: string): Promise<boolean> {
  const result = await db.query<{ exists: boolean }>(
    `SELECT EXISTS (
       SELECT 1
         FROM webhook_quarantine
        WHERE provider = $1 AND event_id = $2 AND released_at IS NULL
     ) AS exists`,
    [provider, eventId],
  );
  return result.rows[0]?.exists ?? false;
}

/**
 * List active quarantine entries, optionally filtered by provider or integration.
 */
export async function listQuarantinedLetters(
  provider?: string,
  integration?: string,
): Promise<QuarantinedLetterRecord[]> {
  const conditions = ['released_at IS NULL'];
  const params: string[] = [];

  if (provider !== undefined) {
    params.push(provider);
    conditions.push(`provider = $${params.length}`);
  }
  if (integration !== undefined) {
    params.push(integration);
    conditions.push(`integration = $${params.length}`);
  }

  const result = await db.query<QuarantinedLetterRecord>(
    `SELECT id, provider, event_id, payload_hash, error_code, fingerprint,
            attempt_count, quarantine_reason, integration, quarantined_at,
            released_at, released_by
       FROM webhook_quarantine
      WHERE ${conditions.join(' AND ')}
      ORDER BY quarantined_at DESC`,
    params,
  );
  return result.rows;
}

/**
 * Release an active quarantine entry once; returns false when none is active.
 */
export async function releaseQuarantinedLetter(
  provider: string,
  eventId: string,
  releasedBy: string,
): Promise<boolean> {
  const result = await db.query<{ id: number }>(
    `UPDATE webhook_quarantine
        SET released_at = NOW(), released_by = $3
      WHERE provider = $1 AND event_id = $2 AND released_at IS NULL
      RETURNING id`,
    [provider, eventId, releasedBy],
  );
  return result.rows.length > 0;
}

/**
 * Permanently remove a quarantine record by provider and event ID.
 */
export async function purgeQuarantinedLetter(
  provider: string,
  eventId: string,
): Promise<boolean> {
  const result = await db.query<{ id: number }>(
    `DELETE FROM webhook_quarantine
      WHERE provider = $1 AND event_id = $2
      RETURNING id`,
    [provider, eventId],
  );
  return result.rows.length > 0;
}

/**
 * Count dead-letter entries in each integration shard.
 */
export async function listDeadLetterShards(): Promise<Array<{ integration: string; count: number }>> {
  const result = await db.query<{ integration: string; count: number }>(
    `SELECT integration, COUNT(*)::int AS count
       FROM webhook_dead_letters
      GROUP BY integration
      ORDER BY integration`,
  );
  return result.rows;
}
