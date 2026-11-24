import { db } from '../../db/client.js';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { randomUUID, createHash } from 'crypto';
import { Logger } from '../../utils/logger.js';
import { webhookDeadLetterWriteFailuresTotal } from '../../metrics.js';

const deadLetterLogger = new Logger('DLQ');

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
  id: number;
  provider: string;
  event_id: string;
  payload_hash: string;
  error_code: string;
  attempt_count: number;
  integration: string;
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

    const conditions: string[] = [];
    const params: unknown[] = [];
    const addCondition = (sql: string, value: unknown) => {
      params.push(value);
      conditions.push(sql.replace('?', `$${params.length}`));
    };
    if (type) addCondition('provider = ?', type);
    if (archived !== undefined) addCondition('archived = ?', archived);
    if (startDate) addCondition('created_at >= ?', startDate);
    if (endDate) addCondition('created_at <= ?', endDate);
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const count = await db.query<{ total: string }>(
      `SELECT COUNT(*) AS total FROM webhook_dead_letters ${where}`,
      params,
    );
    const entries = await db.query<DLQEntry>(
      `SELECT * FROM webhook_dead_letters ${where} ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, pageSize, offset],
    );
    return { entries: entries.rows, total: Number(count.rows[0]?.total ?? 0) };
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
    const entriesResult = await db.query<DLQEntry>(
      'SELECT * FROM webhook_dead_letters WHERE created_at < $1 AND archived = FALSE LIMIT $2',
      [cutoffDate, batchSize],
    );
    const entries = entriesResult.rows;

    total = entries.length;

    for (const entry of entries) {
      try {
        const archiveKey = this.generateArchiveKey(entry);
        const encryptedData = await this.encryptEntry(entry);
        const s3Url = await this.uploadToS3(archiveBucket, archiveKey, encryptedData);

        // Update database with archive location
        await db.query(
          'UPDATE webhook_dead_letters SET archived = TRUE, archive_location = $1, archive_encrypted = TRUE, updated_at = NOW() WHERE id = $2',
          [s3Url, entry.id],
        );

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
    const result = await db.query<DLQEntry>('SELECT * FROM webhook_dead_letters WHERE id = $1::integer LIMIT 1', [entryId]);
    const entry = result.rows[0];

    if (!entry) {
      throw new Error(`DLQ entry ${entryId} not found`);
    }

    if (entry.archived) {
      throw new Error(`DLQ entry ${entryId} already archived`);
    }

    const archiveKey = this.generateArchiveKey(entry);
    const encryptedData = await this.encryptEntry(entry);
    const s3Url = await this.uploadToS3(this.config.bucket, archiveKey, encryptedData);

    await db.query(
      'UPDATE webhook_dead_letters SET archived = TRUE, archive_location = $1, archive_encrypted = TRUE, updated_at = NOW() WHERE id = $2::integer',
      [s3Url, entryId],
    );

    this.logger.info(`Archived DLQ entry ${entryId} to ${s3Url}`);
    return s3Url;
  }

  /**
   * Restore a DLQ entry from archive
   */
  async restoreEntry(entryId: string, options: RestoreOptions = {}): Promise<DLQEntry> {
    const result = await db.query<DLQEntry>('SELECT * FROM webhook_dead_letters WHERE id = $1::integer LIMIT 1', [entryId]);
    const entry = result.rows[0];

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
    await db.query(
      'UPDATE webhook_dead_letters SET archived = FALSE, archive_location = NULL, archive_encrypted = FALSE, updated_at = NOW() WHERE id = $1::integer',
      [entryId],
    );

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
    const [counts, dates] = await Promise.all([
      db.query<{ archived: string; active: string }>("SELECT COUNT(*) FILTER (WHERE archived) AS archived, COUNT(*) FILTER (WHERE NOT archived) AS active FROM webhook_dead_letters"),
      db.query<{ oldest: Date | null; newest: Date | null }>("SELECT MIN(created_at) FILTER (WHERE archived) AS oldest, MAX(created_at) FILTER (WHERE archived) AS newest FROM webhook_dead_letters"),
    ]);

    return {
      totalArchived: Number(counts.rows[0]?.archived || 0),
      totalActive: Number(counts.rows[0]?.active || 0),
      archiveSizeBytes: 0, // Would need to calculate from S3
      oldestEntry: dates.rows[0]?.oldest || null,
      newestEntry: dates.rows[0]?.newest || null,
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
      provider: entry.provider,
      event_id: entry.event_id,
      payload_hash: entry.payload_hash,
      error_code: entry.error_code,
      attempt_count: entry.attempt_count,
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

  try {
    await db.query(
      `INSERT INTO webhook_dead_letters (provider, event_id, payload_hash, error_code, attempt_count, integration)
       VALUES ($1, $2, $3, $4, $5, $1)
       ON CONFLICT (provider, event_id) DO UPDATE SET
         attempt_count = webhook_dead_letters.attempt_count + EXCLUDED.attempt_count,
         error_code = EXCLUDED.error_code,
         updated_at = NOW()`,
      [provider, eventId, payloadHash, errorCode, attempts],
    );
  } catch (error) {
    webhookDeadLetterWriteFailuresTotal.inc();
    deadLetterLogger.error('Failed to persist dead-letter event', error);
    throw error;
  }
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
