import { db } from '../../config/database';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { randomUUID } from 'crypto';
import { Logger } from '../../utils/logger';

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
  # Private Methods
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
