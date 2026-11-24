import { logger } from '../logger.js'

export class KmsDiskCache {
  private readonly algorithm = 'aes-256-gcm'

  constructor(
    private readonly kmsKeyId: string,
    private readonly cachePath: string,
    private readonly ttlMinutes: number,
    private readonly region: string = process.env.AWS_REGION || 'us-east-1'
  ) {}

  async save(secrets: Map<string, string>): Promise<void> {
    try {
      const { KMSClient, GenerateDataKeyCommand } = await import('@aws-sdk/client-kms')
      const client = new KMSClient({ region: this.region })

      const dataKeyResponse = await client.send(
        new GenerateDataKeyCommand({
          KeyId: this.kmsKeyId,
          KeySpec: 'AES_256',
        })
      )

      if (!dataKeyResponse.Plaintext || !dataKeyResponse.CiphertextBlob) {
        throw new Error('Failed to generate KMS data key')
      }

      const crypto = await import('node:crypto')
      const iv = crypto.randomBytes(12)
      const cipher = crypto.createCipheriv(this.algorithm, Buffer.from(dataKeyResponse.Plaintext), iv)

      const payloadStr = JSON.stringify(Object.fromEntries(secrets))
      let encrypted = cipher.update(payloadStr, 'utf8', 'base64')
      encrypted += cipher.final('base64')
      const authTag = cipher.getAuthTag()

      const cachePayload = {
        ciphertextKey: Buffer.from(dataKeyResponse.CiphertextBlob).toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        encryptedData: encrypted,
        expiresAt: Date.now() + this.ttlMinutes * 60 * 1000,
      }

      const fs = await import('node:fs/promises')
      const path = await import('node:path')

      await fs.mkdir(path.dirname(this.cachePath), { recursive: true })
      await fs.writeFile(this.cachePath, JSON.stringify(cachePayload), { mode: 0o600 })
    } catch (err) {
      logger.error('Failed to save KMS encrypted cache', err instanceof Error ? err.message : String(err))
    }
  }

  async load(): Promise<Map<string, string> | null> {
    try {
      const fs = await import('node:fs/promises')
      let fileContent: string
      try {
        fileContent = await fs.readFile(this.cachePath, 'utf8')
      } catch (err: any) {
        if (err.code === 'ENOENT') return null
        throw err
      }

      const parsed = JSON.parse(fileContent)
      if (Date.now() > parsed.expiresAt) {
        logger.warn('KMS cache expired, ignoring')
        return null
      }

      const { KMSClient, DecryptCommand } = await import('@aws-sdk/client-kms')
      const client = new KMSClient({ region: this.region })

      const decryptResponse = await client.send(
        new DecryptCommand({
          CiphertextBlob: Buffer.from(parsed.ciphertextKey, 'base64'),
        })
      )

      if (!decryptResponse.Plaintext) {
        throw new Error('Failed to decrypt KMS data key')
      }

      const crypto = await import('node:crypto')
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        Buffer.from(decryptResponse.Plaintext),
        Buffer.from(parsed.iv, 'base64')
      )
      decipher.setAuthTag(Buffer.from(parsed.authTag, 'base64'))

      let decrypted = decipher.update(parsed.encryptedData, 'base64', 'utf8')
      decrypted += decipher.final('utf8')

      const secretsRecord = JSON.parse(decrypted)

      // Audit cache hit
      logger.info('Secret loader fell back to KMS-encrypted disk cache')

      const map = new Map<string, string>()
      for (const [k, v] of Object.entries(secretsRecord)) {
        map.set(k, v as string)
      }
      return map
    } catch (err) {
      logger.error('Failed to load or decrypt KMS cache (possible tampering or invalid format)', err instanceof Error ? err.message : String(err))
      return null
    }
  }
}
