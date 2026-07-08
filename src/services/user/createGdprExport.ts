import { createCipheriv, createDecipheriv, randomBytes, createHmac } from 'node:crypto'
import { promisify } from 'node:util'
import { gzip, gunzip } from 'node:zlib'
import { findUserById } from '../../repositories/userRepository.js'
import { getAuditLogsByUser } from '../../repositories/auditLogRepository.js'
import { logger } from '../../utils/logger.js'

const gzipAsync = promisify(gzip)
const gunzipAsync = promisify(gunzip)

export interface GdprExportData {
  user: {
    id: string
    email: string
    createdAt: string
    updatedAt: string
    role: string
  }
  auditLogs: Array<{
    id: string
    action: string
    resource: string
    timestamp: string
    metadata?: any
  }>
  exportedAt: string
}

/**
 * Create and encrypt a GDPR data export for a user
 */
export async function createGdprExport(userId: string): Promise<{
  encryptedData: Buffer
  iv: Buffer
  salt: Buffer
  signature: string
  metadata: {
    algorithm: string
    keyDerivation: string
    compressionFormat: string
  }
}> {
  // Fetch user data
  const user = await findUserById(userId)
  if (!user) {
    throw new Error(`User ${userId} not found`)
  }

  // Fetch audit logs for the user
  const auditLogs = await getAuditLogsByUser(userId)

  // Bundle data
  const exportData: GdprExportData = {
    user: {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
      role: user.role,
    },
    auditLogs: auditLogs.map(log => ({
      id: log.id,
      action: log.action,
      resource: log.resource,
      timestamp: log.timestamp.toISOString(),
      metadata: log.metadata,
    })),
    exportedAt: new Date().toISOString(),
  }

  // Serialize to JSON
  const jsonData = Buffer.from(JSON.stringify(exportData, null, 2))

  // Compress
  const compressedData = await gzipAsync(jsonData)

  // Encrypt using AES-256-GCM
  const salt = randomBytes(16)
  const iv = randomBytes(12) // GCM IV is 12 bytes
  const encryptionKey = deriveEncryptionKey(salt)

  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv)
  let encrypted = cipher.update(compressedData)
  encrypted = Buffer.concat([encrypted, cipher.final()])

  // Get authentication tag
  const authTag = cipher.getAuthTag()

  // Create signature for tamper detection
  const signature = createSignature(
    Buffer.concat([salt, iv, authTag, encrypted]),
    userId
  )

  // Combine with auth tag
  const encryptedWithTag = Buffer.concat([authTag, encrypted])

  return {
    encryptedData: encryptedWithTag,
    iv,
    salt,
    signature,
    metadata: {
      algorithm: 'aes-256-gcm',
      keyDerivation: 'pbkdf2-sha256',
      compressionFormat: 'gzip',
    },
  }
}

/**
 * Decrypt GDPR export
 */
export async function decryptGdprExport(
  encryptedData: Buffer,
  iv: Buffer,
  salt: Buffer,
  signature: string,
  userId: string
): Promise<GdprExportData> {
  // Extract auth tag (first 16 bytes of encrypted data)
  const authTag = encryptedData.slice(0, 16)
  const actualEncrypted = encryptedData.slice(16)

  // Derive the same encryption key
  const encryptionKey = deriveEncryptionKey(salt)

  // Decrypt
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv)
  decipher.setAuthTag(authTag)

  let decompressed: Buffer
  try {
    let decryptedBuffer = decipher.update(actualEncrypted)
    decryptedBuffer = Buffer.concat([decryptedBuffer, decipher.final()])

    // Decompress
    decompressed = await gunzipAsync(decryptedBuffer)
  } catch (err) {
    throw new Error('Failed to decrypt export: authentication failed')
  }

  // Verify signature after successful decryption
  const isValid = verifySignature(
    Buffer.concat([salt, iv, encryptedData]),
    signature,
    userId
  )

  if (!isValid) {
    throw new Error('Invalid or tampered export data')
  }

  // Parse JSON
  return JSON.parse(decompressed.toString('utf-8'))
}

/**
 * Derive encryption key from salt using PBKDF2
 */
function deriveEncryptionKey(salt: Buffer): Buffer {
  // Use the user's ID as password (it's known in context)
  // In production, you might use a server secret combined with the user ID
  const crypto = require('node:crypto')
  return crypto.pbkdf2Sync(
    process.env.GDPR_EXPORT_SECRET || 'default-export-secret',
    salt,
    100000, // iterations
    32, // 256 bits for AES-256
    'sha256'
  )
}

/**
 * Create HMAC signature for tamper detection
 */
function createSignature(data: Buffer, userId: string): string {
  const hmac = createHmac('sha256', Buffer.from(userId))
  hmac.update(data)
  return hmac.digest('hex')
}

/**
 * Verify HMAC signature
 */
function verifySignature(data: Buffer, signature: string, userId: string): boolean {
  const expectedSignature = createSignature(data, userId)
  return expectedSignature === signature
}
