import { describe, it, expect, beforeEach } from 'vitest'
import { createGdprExport, decryptGdprExport } from '../../../src/services/user/createGdprExport.js'
import * as userRepo from '../../../src/repositories/userRepository.js'
import * as auditLogRepo from '../../../src/repositories/auditLogRepository.js'

beforeEach(() => {
  userRepo.clearAllUsers()
  auditLogRepo.clearAllAuditLogs()
})

describe('createGdprExport - Encryption and Signing', () => {
  it('should create export with all required fields', async () => {
    // Create a test user
    const user = await userRepo.createUser('test@example.com', 'hash123')

    const result = await createGdprExport(user.id)

    expect(result).toHaveProperty('encryptedData')
    expect(result).toHaveProperty('iv')
    expect(result).toHaveProperty('salt')
    expect(result).toHaveProperty('signature')
    expect(result).toHaveProperty('metadata')
  })

  it('should use AES-256-GCM encryption', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const result = await createGdprExport(user.id)

    expect(result.metadata.algorithm).toBe('aes-256-gcm')
    expect(result.metadata.keyDerivation).toBe('pbkdf2-sha256')
    expect(result.metadata.compressionFormat).toBe('gzip')
  })

  it('should generate unique IVs for each export', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')

    const result1 = await createGdprExport(user.id)
    const result2 = await createGdprExport(user.id)

    expect(result1.iv.toString('hex')).not.toBe(result2.iv.toString('hex'))
    expect(result1.salt.toString('hex')).not.toBe(result2.salt.toString('hex'))
  })

  it('should generate valid 12-byte IV for GCM', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const result = await createGdprExport(user.id)

    expect(result.iv.length).toBe(12)
    expect(result.salt.length).toBe(16)
  })

  it('should create valid HMAC signature', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const result = await createGdprExport(user.id)

    expect(result.signature).toMatch(/^[a-f0-9]{64}$/) // SHA-256 hex = 64 chars
    expect(result.signature.length).toBe(64)
  })

  it('should throw error for non-existent user', async () => {
    try {
      await createGdprExport('non-existent-user-id')
      expect(true).toBe(false) // Should not reach here
    } catch (err) {
      expect(err).toBeInstanceOf(Error)
      expect((err as Error).message).toContain('User')
    }
  })

  it('should include user email in encrypted data', async () => {
    const user = await userRepo.createUser('unique@example.com', 'hash123')
    const result = await createGdprExport(user.id)

    const decrypted = await decryptGdprExport(
      result.encryptedData,
      result.iv,
      result.salt,
      result.signature,
      user.id
    )

    expect(decrypted.user.email).toBe('unique@example.com')
  })

  it('should include user role in encrypted data', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const result = await createGdprExport(user.id)

    const decrypted = await decryptGdprExport(
      result.encryptedData,
      result.iv,
      result.salt,
      result.signature,
      user.id
    )

    expect(decrypted.user.role).toBe('user')
  })

  it('should include audit logs in encrypted data', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')

    // Create audit logs
    await auditLogRepo.createAuditLog({
      userId: user.id,
      action: 'LOGIN',
      resource: 'AUTH',
      metadata: { ip: '127.0.0.1' },
    })

    await auditLogRepo.createAuditLog({
      userId: user.id,
      action: 'UPDATE',
      resource: 'USER',
    })

    const result = await createGdprExport(user.id)
    const decrypted = await decryptGdprExport(
      result.encryptedData,
      result.iv,
      result.salt,
      result.signature,
      user.id
    )

    expect(decrypted.auditLogs).toHaveLength(2)
    expect(decrypted.auditLogs[0].action).toBe('LOGIN')
    expect(decrypted.auditLogs[1].action).toBe('UPDATE')
  })

  it('should handle users with no audit logs', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const result = await createGdprExport(user.id)

    const decrypted = await decryptGdprExport(
      result.encryptedData,
      result.iv,
      result.salt,
      result.signature,
      user.id
    )

    expect(decrypted.auditLogs).toEqual([])
  })

  it('should include exportedAt timestamp', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const beforeExport = new Date()

    const result = await createGdprExport(user.id)
    const decrypted = await decryptGdprExport(
      result.encryptedData,
      result.iv,
      result.salt,
      result.signature,
      user.id
    )

    const afterExport = new Date()

    const exportedAt = new Date(decrypted.exportedAt)
    expect(exportedAt.getTime()).toBeGreaterThanOrEqual(beforeExport.getTime())
    expect(exportedAt.getTime()).toBeLessThanOrEqual(afterExport.getTime())
  })
})

describe('decryptGdprExport - Decryption and Verification', () => {
  it('should successfully decrypt valid export', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const encrypted = await createGdprExport(user.id)

    const decrypted = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id
    )

    expect(decrypted.user.id).toBe(user.id)
    expect(decrypted.user.email).toBe(user.email)
  })

  it('should reject tampered data with wrong signature', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const encrypted = await createGdprExport(user.id)

    // Modify the signature
    const tamperedSignature = '00'.repeat(32)

    try {
      await decryptGdprExport(
        encrypted.encryptedData,
        encrypted.iv,
        encrypted.salt,
        tamperedSignature,
        user.id
      )
      expect(true).toBe(false) // Should throw
    } catch (err) {
      expect((err as Error).message).toContain('Invalid or tampered')
    }
  })

  it('should reject decryption with wrong IV', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const encrypted = await createGdprExport(user.id)

    // Use wrong IV
    const wrongIv = Buffer.alloc(12)

    try {
      await decryptGdprExport(
        encrypted.encryptedData,
        wrongIv,
        encrypted.salt,
        encrypted.signature,
        user.id
      )
      expect(true).toBe(false) // Should throw
    } catch (err) {
      // Either authentication fails during decryption or signature fails
      expect((err as Error).message).toMatch(/Failed to decrypt|Invalid or tampered/)
    }
  })

  it('should reject decryption with wrong salt', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const encrypted = await createGdprExport(user.id)

    // Use wrong salt (will derive wrong key)
    const wrongSalt = Buffer.alloc(16)

    try {
      await decryptGdprExport(
        encrypted.encryptedData,
        encrypted.iv,
        wrongSalt,
        encrypted.signature,
        user.id
      )
      expect(true).toBe(false) // Should throw
    } catch (err) {
      // Either authentication fails during decryption or signature fails
      expect((err as Error).message).toMatch(/Failed to decrypt|Invalid or tampered/)
    }
  })

  it('should validate signature with correct user ID', async () => {
    const user1 = await userRepo.createUser('user1@example.com', 'hash123')
    const encrypted = await createGdprExport(user1.id)

    // Try to decrypt with a different user ID
    const user2 = await userRepo.createUser('user2@example.com', 'hash123')

    try {
      await decryptGdprExport(
        encrypted.encryptedData,
        encrypted.iv,
        encrypted.salt,
        encrypted.signature,
        user2.id // Wrong user ID
      )
      expect(true).toBe(false) // Should throw
    } catch (err) {
      expect((err as Error).message).toContain('Invalid or tampered')
    }
  })

  it('should handle audit logs with metadata correctly', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')

    await auditLogRepo.createAuditLog({
      userId: user.id,
      action: 'API_CALL',
      resource: 'ATTESTATION',
      metadata: {
        method: 'POST',
        path: '/attestations',
        statusCode: 201,
        duration: 245,
      },
    })

    const encrypted = await createGdprExport(user.id)
    const decrypted = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id
    )

    expect(decrypted.auditLogs[0].metadata).toEqual({
      method: 'POST',
      path: '/attestations',
      statusCode: 201,
      duration: 245,
    })
  })

  it('should preserve timestamp format as ISO string', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')
    const encrypted = await createGdprExport(user.id)
    const decrypted = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id
    )

    expect(decrypted.user.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(decrypted.user.updatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})

describe('GDPR Export Data Integrity', () => {
  it('should maintain data integrity through encrypt-decrypt cycle', async () => {
    const user = await userRepo.createUser('integrity@example.com', 'hash123')

    // Add multiple audit logs
    for (let i = 0; i < 5; i++) {
      await auditLogRepo.createAuditLog({
        userId: user.id,
        action: `ACTION_${i}`,
        resource: `RESOURCE_${i}`,
        metadata: { index: i },
      })
    }

    const encrypted = await createGdprExport(user.id)
    const decrypted = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id
    )

    expect(decrypted.user.email).toBe('integrity@example.com')
    expect(decrypted.auditLogs.length).toBe(5)
    // Just verify all logs are present
    const actions = decrypted.auditLogs.map(log => log.action)
    expect(actions).toContain('ACTION_0')
    expect(actions).toContain('ACTION_1')
    expect(actions).toContain('ACTION_2')
    expect(actions).toContain('ACTION_3')
    expect(actions).toContain('ACTION_4')
  })

  it('should produce deterministic encryption with same IV (conceptually)', async () => {
    const user = await userRepo.createUser('test@example.com', 'hash123')

    // In production, IVs should be random for security
    // This test verifies the decryption process works
    const encrypted = await createGdprExport(user.id)
    const decrypted1 = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id
    )

    const decrypted2 = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id
    )

    expect(decrypted1.user.email).toBe(decrypted2.user.email)
    expect(decrypted1.auditLogs.length).toBe(decrypted2.auditLogs.length)
  })
})
