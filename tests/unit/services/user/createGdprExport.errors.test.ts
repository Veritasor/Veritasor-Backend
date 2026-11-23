/**
 * @file createGdprExport.errors.test.ts
 * @description Dedicated regression suite for the explicit failure paths of
 * `src/services/user/createGdprExport.ts`:
 *
 * - `createGdprExport` — `User ${userId} not found` (unknown/empty id)
 * - `decryptGdprExport` — `Failed to decrypt export: authentication failed`
 *   (AES-256-GCM auth failure: tampered ciphertext, wrong IV/salt, truncated
 *   envelope)
 * - `decryptGdprExport` — `Invalid or tampered export data` (HMAC signature
 *   verification failure after successful decryption)
 *
 * Companion to `tests/unit/services/createGdprExport.test.ts`, which covers
 * the broad encrypt/decrypt behavior. This file pins the exact error
 * contracts (message equality, not substring matching) and the verification
 * ordering, so silent behavior changes fail loudly.
 *
 * All crypto boundaries were verified against Node's AES-256-GCM semantics:
 * GCM authentication rejects wrong IV/salt (via the derived key), tampered
 * ciphertext, and truncated envelopes at `decipher.final()`, so every
 * corrupted-input case below deterministically lands in the decryption catch
 * block rather than the signature check.
 */

import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import {
  createGdprExport,
  decryptGdprExport,
} from '../../../../src/services/user/createGdprExport.js'
import * as userRepo from '../../../../src/repositories/userRepository.js'
import * as auditLogRepo from '../../../../src/repositories/auditLogRepository.js'

// ---------------------------------------------------------------------------
// Environment hygiene
// ---------------------------------------------------------------------------

const ORIGINAL_GDPR_SECRET = process.env.GDPR_EXPORT_SECRET

beforeEach(() => {
  userRepo.clearAllUsers()
  auditLogRepo.clearAllAuditLogs()
  // Pin the PBKDF2 input so key derivation is hermetic regardless of CI env.
  process.env.GDPR_EXPORT_SECRET = 'gdpr-export-test-secret'
})

afterAll(() => {
  if (ORIGINAL_GDPR_SECRET === undefined) {
    delete process.env.GDPR_EXPORT_SECRET
  } else {
    process.env.GDPR_EXPORT_SECRET = ORIGINAL_GDPR_SECRET
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async function createUserWithData(logCount = 0) {
  const user = await userRepo.createUser('gdpr-errors@example.com', 'hash123')
  for (let i = 0; i < logCount; i++) {
    await auditLogRepo.createAuditLog({
      userId: user.id,
      action: `ACTION_${i}`,
      resource: `RESOURCE_${i}`,
      metadata: { index: i },
    })
  }
  return user
}

async function createExportFor(user: { id: string }) {
  return createGdprExport(user.id)
}

/** Flips one byte of the ciphertext portion (past the 16-byte GCM auth tag). */
function tamperCiphertext(encryptedData: Buffer): Buffer {
  const tampered = Buffer.from(encryptedData)
  tampered[16 + 5] ^= 0xff
  return tampered
}

// ---------------------------------------------------------------------------
// createGdprExport — unknown user (line 46)
// ---------------------------------------------------------------------------

describe('createGdprExport — unknown user failure path', () => {
  it('throws with the exact interpolated message for a nonexistent user', async () => {
    const err: unknown = await createGdprExport('missing-user-id').catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).name).toBe('Error')
    expect((err as Error).message).toBe('User missing-user-id not found')
  })

  it('throws the empty-interpolation message for an empty-string userId (boundary)', async () => {
    // findUserById('') resolves null → the message contains no id at all.
    const err: unknown = await createGdprExport('').catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('User  not found')
  })

  it('throws a plain Error, not a custom subclass (contract stability)', async () => {
    const err: unknown = await createGdprExport('no-such-user').catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect(Object.getPrototypeOf(err)).toBe(Error.prototype)
  })

  it('resolves with the full envelope contract for an existing user (neighboring normal path)', async () => {
    const user = await createUserWithData()
    const result = await createExportFor(user)

    expect(Object.keys(result).sort()).toEqual([
      'encryptedData',
      'iv',
      'metadata',
      'salt',
      'signature',
    ])
    expect(result.metadata).toEqual({
      algorithm: 'aes-256-gcm',
      keyDerivation: 'pbkdf2-sha256',
      compressionFormat: 'gzip',
    })
    expect(result.iv).toBeInstanceOf(Buffer)
    expect(result.iv.length).toBe(12)
    expect(result.salt).toBeInstanceOf(Buffer)
    expect(result.salt.length).toBe(16)
    // 16-byte GCM auth tag prefix + ciphertext: never just the tag.
    expect(result.encryptedData.length).toBeGreaterThan(16)
    expect(result.signature).toMatch(/^[a-f0-9]{64}$/)
  })
})

// ---------------------------------------------------------------------------
// decryptGdprExport — GCM authentication failure (line 140)
// ---------------------------------------------------------------------------

describe('decryptGdprExport — authentication failure path', () => {
  it('throws the exact auth-failure message when the ciphertext is tampered (signature left intact)', async () => {
    const user = await createUserWithData(1)
    const encrypted = await createExportFor(user)

    // The signature is stale after tampering, but GCM auth fails first —
    // this pins that the decryption check (line 140) runs before the
    // signature check (line 151).
    const err: unknown = await decryptGdprExport(
      tamperCiphertext(encrypted.encryptedData),
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    ).catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('Failed to decrypt export: authentication failed')
  })

  it('throws the exact auth-failure message for a wrong IV', async () => {
    const user = await createUserWithData()
    const encrypted = await createExportFor(user)

    const err: unknown = await decryptGdprExport(
      encrypted.encryptedData,
      Buffer.alloc(12), // valid length, wrong value
      encrypted.salt,
      encrypted.signature,
      user.id,
    ).catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('Failed to decrypt export: authentication failed')
  })

  it('throws the exact auth-failure message for a wrong salt (different derived key)', async () => {
    const user = await createUserWithData()
    const encrypted = await createExportFor(user)

    const err: unknown = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      Buffer.alloc(16), // valid length, wrong value
      encrypted.signature,
      user.id,
    ).catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('Failed to decrypt export: authentication failed')
  })

  it('throws the exact auth-failure message for an envelope shorter than the 16-byte auth tag (boundary)', async () => {
    const user = await createUserWithData()
    const encrypted = await createExportFor(user)

    const err: unknown = await decryptGdprExport(
      encrypted.encryptedData.slice(0, 8),
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    ).catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('Failed to decrypt export: authentication failed')
  })

  it('never leaks the underlying crypto error (no cause, plain message)', async () => {
    const user = await createUserWithData()
    const encrypted = await createExportFor(user)

    const err: unknown = await decryptGdprExport(
      tamperCiphertext(encrypted.encryptedData),
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    ).catch((e) => e)

    expect((err as Error).name).toBe('Error')
    expect((err as { cause?: unknown }).cause).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// decryptGdprExport — signature verification failure (line 151)
// ---------------------------------------------------------------------------

describe('decryptGdprExport — tamper detection path', () => {
  it('throws the exact tamper message when only the signature is wrong (decryption succeeds)', async () => {
    const user = await createUserWithData(1)
    const encrypted = await createExportFor(user)

    // Ciphertext is intact so GCM auth passes; the stale signature then
    // fails verification — isolating line 151 from line 140.
    const err: unknown = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      '00'.repeat(32),
      user.id,
    ).catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('Invalid or tampered export data')
  })

  it('throws the exact tamper message for an empty-string signature (boundary)', async () => {
    const user = await createUserWithData()
    const encrypted = await createExportFor(user)

    const err: unknown = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      '',
      user.id,
    ).catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('Invalid or tampered export data')
  })

  it('rejects an export decrypted with a different userId (signature binds the user)', async () => {
    const user1 = await userRepo.createUser('gdpr-user-1@example.com', 'hash123')
    const encrypted = await createExportFor(user1)
    const user2 = await userRepo.createUser('gdpr-user-2@example.com', 'hash123')

    // The AES key derives from the server secret + salt only (no userId),
    // so decryption succeeds — only the HMAC (keyed by userId) fails.
    const err: unknown = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user2.id,
    ).catch((e) => e)

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toBe('Invalid or tampered export data')
  })

  it('verifies decryption before the signature (ordering pinned by the two distinct messages)', async () => {
    const user = await createUserWithData()
    const encrypted = await createExportFor(user)

    // Tampered ciphertext + valid-format signature: if the implementation
    // ever checked the signature first, this would throw the tamper message
    // instead of the auth message.
    await expect(
      decryptGdprExport(
        tamperCiphertext(encrypted.encryptedData),
        encrypted.iv,
        encrypted.salt,
        encrypted.signature,
        user.id,
      ),
    ).rejects.toThrow('Failed to decrypt export: authentication failed')

    // Mirror case: intact ciphertext + wrong signature must hit the tamper
    // message, proving both branches are reachable and distinguishable.
    await expect(
      decryptGdprExport(
        encrypted.encryptedData,
        encrypted.iv,
        encrypted.salt,
        '00'.repeat(32),
        user.id,
      ),
    ).rejects.toThrow('Invalid or tampered export data')
  })
})

// ---------------------------------------------------------------------------
// Round trip — neighboring normal path and boundaries
// ---------------------------------------------------------------------------

describe('createGdprExport / decryptGdprExport — round trip', () => {
  it('preserves the full GdprExportData contract through encrypt → decrypt', async () => {
    const user = await createUserWithData(2)
    const encrypted = await createExportFor(user)

    const decrypted = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    )

    expect(decrypted.user.id).toBe(user.id)
    expect(decrypted.user.email).toBe('gdpr-errors@example.com')
    expect(decrypted.user.role).toBe('user')
    expect(decrypted.user.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(decrypted.user.updatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(decrypted.exportedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(decrypted.auditLogs).toHaveLength(2)
    // getAuditLogsByUser sorts reverse-chronologically; logs created within
    // the same millisecond keep insertion order, so index positions are not
    // stable across timing. Assert by lookup, never by index.
    const first = decrypted.auditLogs.find((log) => log.action === 'ACTION_0')
    expect(first).toMatchObject({
      resource: 'RESOURCE_0',
      metadata: { index: 0 },
    })
  })

  it('returns an empty auditLogs array for a user with no logs (empty-result boundary)', async () => {
    const user = await createUserWithData(0)
    const encrypted = await createExportFor(user)

    const decrypted = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    )

    expect(decrypted.auditLogs).toEqual([])
  })

  it('survives the gzip compression boundary with a large payload (200 logs)', async () => {
    const user = await createUserWithData(200)
    const encrypted = await createExportFor(user)

    const decrypted = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    )

    expect(decrypted.auditLogs).toHaveLength(200)
    expect(decrypted.auditLogs.map((log) => log.action)).toContain('ACTION_199')
  })

  it('is deterministic: the same envelope decrypts identically on every call', async () => {
    const user = await createUserWithData(1)
    const encrypted = await createExportFor(user)

    const first = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    )
    const second = await decryptGdprExport(
      encrypted.encryptedData,
      encrypted.iv,
      encrypted.salt,
      encrypted.signature,
      user.id,
    )

    expect(second).toEqual(first)
  })
})
