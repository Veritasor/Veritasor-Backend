import { describe, it, expect, beforeEach } from 'vitest'
import { create, update, listByUserId, deleteById, clearAll } from '../../../src/repositories/integration'
import {
  clearAllUsers,
  createUser,
  findUserByEmail,
  findUserById,
  setResetToken,
  updateUser,
  updateUserPassword,
} from '../../../src/repositories/userRepository'

describe('Integration Repository - update function', () => {
  beforeEach(() => {
    // Clear all integrations before each test
    clearAll()
  })

  it('should update token field and return updated integration', async () => {
    // Create an integration
    const created = await create({
      userId: 'user-1',
      provider: 'stripe',
      externalId: 'acct_123',
      token: { apiKey: 'old_key' },
      metadata: { plan: 'basic' }
    })

    // Small delay to ensure timestamp difference
    await new Promise(resolve => setTimeout(resolve, 10))

    // Update only the token
    const newToken = { apiKey: 'new_key', secret: 'secret_123' }
    const updated = await update(created.userId, created.id, { token: newToken })

    expect(updated).not.toBeNull()
    expect(updated!.token).toEqual(newToken)
    expect(updated!.metadata).toEqual({ plan: 'basic' }) // metadata unchanged
    expect(updated!.userId).toBe('user-1') // immutable field unchanged
    expect(updated!.provider).toBe('stripe') // immutable field unchanged
    expect(updated!.externalId).toBe('acct_123') // immutable field unchanged
    expect(updated!.createdAt).toBe(created.createdAt) // createdAt unchanged
    expect(updated!.updatedAt).not.toBe(created.updatedAt) // updatedAt changed
  })

  it('should update metadata field and return updated integration', async () => {
    // Create an integration
    const created = await create({
      userId: 'user-2',
      provider: 'razorpay',
      externalId: 'rzp_123',
      token: { apiKey: 'key_123' },
      metadata: { plan: 'basic' }
    })

    // Small delay to ensure timestamp difference
    await new Promise(resolve => setTimeout(resolve, 10))

    // Update only the metadata
    const newMetadata = { plan: 'premium', features: ['feature1', 'feature2'] }
    const updated = await update(created.userId, created.id, { metadata: newMetadata })

    expect(updated).not.toBeNull()
    expect(updated!.metadata).toEqual(newMetadata)
    expect(updated!.token).toEqual({ apiKey: 'key_123' }) // token unchanged
    expect(updated!.createdAt).toBe(created.createdAt) // createdAt unchanged
    expect(updated!.updatedAt).not.toBe(created.updatedAt) // updatedAt changed
  })

  it('should update both token and metadata fields', async () => {
    // Create an integration
    const created = await create({
      userId: 'user-3',
      provider: 'shopify',
      externalId: 'shop_123',
      token: { accessToken: 'old_token' },
      metadata: { storeName: 'Old Store' }
    })

    // Small delay to ensure timestamp difference
    await new Promise(resolve => setTimeout(resolve, 10))

    // Update both fields
    const newToken = { accessToken: 'new_token', refreshToken: 'refresh_123' }
    const newMetadata = { storeName: 'New Store', domain: 'newstore.myshopify.com' }
    const updated = await update(created.userId, created.id, { token: newToken, metadata: newMetadata })

    expect(updated).not.toBeNull()
    expect(updated!.token).toEqual(newToken)
    expect(updated!.metadata).toEqual(newMetadata)
    expect(updated!.createdAt).toBe(created.createdAt) // createdAt unchanged
    expect(updated!.updatedAt).not.toBe(created.updatedAt) // updatedAt changed
  })

  it('should return null for non-existent integration ID', async () => {
    const result = await update('user-1', 'non-existent-id', { token: { key: 'value' } })
    expect(result).toBeNull()
  })

  it('should keep immutable fields unchanged', async () => {
    // Create an integration
    const created = await create({
      userId: 'user-4',
      provider: 'stripe',
      externalId: 'acct_456',
      token: { apiKey: 'key_456' },
      metadata: { plan: 'basic' }
    })

    // Update with new data
    const updated = await update(created.userId, created.id, { 
      token: { apiKey: 'new_key' },
      metadata: { plan: 'premium' }
    })

    expect(updated).not.toBeNull()
    expect(updated!.id).toBe(created.id)
    expect(updated!.userId).toBe(created.userId)
    expect(updated!.provider).toBe(created.provider)
    expect(updated!.externalId).toBe(created.externalId)
    expect(updated!.createdAt).toBe(created.createdAt)
  })

  it('should deny updates from a different tenant scope', async () => {
    const created = await create({
      userId: 'user-tenant-a',
      provider: 'stripe',
      externalId: 'acct_cross_tenant',
      token: { apiKey: 'original' },
      metadata: { plan: 'basic' }
    })

    const result = await update('user-tenant-b', created.id, {
      token: { apiKey: 'tampered' },
      metadata: { plan: 'enterprise' }
    })

    expect(result).toBeNull()

    const stored = await listByUserId(created.userId)
    expect(stored).toHaveLength(1)
    expect(stored[0].token).toEqual({ apiKey: 'original' })
    expect(stored[0].metadata).toEqual({ plan: 'basic' })
  })

  it('should not leak nested token or metadata mutations through returned objects', async () => {
    const created = await create({
      userId: 'user-5',
      provider: 'stripe',
      externalId: 'acct_nested',
      token: { oauth: { accessToken: 'token-1' } },
      metadata: { account: { region: 'eu' } }
    })

    created.token.oauth.accessToken = 'tampered'
    created.metadata.account.region = 'us'

    const listed = await listByUserId('user-5')
    expect(listed[0].token).toEqual({ oauth: { accessToken: 'token-1' } })
    expect(listed[0].metadata).toEqual({ account: { region: 'eu' } })

    listed[0].token.oauth.accessToken = 'tampered-again'
    listed[0].metadata.account.region = 'apac'

    const afterMutation = await listByUserId('user-5')
    expect(afterMutation[0].token).toEqual({ oauth: { accessToken: 'token-1' } })
    expect(afterMutation[0].metadata).toEqual({ account: { region: 'eu' } })
  })
})

describe('Integration Repository - deleteById function', () => {
  beforeEach(() => {
    // Clear all integrations before each test
    clearAll()
  })

  it('should delete existing integration and return true', async () => {
    // Create an integration
    const created = await create({
      userId: 'user-1',
      provider: 'stripe',
      externalId: 'acct_123',
      token: { apiKey: 'key_123' },
      metadata: { plan: 'basic' }
    })

    // Delete the integration
    const result = await deleteById(created.userId, created.id)

    expect(result).toBe(true)

    // Verify it no longer appears in list
    const integrations = await listByUserId('user-1')
    expect(integrations).toHaveLength(0)
  })

  it('should return false for non-existent integration ID', async () => {
    const result = await deleteById('user-1', 'non-existent-id')
    expect(result).toBe(false)
  })

  it('should return false when deleting same ID twice', async () => {
    // Create an integration
    const created = await create({
      userId: 'user-2',
      provider: 'razorpay',
      externalId: 'rzp_123',
      token: { apiKey: 'key_456' },
      metadata: { plan: 'premium' }
    })

    // Delete the integration first time
    const firstDelete = await deleteById(created.userId, created.id)
    expect(firstDelete).toBe(true)

    // Delete the same integration second time
    const secondDelete = await deleteById(created.userId, created.id)
    expect(secondDelete).toBe(false)
  })

  it('should not affect other integrations when deleting one', async () => {
    // Create multiple integrations for the same user
    const integration1 = await create({
      userId: 'user-3',
      provider: 'stripe',
      externalId: 'acct_111',
      token: { apiKey: 'key_111' },
      metadata: {}
    })

    const integration2 = await create({
      userId: 'user-3',
      provider: 'razorpay',
      externalId: 'rzp_222',
      token: { apiKey: 'key_222' },
      metadata: {}
    })

    // Delete only the first integration
    await deleteById(integration1.userId, integration1.id)

    // Verify the second integration still exists
    const integrations = await listByUserId('user-3')
    expect(integrations).toHaveLength(1)
    expect(integrations[0].id).toBe(integration2.id)
  })

  it('should deny deletes from a different tenant scope', async () => {
    const created = await create({
      userId: 'user-delete-a',
      provider: 'stripe',
      externalId: 'acct_delete_scope',
      token: { apiKey: 'key_123' },
      metadata: { plan: 'basic' }
    })

    const deleted = await deleteById('user-delete-b', created.id)

    expect(deleted).toBe(false)

    const integrations = await listByUserId(created.userId)
    expect(integrations).toHaveLength(1)
    expect(integrations[0].id).toBe(created.id)
  })
})

describe('User Repository - partial update safety', () => {
  beforeEach(() => {
    clearAllUsers()
  })

  it('updates only provided fields when resetting password', async () => {
    const created = await createUser('user@example.com', 'hash-old')

    const withToken = (await setResetToken(created.id, 'reset-token', 5)) ?? created

    await new Promise(resolve => setTimeout(resolve, 5))

    const updated = await updateUserPassword(created.id, 'hash-new')

    expect(updated).not.toBeNull()
    expect(updated!.passwordHash).toBe('hash-new')
    expect(updated!.email).toBe('user@example.com')
    expect(updated!.resetToken).toBeUndefined()
    expect(updated!.resetTokenExpiry).toBeUndefined()
    expect(updated!.createdAt.getTime()).toBe(created.createdAt.getTime())
    expect(updated!.updatedAt.getTime()).toBeGreaterThan(withToken.updatedAt.getTime())

    // Mutating returned object must not leak into storage
    updated!.email = 'tampered@example.com'
    const stored = await findUserById(created.id)
    expect(stored!.email).toBe('user@example.com')
  })

  it('sets reset token without touching other fields', async () => {
    const created = await createUser('user2@example.com', 'hash-original')
    const previousUpdatedAt = created.updatedAt.getTime()

    await new Promise(resolve => setTimeout(resolve, 5))

    const updated = await setResetToken(created.id, 'token-123', 10)

    expect(updated).not.toBeNull()
    expect(updated!.resetToken).toBe('token-123')
    expect(updated!.resetTokenExpiry).toBeInstanceOf(Date)
    expect(updated!.passwordHash).toBe('hash-original')
    expect(updated!.createdAt.getTime()).toBe(created.createdAt.getTime())
    expect(updated!.updatedAt.getTime()).toBeGreaterThan(previousUpdatedAt)
  })

  it('updates email via partial update and refreshes lookup index', async () => {
    const created = await createUser('old@example.com', 'hash-email')

    await new Promise(resolve => setTimeout(resolve, 5))

    const updated = await updateUser(created.id, { email: 'new@example.com' })
    expect(updated).not.toBeNull()
    expect(updated!.email).toBe('new@example.com')

    const oldLookup = await findUserByEmail('old@example.com')
    expect(oldLookup).toBeNull()

    const newLookup = await findUserByEmail('new@example.com')
    expect(newLookup).not.toBeNull()
    expect(newLookup!.id).toBe(created.id)
  })

  it('returns null when updating a non-existent user', async () => {
    const result = await updateUser('missing-id', { email: 'none@example.com' })
    expect(result).toBeNull()
  })
})
