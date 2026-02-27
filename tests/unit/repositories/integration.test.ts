import { describe, it, expect, beforeEach } from 'vitest'
import { create, update, listByUserId, deleteById, clearAll } from '../../../src/repositories/integration'

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
    const updated = await update(created.id, { token: newToken })

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
    const updated = await update(created.id, { metadata: newMetadata })

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
    const updated = await update(created.id, { token: newToken, metadata: newMetadata })

    expect(updated).not.toBeNull()
    expect(updated!.token).toEqual(newToken)
    expect(updated!.metadata).toEqual(newMetadata)
    expect(updated!.createdAt).toBe(created.createdAt) // createdAt unchanged
    expect(updated!.updatedAt).not.toBe(created.updatedAt) // updatedAt changed
  })

  it('should return null for non-existent integration ID', async () => {
    const result = await update('non-existent-id', { token: { key: 'value' } })
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
    const updated = await update(created.id, { 
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
    const result = await deleteById(created.id)

    expect(result).toBe(true)

    // Verify it no longer appears in list
    const integrations = await listByUserId('user-1')
    expect(integrations).toHaveLength(0)
  })

  it('should return false for non-existent integration ID', async () => {
    const result = await deleteById('non-existent-id')
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
    const firstDelete = await deleteById(created.id)
    expect(firstDelete).toBe(true)

    // Delete the same integration second time
    const secondDelete = await deleteById(created.id)
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
    await deleteById(integration1.id)

    // Verify the second integration still exists
    const integrations = await listByUserId('user-3')
    expect(integrations).toHaveLength(1)
    expect(integrations[0].id).toBe(integration2.id)
  })
})
