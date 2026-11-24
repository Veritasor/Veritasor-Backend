import { describe, expect, it } from 'vitest'
import type { SecretAdapter } from './secrets/base.js'

export interface ProviderContext {
  // FileAdapter has historically returned a Promise, while the other adapters
  // return strings. Exercise both without changing the loader's public API.
  adapter: Omit<SecretAdapter, 'get'> & { get(key: string): string | Promise<string> }
  seed?: (key: string, value: string) => void
}

export function describeSecretProviderContract(
  name: string,
  createAdapter: () => Promise<ProviderContext>,
): void {
  const KEY = 'CONTRACT_TEST_KEY'
  const VALUE = 'contract-test-value'
  const MISSING = 'CONTRACT_MISSING_KEY'

  describe(`${name} contract`, () => {
    it('createAdapter() resolves', async () => {
      const ctx = await createAdapter()
      expect(ctx.adapter).toBeDefined()
    })

    it('get(knownKey) returns a string after reload()', async () => {
      const ctx = await createAdapter()
      if (ctx.seed) ctx.seed(KEY, VALUE)
      await ctx.adapter.reload()
      const result = await ctx.adapter.get(KEY)
      expect(typeof result).toBe('string')
      expect(result).toBe(VALUE)
    })

    it('get(unknownKey) throws when the provider has no value', async () => {
      const ctx = await createAdapter()
      await ctx.adapter.reload()
      await expect(async () => ctx.adapter.get(MISSING)).rejects.toThrow()
    })

    it('reload() resolves', async () => {
      const ctx = await createAdapter()
      if (ctx.seed) ctx.seed(KEY, VALUE)
      await expect(ctx.adapter.reload()).resolves.toBeUndefined()
    })

    it('reload() is idempotent', async () => {
      const ctx = await createAdapter()
      if (ctx.seed) ctx.seed(KEY, VALUE)
      await ctx.adapter.reload()
      await expect(ctx.adapter.reload()).resolves.toBeUndefined()
    })

    it('reload() reflects updated values', async () => {
      const ctx = await createAdapter()
      if (ctx.seed) ctx.seed(KEY, VALUE)
      await ctx.adapter.reload()
      const first = await ctx.adapter.get(KEY)

      const UPDATED = 'contract-test-updated'
      if (ctx.seed) ctx.seed(KEY, UPDATED)
      await ctx.adapter.reload()
      const second = await ctx.adapter.get(KEY)

      expect(first).toBe(VALUE)
      expect(second).toBe(UPDATED)
    })
  })
}
