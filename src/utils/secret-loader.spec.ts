import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'node:fs/promises'
import path from 'node:path'
import { EnvAdapter, FileAdapter, VaultAdapter, createSecretLoader, SecretLoadError, SecretNotFoundError } from './secret-loader.js'

const ORIGINAL_ENV = { ...process.env }

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) {
      delete process.env[key]
    }
  }

  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    process.env[key] = value
  }
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  restoreEnv()
  vi.restoreAllMocks()
})

describe('SecretLoader', () => {
  it('reads env values and picks up rotated values after reload', async () => {
    process.env.JWT_SECRET = 'first-secret'
    const loader = new EnvAdapter()

    await loader.reload()
    expect(loader.get('JWT_SECRET')).toBe('first-secret')

    process.env.JWT_SECRET = 'second-secret'
    await loader.reload()
    expect(loader.get('JWT_SECRET')).toBe('second-secret')
  })

  it('throws SecretNotFoundError when a key is missing from the environment', async () => {
    const loader = new EnvAdapter()
    await loader.reload()
    expect(() => loader.get('MISSING_SECRET')).toThrow(SecretNotFoundError)
  })

  it('loads secrets from a file-backed source and refreshes after reload', async () => {
    const dir = await fs.mkdtemp('/tmp/secret-loader-')
    const secretFile = path.join(dir, 'secrets.env')
    await fs.writeFile(secretFile, 'JWT_SECRET=from-file\nRAZORPAY_WEBHOOK_SECRET=rotating-value\n', 'utf8')

    const loader = new FileAdapter(secretFile)
    await loader.reload()

    expect(loader.get('JWT_SECRET')).toBe('from-file')
    expect(loader.get('RAZORPAY_WEBHOOK_SECRET')).toBe('rotating-value')

    await fs.writeFile(secretFile, 'JWT_SECRET=next-secret\n', 'utf8')
    await loader.reload()
    expect(loader.get('JWT_SECRET')).toBe('next-secret')
  })

  it('rejects empty file sources during reload', async () => {
    const dir = await fs.mkdtemp('/tmp/secret-loader-')
    const emptyFile = path.join(dir, 'empty.env')
    await fs.writeFile(emptyFile, '   \n', 'utf8')

    const loader = new FileAdapter(emptyFile)
    await expect(loader.reload()).rejects.toThrow(SecretLoadError)
  })

  it('falls back to the env adapter when the primary provider fails', async () => {
    process.env.FALLBACK_SECRET = 'fallback-value'
    const loader = createSecretLoader({ provider: 'vault', vaultBaseUrl: 'https://vault.example.com', vaultSecretPath: 'secrets/path' })

    await loader.reload()
    expect(loader.get('FALLBACK_SECRET')).toBe('fallback-value')
  })

  it('supports the env-based factory and required config checks', () => {
    expect(createSecretLoader()).toBeDefined()
    expect(() => createSecretLoader({ provider: 'aws' })).toThrow(SecretLoadError)
    expect(() => createSecretLoader({ provider: 'vault' })).toThrow(SecretLoadError)
    expect(() => createSecretLoader({ provider: 'gsm' })).toThrow(SecretLoadError)
    expect(() => createSecretLoader({ provider: 'invalid' as any })).toThrow(SecretLoadError)
  })

  it('can read secrets from Vault when the endpoint responds with valid data', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => ({ data: { VAULT_SECRET: 'vault-value' } }),
    })) as typeof fetch)

    const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'vault-token')
    await loader.reload()
    expect(loader.get('VAULT_SECRET')).toBe('vault-value')
  })
})
