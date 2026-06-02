import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  EnvSecretLoader,
  FileSecretLoader,
  VaultSecretLoader,
  SecretNotFoundError,
  SecretLoadError,
} from './secret-loader.js'

const ORIGINAL_ENV = { ...process.env }
let tempDir = ''

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

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'secret-loader-'))
})

afterEach(async () => {
  restoreEnv()
  if (tempDir) {
    await fs.rm(tempDir, { recursive: true, force: true })
  }
  vi.restoreAllMocks()
})

describe('SecretLoader', () => {
  it('returns the current value after EnvSecretLoader.reload', async () => {
    process.env.TEST_SECRET = 'env-secret-value'
    const loader = new EnvSecretLoader()

    await loader.reload()

    expect(loader.get('TEST_SECRET')).toBe('env-secret-value')
  })

  it('throws SecretNotFoundError when the secret is missing', async () => {
    const loader = new EnvSecretLoader()

    await loader.reload()

    expect(() => loader.get('MISSING_SECRET')).toThrow(SecretNotFoundError)
  })

  it('reload picks up a changed environment secret', async () => {
    process.env.TEST_SECRET = 'first-value'
    const loader = new EnvSecretLoader()

    await loader.reload()
    expect(loader.get('TEST_SECRET')).toBe('first-value')

    process.env.TEST_SECRET = 'second-value'
    await loader.reload()
    expect(loader.get('TEST_SECRET')).toBe('second-value')
  })

  it('reload picks up a changed file secret', async () => {
    const secretPath = path.join(tempDir, 'secrets.json')
    await fs.writeFile(secretPath, JSON.stringify({ FILE_SECRET: 'first-file-value' }), 'utf8')

    const loader = new FileSecretLoader(secretPath)
    await loader.reload()
    expect(loader.get('FILE_SECRET')).toBe('first-file-value')

    await fs.writeFile(secretPath, JSON.stringify({ FILE_SECRET: 'second-file-value' }), 'utf8')
    await loader.reload()
    expect(loader.get('FILE_SECRET')).toBe('second-file-value')
  })

  it('throws a readable error when the secret file is missing', async () => {
    const loader = new FileSecretLoader(path.join(tempDir, 'missing.env'))

    await expect(loader.reload()).rejects.toThrow('Failed to read secret file')
  })

  it('loads secrets from a Vault-compatible HTTP endpoint', async () => {
    const response = {
      ok: true,
      status: 200,
      statusText: 'OK',
      json: vi.fn(async () => ({ data: { VAULT_SECRET: 'vault-value' } })),
    }

    vi.stubGlobal('fetch', vi.fn(async () => response) as typeof fetch)

    const loader = new VaultSecretLoader('https://vault.example.com', 'secrets/path', 'vault-token')
    await loader.reload()

    expect(loader.get('VAULT_SECRET')).toBe('vault-value')
    expect(response.json).toHaveBeenCalled()
  })
})
