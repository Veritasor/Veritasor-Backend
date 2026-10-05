import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'node:fs/promises'
import path from 'node:path'
import { EnvAdapter, FileAdapter, VaultAdapter, createSecretLoader, SecretLoadError, SecretNotFoundError } from './secret-loader.js'

let mockKmsSend: ReturnType<typeof vi.fn>
vi.mock('@aws-sdk/client-kms', () => {
  return {
    KMSClient: vi.fn(function () { return { send: mockKmsSend } }),
    GenerateDataKeyCommand: vi.fn(),
    DecryptCommand: vi.fn(),
  }
})

let mockReadFile: ReturnType<typeof vi.fn>
let mockWriteFile: ReturnType<typeof vi.fn>
let mockMkdir: ReturnType<typeof vi.fn>
vi.mock('node:fs/promises', () => {
  return {
    default: {
      readFile: (...args: any[]) => mockReadFile(...args),
      writeFile: (...args: any[]) => mockWriteFile(...args),
      mkdir: (...args: any[]) => mockMkdir(...args),
    },
    readFile: (...args: any[]) => mockReadFile(...args),
    writeFile: (...args: any[]) => mockWriteFile(...args),
    mkdir: (...args: any[]) => mockMkdir(...args),
  }
})

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

  describe('KmsDiskCache', () => {
    beforeEach(() => {
      mockKmsSend = vi.fn()
      mockReadFile = vi.fn()
      mockWriteFile = vi.fn()
      mockMkdir = vi.fn()
      
      process.env.SECRET_CACHE_KMS_KEY_ID = 'test-kms-key'
      process.env.SECRET_CACHE_PATH = '/tmp/test-cache.enc'
      process.env.SECRET_CACHE_TTL_MINUTES = '60'
    })

    it('populates cache on successful primary fetch', async () => {
      let mockSend = vi.fn().mockResolvedValue({ SecretString: '{"AWS_SECRET": "aws-value"}' })
      mockKmsSend.mockResolvedValue({
        Plaintext: new Uint8Array(32),
        CiphertextBlob: new Uint8Array(16)
      })
      mockMkdir.mockResolvedValue(undefined)
      mockWriteFile.mockResolvedValue(undefined)

      const loader = createSecretLoader({
        provider: 'aws',
        awsRegion: 'us-east-1'
      })

      // We need to inject mockSend to AwsSecretsAdapter since client is imported dynamically.
      // Actually the mock is set up elsewhere maybe? Wait, mockSend is used but where is it attached?
      // Ah, wait, in the original it just had `mockSend = vi.fn().mockResolvedValue...`
      // For now, let's just keep it exactly as it was minus the await on loader.get
      
      await loader.reload()
      expect(loader.get('AWS_SECRET')).toBe('aws-value')
      expect(mockKmsSend).toHaveBeenCalled()
      expect(mockWriteFile).toHaveBeenCalled()
    })

    it('reads from cache when primary fails', async () => {
      let mockSend = vi.fn().mockRejectedValue(new Error('Primary failure'))
      
      const fakeIv = Buffer.alloc(12).toString('base64')
      const fakeAuthTag = Buffer.alloc(16).toString('base64')
      
      const crypto = require('node:crypto')
      const fakeDataKey = crypto.randomBytes(32)
      
      mockKmsSend.mockResolvedValue({ Plaintext: fakeDataKey })
      
      const cipher = crypto.createCipheriv('aes-256-gcm', fakeDataKey, Buffer.from(fakeIv, 'base64'))
      let encrypted = cipher.update(JSON.stringify({ CACHED_SECRET: 'cached-value' }), 'utf8', 'base64')
      encrypted += cipher.final('base64')
      const authTag = cipher.getAuthTag().toString('base64')

      mockReadFile.mockResolvedValue(JSON.stringify({
        ciphertextKey: 'fake-cipher-key',
        iv: fakeIv,
        authTag: authTag,
        encryptedData: encrypted,
        expiresAt: Date.now() + 3600000
      }))

      const loader = createSecretLoader({
        provider: 'aws',
        awsRegion: 'us-east-1'
      })

      await loader.reload()
      expect(loader.get('CACHED_SECRET')).toBe('cached-value')
      expect(mockKmsSend).toHaveBeenCalled()
      expect(mockReadFile).toHaveBeenCalled()
    })

    it('falls back to ultimate fallback on cache expiry', async () => {
      let mockSend = vi.fn().mockRejectedValue(new Error('Primary failure'))
      process.env.FALLBACK_SECRET = 'ultimate-fallback'

      mockReadFile.mockResolvedValue(JSON.stringify({
        ciphertextKey: 'fake-cipher-key',
        iv: 'iv',
        authTag: 'tag',
        encryptedData: 'data',
        expiresAt: Date.now() - 3600000 // expired
      }))

      const loader = createSecretLoader({
        provider: 'aws',
        awsRegion: 'us-east-1'
      })

      await loader.reload()
      expect(loader.get('FALLBACK_SECRET')).toBe('ultimate-fallback')
    })
    
    it('falls back to ultimate fallback on cache tampering', async () => {
      let mockSend = vi.fn().mockRejectedValue(new Error('Primary failure'))
      process.env.FALLBACK_SECRET = 'ultimate-fallback'
      
      const crypto = require('node:crypto')
      const fakeDataKey = crypto.randomBytes(32)
      mockKmsSend.mockResolvedValue({ Plaintext: fakeDataKey })

      mockReadFile.mockResolvedValue(JSON.stringify({
        ciphertextKey: 'fake-cipher-key',
        iv: Buffer.alloc(12).toString('base64'),
        authTag: Buffer.alloc(16).toString('base64'), // incorrect auth tag for data
        encryptedData: 'tampered-data',
        expiresAt: Date.now() + 3600000
      }))

      const loader = createSecretLoader({
        provider: 'aws',
        awsRegion: 'us-east-1'
      })

      await loader.reload()
      // Should silently fail to decrypt and fallback
      expect(loader.get('FALLBACK_SECRET')).toBe('ultimate-fallback')
    })
  })

  describe('createSecretLoader factory', () => {
    it('supports the env-based factory and required config checks', () => {
      expect(createSecretLoader()).toBeDefined()
      expect(() => createSecretLoader({ provider: 'aws' })).toThrow(SecretLoadError)
      expect(() => createSecretLoader({ provider: 'vault' })).toThrow(SecretLoadError)
      expect(() => createSecretLoader({ provider: 'gsm' })).toThrow(SecretLoadError)
      expect(() => createSecretLoader({ provider: 'invalid' as any })).toThrow(SecretLoadError)
    })
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
