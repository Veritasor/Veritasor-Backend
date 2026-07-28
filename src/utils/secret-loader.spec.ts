import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  EnvAdapter,
  VaultAdapter,
  AwsSecretsAdapter,
  GsmSecretAdapter,
  createSecretLoader,
  SecretNotFoundError,
  SecretLoadError,
} from './secret-loader.js'
import { logger } from './logger.js'

let mockSend: ReturnType<typeof vi.fn>

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn(function () { return { send: mockSend } }),
  GetSecretValueCommand: vi.fn(),
}))

let mockSend: ReturnType<typeof vi.fn>
let mockAccessSecretVersion: ReturnType<typeof vi.fn>

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn(function () { return { send: mockSend } }),
  GetSecretValueCommand: vi.fn(),
}))

vi.mock('@google-cloud/secret-manager', () => ({
  SecretManagerServiceClient: vi.fn(function () {
    return { accessSecretVersion: mockAccessSecretVersion }
  }),
}))

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
  vi.useFakeTimers()
})

afterEach(() => {
  restoreEnv()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('SecretLoader', () => {
  describe('EnvAdapter', () => {
    it('returns environment variable value', async () => {
      process.env.TEST_SECRET = 'env-secret-value'
      const loader = new EnvAdapter()
      await loader.reload()
      expect(await loader.get('TEST_SECRET')).toBe('env-secret-value')
    })

    it('throws SecretNotFoundError when secret is missing', async () => {
      const loader = new EnvAdapter()
      await loader.reload()
      await expect(loader.get('MISSING_SECRET')).rejects.toThrow(SecretNotFoundError)
    })
  })

  describe('VaultAdapter', () => {
    it('loads secrets from Vault', async () => {
      const response = {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: vi.fn(async () => ({ data: { VAULT_SECRET: 'vault-value' } })),
      }
      vi.stubGlobal('fetch', vi.fn(async () => response) as typeof fetch)

      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'vault-token')
      await loader.reload()
      expect(await loader.get('VAULT_SECRET')).toBe('vault-value')
      expect(response.json).toHaveBeenCalled()
    })
  })

  describe('GsmSecretAdapter', () => {
    beforeEach(() => {
      mockAccessSecretVersion = vi.fn()
    })

    it('loads secrets from Google Secret Manager', async () => {
      mockAccessSecretVersion.mockResolvedValue([{
        payload: { data: Buffer.from('gsm-value', 'utf8') },
      }])

      const loader = new GsmSecretAdapter('my-project')
      await loader.reload()
      expect(await loader.get('MY_SECRET')).toBe('gsm-value')
      expect(mockAccessSecretVersion).toHaveBeenCalledWith({
        name: 'projects/my-project/secrets/MY_SECRET/versions/latest',
      })
    })

    it('throws SecretLoadError on API error', async () => {
      mockAccessSecretVersion.mockRejectedValue(new Error('NOT_FOUND'))

      const loader = new GsmSecretAdapter('my-project')
      await loader.reload()

      await expect(loader.get('MISSING')).rejects.toThrow(SecretLoadError)
    })

    it('throws SecretLoadError on permission denied', async () => {
      mockAccessSecretVersion.mockRejectedValue(new Error('PermissionDenied'))

      const loader = new GsmSecretAdapter('my-project')
      await loader.reload()

      await expect(loader.get('SECRET')).rejects.toThrow(SecretLoadError)
    })

    it('throws SecretLoadError when payload is empty', async () => {
      mockAccessSecretVersion.mockResolvedValue([{ payload: undefined }])

      const loader = new GsmSecretAdapter('my-project')
      await loader.reload()

      await expect(loader.get('EMPTY')).rejects.toThrow(SecretLoadError)
    })
  })

  describe('AwsSecretsAdapter', () => {
    beforeEach(() => {
      mockSend = vi.fn()
    })

    it('loads secrets from AWS Secrets Manager', async () => {
      mockSend.mockResolvedValue({ SecretString: '{"AWS_SECRET": "aws-value"}' })

      const loader = new AwsSecretsAdapter('us-east-1')
      await loader.reload()
      expect(await loader.get('test-secret')).toBe('aws-value')
      expect(mockSend).toHaveBeenCalledTimes(1)
    })
  })

  describe('Failover mechanism', () => {
    it('falls back to EnvAdapter when primary provider fails', async () => {
      process.env.FALLBACK_SECRET = 'fallback-value'

      const failingPrimary = {
        reload: vi.fn().mockRejectedValue(new Error('Primary failed')),
        get: vi.fn().mockRejectedValue(new Error('Primary failed')),
      }

      const failingLoader = createSecretLoader({
        provider: 'vault',
        vaultBaseUrl: 'https://vault.example.com',
        vaultSecretPath: 'secrets/path',
      })

      ;(failingLoader as any).primaryAdapter = failingPrimary

      await failingLoader.reload()
      expect(await failingLoader.get('FALLBACK_SECRET')).toBe('fallback-value')
    })

    it('times out and falls back to EnvAdapter', async () => {
      vi.useRealTimers()
      process.env.TIMEOUT_SECRET = 'timeout-fallback'

      const slowPrimary = {
        reload: vi.fn().mockImplementation(() => new Promise(() => {})),
        get: vi.fn().mockImplementation(() => new Promise(() => {})),
      }

      const timeoutLoader = createSecretLoader({
        provider: 'vault',
        vaultBaseUrl: 'https://vault.example.com',
        vaultSecretPath: 'secrets/path',
        timeout: 50,
      })

      ;(timeoutLoader as any).primaryAdapter = slowPrimary

      await expect(timeoutLoader.reload()).resolves.not.toThrow()

      const result = await timeoutLoader.get('TIMEOUT_SECRET')
      expect(result).toBe('timeout-fallback')
    })
  })

  describe('createSecretLoader factory', () => {
    it('creates EnvAdapter by default', () => {
      const loader = createSecretLoader()
      expect(loader).toBeDefined()
    })

    it('uses SECRET_PROVIDER environment variable', () => {
      process.env.SECRET_PROVIDER = 'env'
      const loader = createSecretLoader()
      expect(loader).toBeDefined()
    })

    it('throws when required AWS config is missing', () => {
      expect(() => createSecretLoader({ provider: 'aws' })).toThrow(SecretLoadError)
    })

    it('accepts awsSecondaryRegion option', () => {
      expect(() => createSecretLoader({
        provider: 'aws',
        awsRegion: 'us-east-1',
        awsSecondaryRegion: 'us-west-2',
      })).not.toThrow()
    })

    it('throws when required Vault config is missing', () => {
      expect(() => createSecretLoader({ provider: 'vault' })).toThrow(SecretLoadError)
    })

    it('accepts gcpProjectId option', () => {
      expect(() => createSecretLoader({
        provider: 'gsm',
        gcpProjectId: 'my-project',
      })).not.toThrow()
    })

    it('throws when required GCP config is missing', () => {
      expect(() => createSecretLoader({ provider: 'gsm' })).toThrow(SecretLoadError)
    })

    it('throws for unsupported provider', () => {
      expect(() => createSecretLoader({ provider: 'invalid' as any })).toThrow(SecretLoadError)
    })
  })
})
