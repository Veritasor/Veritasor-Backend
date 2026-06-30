import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  EnvAdapter,
  VaultAdapter,
  AwsSecretsAdapter,
  createSecretLoader,
  SecretNotFoundError,
  SecretLoadError,
} from './secret-loader.js'

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

  describe('AwsSecretsAdapter', () => {
    it('loads secrets from AWS Secrets Manager', async () => {
      const mockSend = vi.fn(async () => ({
        SecretString: '{"AWS_SECRET": "aws-value"}',
      }))
      
      vi.mock('@aws-sdk/client-secrets-manager', () => ({
        SecretsManagerClient: vi.fn(() => ({ send: mockSend })),
        GetSecretValueCommand: vi.fn(),
      }))

      const loader = new AwsSecretsAdapter('us-east-1')
      await loader.reload()
      expect(await loader.get('test-secret')).toBe('aws-value')
      expect(mockSend).toHaveBeenCalled()
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
      
      vi.spyOn(failingLoader as any, 'primaryAdapter').mockImplementation(() => failingPrimary)
      
      await failingLoader.reload()
      expect(await failingLoader.get('FALLBACK_SECRET')).toBe('fallback-value')
    })

    it('times out and falls back to EnvAdapter', async () => {
      process.env.TIMEOUT_SECRET = 'timeout-fallback'
      
      const slowPrimary = {
        reload: vi.fn().mockImplementation(() => new Promise(() => {})),
        get: vi.fn().mockImplementation(() => new Promise(() => {})),
      }
      
      const timeoutLoader = createSecretLoader({
        provider: 'vault',
        vaultBaseUrl: 'https://vault.example.com',
        vaultSecretPath: 'secrets/path',
        timeout: 100,
      })
      
      vi.spyOn(timeoutLoader as any, 'primaryAdapter').mockImplementation(() => slowPrimary)
      
      await expect(timeoutLoader.reload()).resolves.not.toThrow()
      
      const getPromise = timeoutLoader.get('TIMEOUT_SECRET')
      vi.advanceTimersByTime(200)
      await expect(getPromise).resolves.toBe('timeout-fallback')
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

    it('throws when required Vault config is missing', () => {
      expect(() => createSecretLoader({ provider: 'vault' })).toThrow(SecretLoadError)
    })

    it('throws for unsupported provider', () => {
      expect(() => createSecretLoader({ provider: 'invalid' as any })).toThrow(SecretLoadError)
    })
  })
})
