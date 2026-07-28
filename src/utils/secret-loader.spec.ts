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

  describe('VaultAdapter lease renewal', () => {
    function leaseResponse(overrides: Record<string, unknown> = {}) {
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: vi.fn(async () => ({
          data: { VAULT_SECRET: 'vault-value' },
          lease_id: 'lease-1',
          lease_duration: 1000,
          renewable: true,
          ...overrides,
        })),
      }
    }

    function fakeTimer() {
      const scheduled: { cb: () => void; ms: number }[] = []
      const setTimeoutFn = vi.fn((cb: () => void, ms: number) => {
        const handle = { id: scheduled.length }
        scheduled.push({ cb, ms })
        return handle
      })
      const clearTimeoutFn = vi.fn()
      return { setTimeoutFn, clearTimeoutFn, scheduled }
    }

    it('schedules renewal at 70% of the lease duration when the lease is renewable', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => leaseResponse()) as typeof fetch)
      const { setTimeoutFn, scheduled } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', {
        setTimeoutFn,
        randomFn: () => 0.5, // jitterFraction = 0 -> exactly 70%
      })

      await loader.reload()

      expect(setTimeoutFn).toHaveBeenCalledTimes(1)
      expect(scheduled[0].ms).toBe(1000 * 1000 * 0.7)
    })

    it('applies up to +/-10% jitter around the 70% renewal delay', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => leaseResponse()) as typeof fetch)
      const { setTimeoutFn, scheduled } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', {
        setTimeoutFn,
        randomFn: () => 1, // maximum positive jitter
      })

      await loader.reload()

      const base = 1000 * 1000 * 0.7
      expect(scheduled[0].ms).toBe(Math.round(base * 1.1))
    })

    it('does not schedule renewal for a non-renewable lease', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => leaseResponse({ renewable: false })) as typeof fetch)
      const { setTimeoutFn } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', { setTimeoutFn })

      await loader.reload()

      expect(setTimeoutFn).not.toHaveBeenCalled()
    })

    it('does not schedule renewal for a static secret with no lease fields', async () => {
      const response = {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: vi.fn(async () => ({ data: { VAULT_SECRET: 'vault-value' } })),
      }
      vi.stubGlobal('fetch', vi.fn(async () => response) as typeof fetch)
      const { setTimeoutFn } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', { setTimeoutFn })

      await loader.reload()

      expect(setTimeoutFn).not.toHaveBeenCalled()
    })

    it('renews successfully, rotates the lease, and reschedules the next renewal', async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(leaseResponse())
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: 'OK',
          json: vi.fn(async () => ({ lease_id: 'lease-1', lease_duration: 2000, renewable: true })),
        })
      vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch)
      const { setTimeoutFn, scheduled } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', {
        setTimeoutFn,
        randomFn: () => 0.5,
      })

      await loader.reload()
      expect(scheduled).toHaveLength(1)

      // Manually fire the scheduled renewal.
      await scheduled[0].cb()

      expect(fetchMock).toHaveBeenCalledTimes(2)
      const renewCall = fetchMock.mock.calls[1]
      expect(renewCall[0]).toBe('https://vault.example.com/v1/sys/leases/renew')
      expect(renewCall[1]).toMatchObject({ method: 'PUT' })
      expect(JSON.parse(renewCall[1].body)).toEqual({ lease_id: 'lease-1', increment: 1000 })

      expect(loader.getLease()).toEqual({ leaseId: 'lease-1', leaseDurationSeconds: 2000, renewable: true })
      // Reschedule uses the new 2000s duration.
      expect(scheduled).toHaveLength(2)
      expect(scheduled[1].ms).toBe(2000 * 1000 * 0.7)
    })

    it('falls back to a full reload when renewal is denied (403)', async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(leaseResponse())
        .mockResolvedValueOnce({ ok: false, status: 403, statusText: 'Forbidden' })
        .mockResolvedValueOnce(leaseResponse({ lease_id: 'lease-2', lease_duration: 500 }))
      vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch)
      const { setTimeoutFn, scheduled } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', {
        setTimeoutFn,
        randomFn: () => 0.5,
      })

      await loader.reload()
      await scheduled[0].cb()

      expect(fetchMock).toHaveBeenCalledTimes(3) // initial load, denied renew, fallback reload
      expect(loader.getLease()?.leaseId).toBe('lease-2')
      expect(await loader.get('VAULT_SECRET')).toBe('vault-value')
    })

    it('retries sooner after a renewal request failure, without throwing', async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(leaseResponse())
        .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch)
      const { setTimeoutFn, scheduled } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', {
        setTimeoutFn,
        randomFn: () => 0.5,
      })

      await loader.reload()
      await expect(scheduled[0].cb()).resolves.toBeUndefined()

      expect(scheduled).toHaveLength(2)
      expect(scheduled[1].ms).toBe(30_000)
    })

    it('stopLeaseRenewal cancels the pending timer', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => leaseResponse()) as typeof fetch)
      const { setTimeoutFn, clearTimeoutFn } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', {
        setTimeoutFn,
        clearTimeoutFn,
      })

      await loader.reload()
      loader.stopLeaseRenewal()

      expect(clearTimeoutFn).toHaveBeenCalledTimes(1)
    })

    it('reload() cancels a previously scheduled renewal before scheduling a new one', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => leaseResponse()) as typeof fetch)
      const { setTimeoutFn, clearTimeoutFn } = fakeTimer()
      const loader = new VaultAdapter('https://vault.example.com', 'secrets/path', 'token', {
        setTimeoutFn,
        clearTimeoutFn,
      })

      await loader.reload()
      await loader.reload()

      expect(clearTimeoutFn).toHaveBeenCalledTimes(1)
      expect(setTimeoutFn).toHaveBeenCalledTimes(2)
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
