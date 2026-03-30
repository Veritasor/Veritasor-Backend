import { beforeEach, describe, expect, it, vi } from 'vitest'
import { rpc } from '@stellar/stellar-sdk'
import {
  SorobanRpcTimeoutError,
  createSorobanRpcServer,
  executeSorobanRequest,
  getSorobanConfig,
  getSorobanRetryPolicy,
  isRetryableSorobanError,
} from '../../../../src/services/soroban/client.js'

describe('Soroban client retry and timeout policy', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
    process.env = { ...originalEnv }
    delete process.env.SOROBAN_RPC_TIMEOUT_MS
    delete process.env.SOROBAN_RPC_MAX_RETRIES
    delete process.env.SOROBAN_RPC_RETRY_BASE_DELAY_MS
    delete process.env.SOROBAN_RPC_RETRY_MAX_DELAY_MS
    delete process.env.SOROBAN_RPC_RETRY_JITTER_RATIO
  })

  describe('getSorobanConfig', () => {
    it('validates the contract id and returns sane defaults', () => {
      process.env.SOROBAN_CONTRACT_ID =
        'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM'

      const config = getSorobanConfig()

      expect(config.rpcUrl).toBe('https://soroban-testnet.stellar.org')
      expect(config.networkPassphrase).toBe('Test SDF Network ; September 2015')
      expect(config.contractId).toBe(process.env.SOROBAN_CONTRACT_ID)
    })

    it('rejects an invalid contract id early', () => {
      process.env.SOROBAN_CONTRACT_ID = 'invalid-contract-id'

      expect(() => getSorobanConfig()).toThrow(
        'Invalid SOROBAN_CONTRACT_ID. Expected a valid Stellar contract address (C...).',
      )
    })

    it('requires the contract id to be configured', () => {
      delete process.env.SOROBAN_CONTRACT_ID

      expect(() => getSorobanConfig()).toThrow(
        'Missing required environment variable: SOROBAN_CONTRACT_ID',
      )
    })
  })

  describe('getSorobanRetryPolicy', () => {
    it('reads bounded retry settings from the environment', () => {
      process.env.SOROBAN_RPC_TIMEOUT_MS = '900'
      process.env.SOROBAN_RPC_MAX_RETRIES = '4'
      process.env.SOROBAN_RPC_RETRY_BASE_DELAY_MS = '25'
      process.env.SOROBAN_RPC_RETRY_MAX_DELAY_MS = '100'
      process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '0.4'

      expect(getSorobanRetryPolicy()).toEqual({
        timeoutMs: 900,
        maxRetries: 4,
        retryBaseDelayMs: 25,
        retryMaxDelayMs: 100,
        retryJitterRatio: 0.4,
      })
    })

    it('rejects invalid retry settings that would disable bounded behavior', () => {
      process.env.SOROBAN_RPC_RETRY_BASE_DELAY_MS = '200'
      process.env.SOROBAN_RPC_RETRY_MAX_DELAY_MS = '100'

      expect(() => getSorobanRetryPolicy()).toThrow(
        'Invalid Soroban retry policy. retryBaseDelayMs must be less than or equal to retryMaxDelayMs.',
      )
    })

    it('rejects invalid jitter ratios', () => {
      process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '1.5'

      expect(() => getSorobanRetryPolicy()).toThrow(
        'Invalid SOROBAN_RPC_RETRY_JITTER_RATIO. Expected a number between 0 and 1.',
      )
    })

    it('rejects non-integer timeout values', () => {
      process.env.SOROBAN_RPC_TIMEOUT_MS = 'slow'

      expect(() => getSorobanRetryPolicy()).toThrow(
        'Invalid SOROBAN_RPC_TIMEOUT_MS. Expected an integer between 100 and 60000.',
      )
    })
  })

  describe('isRetryableSorobanError', () => {
    it('treats transient network errors and timeouts as retryable', () => {
      const timeoutError = new SorobanRpcTimeoutError('timed out', 100, 'getAccount')
      const networkError = Object.assign(new Error('socket hang up'), {
        code: 'ECONNRESET',
      })

      expect(isRetryableSorobanError(timeoutError)).toBe(true)
      expect(isRetryableSorobanError(networkError)).toBe(true)
    })

    it('does not retry deterministic validation errors', () => {
      expect(isRetryableSorobanError(new Error('invalid contract id'))).toBe(
        false,
      )
    })

    it('returns false for non-error throwables', () => {
      expect(isRetryableSorobanError('network error')).toBe(false)
    })
  })

  describe('executeSorobanRequest', () => {
    it('retries a transient transport failure and then succeeds', async () => {
      const execute = vi
        .fn<() => Promise<string>>()
        .mockRejectedValueOnce(
          Object.assign(new Error('network error'), { code: 'ETIMEDOUT' }),
        )
        .mockResolvedValueOnce('ok')
      const sleep = vi.fn(async () => undefined)

      const result = await executeSorobanRequest({
        operationName: 'simulateTransaction',
        execute,
        policy: {
          timeoutMs: 50,
          maxRetries: 1,
          retryBaseDelayMs: 5,
          retryMaxDelayMs: 5,
          retryJitterRatio: 0,
        },
        sleep,
      })

      expect(result).toBe('ok')
      expect(execute).toHaveBeenCalledTimes(2)
      expect(sleep).toHaveBeenCalledTimes(1)
      expect(sleep).toHaveBeenCalledWith(5)
    })

    it('applies jittered backoff while keeping the delay bounded', async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(
          Object.assign(new Error('network error'), { code: 'ETIMEDOUT' }),
        )
        .mockResolvedValueOnce('ok')
      const sleep = vi.fn(async () => undefined)

      await executeSorobanRequest({
        operationName: 'simulateTransaction',
        execute,
        policy: {
          timeoutMs: 50,
          maxRetries: 1,
          retryBaseDelayMs: 10,
          retryMaxDelayMs: 10,
          retryJitterRatio: 0.5,
        },
        sleep,
        random: () => 1,
      })

      expect(sleep).toHaveBeenCalledWith(15)
    })

    it('retries a TRY_AGAIN_LATER response and returns the eventual success response', async () => {
      const execute = vi
        .fn<() => Promise<{ status: string; hash: string }>>()
        .mockResolvedValueOnce({
          status: 'TRY_AGAIN_LATER',
          hash: 'first',
        })
        .mockResolvedValueOnce({
          status: 'PENDING',
          hash: 'final',
        })
      const sleep = vi.fn(async () => undefined)

      const result = await executeSorobanRequest({
        operationName: 'sendTransaction',
        execute,
        shouldRetryResult: (value) => value.status === 'TRY_AGAIN_LATER',
        policy: {
          timeoutMs: 50,
          maxRetries: 1,
          retryBaseDelayMs: 7,
          retryMaxDelayMs: 7,
          retryJitterRatio: 0,
        },
        sleep,
      })

      expect(result).toEqual({
        status: 'PENDING',
        hash: 'final',
      })
      expect(execute).toHaveBeenCalledTimes(2)
      expect(sleep).toHaveBeenCalledWith(7)
    })

    it('fails fast with a SorobanRpcTimeoutError when an attempt exceeds the timeout budget', async () => {
      const execute = vi.fn(
        () => new Promise<string>(() => undefined),
      )

      await expect(
        executeSorobanRequest({
          operationName: 'getAccount',
          execute,
          policy: {
            timeoutMs: 10,
            maxRetries: 0,
            retryBaseDelayMs: 1,
            retryMaxDelayMs: 1,
            retryJitterRatio: 0,
          },
        }),
      ).rejects.toMatchObject({
        name: 'SorobanRpcTimeoutError',
        timeoutMs: 10,
        operationName: 'getAccount',
      })
    })

    it('does not retry non-retryable failures', async () => {
      const execute = vi
        .fn()
        .mockRejectedValue(new Error('validation failure'))
      const sleep = vi.fn(async () => undefined)

      await expect(
        executeSorobanRequest({
          operationName: 'prepareTransaction',
          execute,
          policy: {
            timeoutMs: 50,
            maxRetries: 2,
            retryBaseDelayMs: 1,
            retryMaxDelayMs: 1,
            retryJitterRatio: 0,
          },
          sleep,
        }),
      ).rejects.toThrow('validation failure')

      expect(execute).toHaveBeenCalledTimes(1)
      expect(sleep).not.toHaveBeenCalled()
    })
  })

  describe('createSorobanRpcServer', () => {
    it('applies the retry wrapper to getAccount', async () => {
      const getAccountSpy = vi
        .spyOn(rpc.Server.prototype, 'getAccount')
        .mockRejectedValueOnce(
          Object.assign(new Error('temporary network issue'), {
            code: 'ECONNRESET',
          }),
        )
        .mockResolvedValueOnce({ id: 'account' } as never)

      const server = createSorobanRpcServer('http://127.0.0.1:8000', {
        timeoutMs: 50,
        maxRetries: 1,
        retryBaseDelayMs: 1,
        retryMaxDelayMs: 1,
        retryJitterRatio: 0,
      })

      await expect(server.getAccount('GTEST')).resolves.toEqual({ id: 'account' })
      expect(getAccountSpy).toHaveBeenCalledTimes(2)
    })

    it('retries TRY_AGAIN_LATER sendTransaction responses', async () => {
      const sendTransactionSpy = vi
        .spyOn(rpc.Server.prototype, 'sendTransaction')
        .mockResolvedValueOnce({
          status: 'TRY_AGAIN_LATER',
          hash: 'retry-me',
        } as never)
        .mockResolvedValueOnce({
          status: 'PENDING',
          hash: 'tx_final',
        } as never)

      const server = createSorobanRpcServer('http://127.0.0.1:8000', {
        timeoutMs: 50,
        maxRetries: 1,
        retryBaseDelayMs: 1,
        retryMaxDelayMs: 1,
        retryJitterRatio: 0,
      })

      await expect(server.sendTransaction({} as never)).resolves.toMatchObject({
        status: 'PENDING',
        hash: 'tx_final',
      })
      expect(sendTransactionSpy).toHaveBeenCalledTimes(2)
    })

    it('reuses wrapped methods and preserves non-wrapped properties', () => {
      const server = createSorobanRpcServer('http://127.0.0.1:8000')

      expect(server.getAccount).toBe(server.getAccount)
      expect(server.serverURL.toString()).toBe('http://127.0.0.1:8000/')
      expect(typeof server.toString).toBe('function')
    })
  })
})
