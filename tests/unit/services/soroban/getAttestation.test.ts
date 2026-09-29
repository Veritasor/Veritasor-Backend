import { beforeEach, describe, expect, it, vi } from 'vitest'
import { rpc, scValToNative, xdr } from '@stellar/stellar-sdk'
import { getAttestation } from '../../../../src/services/soroban/getAttestation.js'
import { logger } from '../../../../src/utils/logger.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal success response — only the fields getAttestation actually reads. */
function makeSimSuccess(native: {
  merkle_root: string
  timestamp: bigint
  version?: bigint
}): rpc.Api.SimulateTransactionResponse {
  const entries = [
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('merkle_root'),
      val: xdr.ScVal.scvString(native.merkle_root),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('timestamp'),
      val: xdr.ScVal.scvU64(xdr.Uint64.fromString(native.timestamp.toString())),
    }),
  ]
  if (native.version !== undefined) {
    entries.push(
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol('version'),
        val: xdr.ScVal.scvU32(Number(native.version)),
      }),
    )
  }
  return {
    latestLedger: 1000,
    result: { retval: xdr.ScVal.scvMap(entries), auth: [] },
  } as unknown as rpc.Api.SimulateTransactionResponse
}

function makeSimVoid(): rpc.Api.SimulateTransactionResponse {
  return {
    latestLedger: 1000,
    result: { retval: xdr.ScVal.scvVoid(), auth: [] },
  } as unknown as rpc.Api.SimulateTransactionResponse
}

/** Contract-level failure. `rpc.Api.isSimulationError()` is `'error' in response`. */
function makeSimError(error: unknown): rpc.Api.SimulateTransactionResponse {
  return {
    latestLedger: 1000,
    error,
  } as unknown as rpc.Api.SimulateTransactionResponse
}

/** RPC replied successfully but without a `result` payload at all. */
function makeSimMissingResult(): rpc.Api.SimulateTransactionResponse {
  return { latestLedger: 1000 } as unknown as rpc.Api.SimulateTransactionResponse
}

/**
 * Runs `run()` while `config.soroban.contractId` resolves to an empty string.
 *
 * `config` is a module-level singleton, so the override is scoped and always
 * restored — the same pattern used in
 * `tests/unit/scripts/rebuild-indexer.test.ts`.
 */
async function withUnconfiguredContractId<T>(run: () => Promise<T>): Promise<T> {
  const { config } = await import('../../../../src/config/index.js')
  const sorobanConfig = config.soroban as unknown as { contractId: string }
  const originalContractId = sorobanConfig.contractId
  sorobanConfig.contractId = ''
  try {
    return await run()
  } finally {
    sorobanConfig.contractId = originalContractId
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('getAttestation staleness contract', () => {
  // A valid Stellar contract address (C…) — required by `new Address(business)`.
  const BUSINESS = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM'
  const PERIOD = '2026-01'

  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('returns fresh data on every call — no in-process caching', async () => {
    const spy = vi
      .spyOn(rpc.Server.prototype, 'simulateTransaction')
      .mockResolvedValueOnce(makeSimSuccess({ merkle_root: 'aabbcc', timestamp: 1_714_000_000n }))
      .mockResolvedValueOnce(makeSimSuccess({ merkle_root: 'ddeeff', timestamp: 1_714_000_060n }))

    const first = await getAttestation(BUSINESS, PERIOD)
    const second = await getAttestation(BUSINESS, PERIOD)

    expect(spy).toHaveBeenCalledTimes(2)
    expect(first?.merkle_root).toBe('aabbcc')
    // Second call reflects updated on-chain state — no stale cache hit.
    expect(second?.merkle_root).toBe('ddeeff')
  })

  it('reflects a revocation on the next call (no revocation lag from caching)', async () => {
    vi.spyOn(rpc.Server.prototype, 'simulateTransaction')
      .mockResolvedValueOnce(makeSimSuccess({ merkle_root: 'aabbcc', timestamp: 1_714_000_000n }))
      .mockResolvedValueOnce(makeSimVoid())

    const before = await getAttestation(BUSINESS, PERIOD)
    const after = await getAttestation(BUSINESS, PERIOD)

    expect(before).not.toBeNull()
    // After revocation the function must return null — a stale cache would
    // incorrectly return the old record here.
    expect(after).toBeNull()
  })

  it('reflects a write immediately on the next call (read-your-writes)', async () => {
    vi.spyOn(rpc.Server.prototype, 'simulateTransaction')
      .mockResolvedValueOnce(makeSimVoid())
      .mockResolvedValueOnce(makeSimSuccess({ merkle_root: 'cafebabe', timestamp: 1_714_000_005n }))

    const before = await getAttestation(BUSINESS, PERIOD)
    const after = await getAttestation(BUSINESS, PERIOD)

    expect(before).toBeNull()
    // The second call must see the newly written attestation without any
    // cache-invalidation step — because there is no cache.
    expect(after?.merkle_root).toBe('cafebabe')
  })

  it('propagates RPC transport errors without swallowing them', async () => {
    vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockRejectedValue(
      Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }),
    )

    await expect(getAttestation(BUSINESS, PERIOD)).rejects.toThrow('socket hang up')
  })

  it('returns null for a contract simulation error (e.g. bad input)', async () => {
    vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue({
      latestLedger: 1000,
      error: 'HostError: contract panicked',
    } as unknown as rpc.Api.SimulateTransactionResponse)

    const result = await getAttestation(BUSINESS, PERIOD)
    expect(result).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// AttestationResult failure / empty-result contract (issue #1011)
//
// Locks down the three failure and empty-result branches of `getAttestation`:
//   1. `throw new Error(...)` when SOROBAN_CONTRACT_ID is missing,
//   2. `return null` when the simulation reports a contract error,
//   3. `return null` when the simulation carries no result payload,
// plus the neighbouring success path, the `Option::None` empty result and the
// boundary inputs/values around them.
// ---------------------------------------------------------------------------

describe('AttestationResult failure and empty-result handling', () => {
  // A valid Stellar contract address (C…) — required by `new Address(business)`.
  const BUSINESS = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM'
  // A valid Stellar account address (G…) — the documented alternative form.
  const ACCOUNT_BUSINESS =
    'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5'
  const PERIOD = '2026-01'
  const CONTRACT_ERROR = 'HostError: Error(Contract, #4)'

  beforeEach(() => {
    vi.restoreAllMocks()
    // Failure handling must stay observable through the logger; silence the
    // transport itself so the suite output stays readable.
    vi.spyOn(logger, 'warn').mockImplementation(() => {})
    vi.spyOn(logger, 'error').mockImplementation(() => {})
  })

  describe('configuration failure — throw new Error (getAttestation.ts:133)', () => {
    it('throws a configuration error before issuing any RPC call', async () => {
      const simulateSpy = vi.spyOn(rpc.Server.prototype, 'simulateTransaction')

      const error = await withUnconfiguredContractId(() =>
        getAttestation(BUSINESS, PERIOD).catch((err: unknown) => err),
      )

      expect(error).toBeInstanceOf(Error)
      expect((error as Error).message).toContain(
        'SOROBAN_CONTRACT_ID is not configured',
      )
      // Fail fast: an unconfigured contract must never produce an RPC round-trip.
      expect(simulateSpy).not.toHaveBeenCalled()
    })

    it('reports the same failure on every call and never masks it as null', async () => {
      const capture = () =>
        withUnconfiguredContractId(() =>
          getAttestation(BUSINESS, PERIOD).then(
            () => null,
            (err: unknown) => err,
          ),
        )

      const first = await capture()
      const second = await capture()

      expect(first).toBeInstanceOf(Error)
      expect(second).toBeInstanceOf(Error)
      expect((first as Error).message).toBe((second as Error).message)
      // `null` is reserved for "no record"; a config failure must stay loud.
      expect(first).not.toBeNull()
    })
  })

  describe('simulation error — return null (getAttestation.ts:191)', () => {
    it('returns null and logs the contract error when the simulation fails', async () => {
      const simulateSpy = vi
        .spyOn(rpc.Server.prototype, 'simulateTransaction')
        .mockResolvedValue(makeSimError(CONTRACT_ERROR))
      const sendSpy = vi.spyOn(rpc.Server.prototype, 'sendTransaction')
      const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {})

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toBeNull()

      expect(simulateSpy).toHaveBeenCalledTimes(1)
      // The read path is simulation-only: nothing is ever broadcast.
      expect(sendSpy).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalledWith(
        { business: BUSINESS, period: PERIOD, error: CONTRACT_ERROR },
        'soroban: get_attestation contract error',
      )
    })

    it('never leaks a partial result when an error is reported alongside a retval', async () => {
      const response = makeSimSuccess({
        merkle_root: 'deadbeef',
        timestamp: 1_714_000_000n,
      })
      ;(response as unknown as { error?: string }).error = CONTRACT_ERROR
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        response,
      )

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toBeNull()
    })

    it('treats an `error` key holding undefined as a failure', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimError(undefined),
      )

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toBeNull()
    })

    it('does not persist the failure — the next successful simulation returns data', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction')
        .mockResolvedValueOnce(makeSimError(CONTRACT_ERROR))
        .mockResolvedValueOnce(
          makeSimSuccess({ merkle_root: 'beefbeef', timestamp: 5n }),
        )

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toBeNull()
      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toStrictEqual({
        merkle_root: 'beefbeef',
        timestamp: 5,
        version: undefined,
      })
    })
  })

  describe('missing result — return null (getAttestation.ts:200)', () => {
    it('returns null and warns when the simulation carries no result', async () => {
      const simulateSpy = vi
        .spyOn(rpc.Server.prototype, 'simulateTransaction')
        .mockResolvedValue(makeSimMissingResult())
      const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {})

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toBeNull()

      expect(simulateSpy).toHaveBeenCalledTimes(1)
      expect(warnSpy).toHaveBeenCalledWith(
        { business: BUSINESS, period: PERIOD },
        'soroban: get_attestation returned no result',
      )
    })

    it('returns null when `result` is present but undefined', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue({
        latestLedger: 1000,
        result: undefined,
      } as unknown as rpc.Api.SimulateTransactionResponse)

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toBeNull()
    })
  })

  describe('empty result — Option::None encoded as ScvVoid', () => {
    it('returns null without reporting a failure for a missing record', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimVoid(),
      )
      const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {})

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toBeNull()

      // "No record" is a documented success path, not a failure: no warning.
      expect(warnSpy).not.toHaveBeenCalled()
    })
  })

  describe('neighbouring success path', () => {
    it('maps a full contract payload onto AttestationResult', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimSuccess({
          merkle_root: 'a1b2c3d4',
          timestamp: 1_714_000_000n,
          version: 3n,
        }),
      )

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toStrictEqual({
        merkle_root: 'a1b2c3d4',
        timestamp: 1_714_000_000,
        version: 3,
      })
    })

    it('keeps the optional version key undefined when the contract omits it', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimSuccess({ merkle_root: 'a1b2c3d4', timestamp: 1_714_000_000n }),
      )

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toStrictEqual({
        merkle_root: 'a1b2c3d4',
        timestamp: 1_714_000_000,
        version: undefined,
      })
    })

    it('does not warn on the success path', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimSuccess({ merkle_root: 'a1b2c3d4', timestamp: 1_714_000_000n }),
      )
      const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {})

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.not.toBeNull()

      expect(warnSpy).not.toHaveBeenCalled()
    })
  })

  describe('boundary values returned by the contract', () => {
    it('preserves falsy values instead of dropping them', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimSuccess({ merkle_root: '', timestamp: 0n, version: 0n }),
      )

      await expect(getAttestation(BUSINESS, PERIOD)).resolves.toStrictEqual({
        merkle_root: '',
        timestamp: 0,
        version: 0,
      })
    })

    it('coerces the maximum exactly-representable u64 timestamp without loss', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimSuccess({
          merkle_root: 'ff',
          timestamp: BigInt(Number.MAX_SAFE_INTEGER),
        }),
      )

      const result = await getAttestation(BUSINESS, PERIOD)

      expect(result?.timestamp).toBe(Number.MAX_SAFE_INTEGER)
      expect(Number.isSafeInteger(result?.timestamp)).toBe(true)
    })

    it('documents the u64 → Number() precision boundary above MAX_SAFE_INTEGER', async () => {
      const unsafeTimestamp = BigInt(Number.MAX_SAFE_INTEGER) + 1n
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimSuccess({ merkle_root: 'ff', timestamp: unsafeTimestamp }),
      )

      const result = await getAttestation(BUSINESS, PERIOD)

      // Documented behaviour: the u64 is coerced with `Number()`, so values at
      // or above 2^53 lose precision rather than throwing or becoming NaN.
      expect(result?.timestamp).toBe(Number(unsafeTimestamp))
      expect(Number.isSafeInteger(result?.timestamp)).toBe(false)
    })

    it('coerces the maximum u32 version exactly', async () => {
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue(
        makeSimSuccess({
          merkle_root: 'ff',
          timestamp: 1n,
          version: 4_294_967_295n,
        }),
      )

      const result = await getAttestation(BUSINESS, PERIOD)

      expect(result?.version).toBe(4_294_967_295)
    })
  })

  describe('boundary inputs', () => {
    it('accepts a G… account strkey as the business address', async () => {
      const simulateSpy = vi
        .spyOn(rpc.Server.prototype, 'simulateTransaction')
        .mockResolvedValue(
          makeSimSuccess({ merkle_root: 'c0ffee', timestamp: 7n }),
        )

      await expect(
        getAttestation(ACCOUNT_BUSINESS, PERIOD),
      ).resolves.toStrictEqual({
        merkle_root: 'c0ffee',
        timestamp: 7,
        version: undefined,
      })
      expect(simulateSpy).toHaveBeenCalledTimes(1)
    })

    it('rejects a malformed business address deterministically, without an RPC call', async () => {
      const simulateSpy = vi.spyOn(rpc.Server.prototype, 'simulateTransaction')

      await expect(getAttestation('not-a-strkey', PERIOD)).rejects.toThrow(
        'Unsupported address type: not-a-strkey',
      )
      expect(simulateSpy).not.toHaveBeenCalled()
    })

    it('forwards an empty period string to the contract instead of short-circuiting', async () => {
      const simulateSpy = vi
        .spyOn(rpc.Server.prototype, 'simulateTransaction')
        .mockResolvedValue(makeSimVoid())

      await expect(getAttestation(BUSINESS, '')).resolves.toBeNull()

      expect(simulateSpy).toHaveBeenCalledTimes(1)
      const builtTx = simulateSpy.mock.calls[0]?.[0] as unknown as {
        operations: Array<{ func: xdr.HostFunction }>
      }
      const invocation = builtTx.operations[0].func.invokeContract()
      const args = invocation.args()

      // The empty period is still a valid Soroban String argument — the
      // validation boundary lives on-chain, not in this client.
      expect(invocation.functionName().toString()).toBe('get_attestation')
      expect(scValToNative(args[0])).toBe(BUSINESS)
      expect(scValToNative(args[1])).toBe('')
    })
  })
})
