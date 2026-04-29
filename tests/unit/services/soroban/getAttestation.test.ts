import { beforeEach, describe, expect, it, vi } from 'vitest'
import { rpc, xdr } from '@stellar/stellar-sdk'
import { getAttestation } from '../../../../src/services/soroban/getAttestation.js'

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
