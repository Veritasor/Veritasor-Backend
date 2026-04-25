/**
 * Fast-check Arbitrary Generators for Attestation Repository Property Tests
 *
 * This module provides custom generators for property-based testing of the attestation repository.
 * Each generator produces valid random inputs that conform to the expected formats and constraints.
 */

import fc from 'fast-check'
import { AttestationStatus, CreateAttestationInput, PaginationParams } from '../../../src/types/attestation.js'

export const uuidArbitrary = (): fc.Arbitrary<string> => {
  const hexChar = (): fc.Arbitrary<string> =>
    fc.integer({ min: 0, max: 15 }).map((n: number) => n.toString(16))

  return fc
    .tuple(
      fc.array(hexChar(), { minLength: 8, maxLength: 8 }),
      fc.array(hexChar(), { minLength: 4, maxLength: 4 }),
      fc.array(hexChar(), { minLength: 4, maxLength: 4 }),
      fc.array(hexChar(), { minLength: 4, maxLength: 4 }),
      fc.array(hexChar(), { minLength: 12, maxLength: 12 }),
    )
    .map(([a, b, c, d, e]: [string[], string[], string[], string[], string[]]) =>
      `${a.join('')}-${b.join('')}-${c.join('')}-${d.join('')}-${e.join('')}`,
    )
}

export const periodArbitrary = (): fc.Arbitrary<string> => {
  return fc.oneof(
    fc
      .tuple(
        fc.integer({ min: 2020, max: 2030 }),
        fc.integer({ min: 1, max: 12 }),
      )
      .map(([year, month]: [number, number]) => `${year}-${month.toString().padStart(2, '0')}`),

    fc
      .tuple(
        fc.integer({ min: 2020, max: 2030 }),
        fc.integer({ min: 1, max: 4 }),
      )
      .map(([year, quarter]: [number, number]) => `${year}-Q${quarter}`),
  )
}

export const merkleRootArbitrary = (): fc.Arbitrary<string> => {
  const hexChar = (): fc.Arbitrary<string> =>
    fc.integer({ min: 0, max: 15 }).map((n: number) => n.toString(16))

  return fc
    .array(hexChar(), { minLength: 64, maxLength: 64 })
    .map((chars: string[]) => `0x${chars.join('')}`)
}

export const txHashArbitrary = (): fc.Arbitrary<string> => {
  const hexChar = (): fc.Arbitrary<string> =>
    fc.integer({ min: 0, max: 15 }).map((n: number) => n.toString(16))

  return fc
    .array(hexChar(), { minLength: 64, maxLength: 64 })
    .map((chars: string[]) => `0x${chars.join('')}`)
}

export const statusArbitrary = (): fc.Arbitrary<AttestationStatus> => {
  return fc.constantFrom<AttestationStatus>('pending', 'submitted', 'confirmed', 'failed', 'revoked')
}

export const paginationParamsArbitrary = (): fc.Arbitrary<PaginationParams> => {
  return fc.record({
    limit: fc.integer({ min: 1, max: 100 }),
    offset: fc.integer({ min: 0, max: 1000 }),
  })
}

export const createAttestationInputArbitrary = (): fc.Arbitrary<CreateAttestationInput> => {
  return fc.record({
    businessId: uuidArbitrary(),
    period: periodArbitrary(),
    merkleRoot: merkleRootArbitrary(),
    txHash: txHashArbitrary(),
    status: statusArbitrary(),
  })
}

export const propertyTestConfig = {
  numRuns: 100,
}
