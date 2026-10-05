import { describe, it, expect } from 'vitest'

import { updateUserProfileSchema } from './users.schema.js'

// ─── helpers ────────────────────────────────────────────────────────────────

/** A minimal, always-valid profile record (arbitrary string keys, unknown values). */
function validProfile(): Record<string, unknown> {
  return {
    bio: 'Stellar builder',
    theme: 'dark',
    nested: { widget: { collapsed: true } },
    count: 3,
    ratio: 0.5,
    enabled: false,
    tags: ['defi', 'payments'],
    empty: null,
  }
}

// ─── accepted input ─────────────────────────────────────────────────────────

describe('updateUserProfileSchema — accepted input', () => {
  it('accepts an empty object because both fields are optional', () => {
    const result = updateUserProfileSchema.safeParse({})

    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data).toEqual({})
    }
  })

  it('accepts explicit undefined for both optional fields', () => {
    const result = updateUserProfileSchema.safeParse({ name: undefined, profile: undefined })

    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.name).toBeUndefined()
      expect(result.data.profile).toBeUndefined()
    }
  })

  it('accepts a name at the 100-character boundary', () => {
    const name = 'a'.repeat(100)
    const result = updateUserProfileSchema.safeParse({ name })

    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.name).toBe(name)
    }
  })

  it('accepts an empty name string', () => {
    const result = updateUserProfileSchema.safeParse({ name: '' })

    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.name).toBe('')
    }
  })

  it('accepts an arbitrary string-keyed profile record', () => {
    const profile = validProfile()
    const result = updateUserProfileSchema.safeParse({ profile })

    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.profile).toEqual(profile)
    }
  })

  it('accepts name and profile together without stripping either', () => {
    const profile = validProfile()
    const result = updateUserProfileSchema.safeParse({ name: 'Ada Lovelace', profile })

    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data).toEqual({ name: 'Ada Lovelace', profile })
    }
  })
})

// ─── rejected input ─────────────────────────────────────────────────────────

describe('updateUserProfileSchema — rejected input', () => {
  it('rejects a name longer than 100 characters', () => {
    const result = updateUserProfileSchema.safeParse({ name: 'a'.repeat(101) })

    expect(result.success).toBe(false)
    if (!result.success) {
      const issue = result.error.issues.find((i) => i.path[0] === 'name')
      expect(issue?.code).toBe('too_big')
    }
  })

  it('rejects a non-string name', () => {
    for (const name of [1, true, ['a'], { toString: () => 'x' }, Symbol('s')]) {
      const result = updateUserProfileSchema.safeParse({ name } as unknown)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path[0] === 'name')).toBe(true)
      }
    }
  })

  it('rejects null for name (optional is not nullable)', () => {
    const result = updateUserProfileSchema.safeParse({ name: null })

    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path[0] === 'name')).toBe(true)
    }
  })

  it('rejects a non-record profile', () => {
    for (const profile of ['text', 42, true, ['a', 'b']]) {
      const result = updateUserProfileSchema.safeParse({ profile } as unknown)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path[0] === 'profile')).toBe(true)
      }
    }
  })

  it('rejects null for profile', () => {
    const result = updateUserProfileSchema.safeParse({ profile: null })

    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path[0] === 'profile')).toBe(true)
    }
  })

  it('rejects unknown top-level keys because the schema is strict', () => {
    const result = updateUserProfileSchema.safeParse({ name: 'Ada', isAdmin: true })

    expect(result.success).toBe(false)
    if (!result.success) {
      const issue = result.error.issues.find((i) => i.code === 'unrecognized_keys')
      expect(issue).toBeDefined()
      expect((issue as { keys?: string[] }).keys).toContain('isAdmin')
    }
  })

  it('rejects non-object top-level payloads', () => {
    for (const payload of [null, [], 'name=Ada', 7, true]) {
      const result = updateUserProfileSchema.safeParse(payload)
      expect(result.success).toBe(false)
    }
  })
})

// ─── contract stability ─────────────────────────────────────────────────────

describe('updateUserProfileSchema — contract stability', () => {
  it('never mutates the input object', () => {
    const input = { name: 'Ada', profile: { bio: 'x' } }
    const snapshot = JSON.stringify(input)

    updateUserProfileSchema.safeParse(input)

    expect(JSON.stringify(input)).toBe(snapshot)
  })

  it('is deterministic for the same input', () => {
    const input = { name: 'Ada', profile: { bio: 'x' } }

    const first = updateUserProfileSchema.safeParse(input)
    const second = updateUserProfileSchema.safeParse(input)

    expect(first.success).toBe(second.success)
    if (first.success && second.success) {
      expect(first.data).toEqual(second.data)
    }
  })

  it('reports every rejection with an empty path for non-object payloads', () => {
    const result = updateUserProfileSchema.safeParse('not-an-object')

    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues).toHaveLength(1)
      expect(result.error.issues[0]?.path).toEqual([])
    }
  })
})
