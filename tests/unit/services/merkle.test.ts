/**
 * Merkle tree unit tests — golden vectors + edge cases.
 *
 * Hash algorithm: SHA-256 of the raw UTF-8 string (Node crypto).
 * Concatenation order: left || right (hex strings concatenated, then hashed).
 * Odd-leaf handling: the last leaf is duplicated at each level.
 *
 * Golden vectors were computed with:
 *   node -e "const {createHash}=require('crypto');const h=s=>createHash('sha256').update(s).digest('hex'); ..."
 */
import { describe, it, expect } from 'vitest'
import { buildTree, getRoot, hash } from '../../../src/services/merkle/buildTree'
import {
  generateProof,
  verifyProof,
  isProof,
  isProofStep,
  isHashHex,
  normalizeHashHex,
  MERKLE_PROOF_MAX_STEPS,
} from '../../../src/services/merkle/generateProof'

// ---------------------------------------------------------------------------
// Pre-computed golden vectors (SHA-256, raw string input)
// ---------------------------------------------------------------------------
const H = {
  a: 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
  b: '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
  c: '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
  d: '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
  ab: '62af5c3cb8da3e4f25061e829ebeea5c7513c54949115b1acc225930a90154da',
  cd: 'd3a0f1c792ccf7f1708d5422696263e35755a86917ea76ef9242bd4a8cf4891a',
  root4: '58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd',
  root3: '0bdf27bf7ec894ca7cadfe491ec1a3ece840f117989e8c5e9bd7086467bf6c38',
}

// ---------------------------------------------------------------------------
// hash() primitive
// ---------------------------------------------------------------------------
describe('hash()', () => {
  it('produces the correct SHA-256 hex for single characters', () => {
    expect(hash('a')).toBe(H.a)
    expect(hash('b')).toBe(H.b)
    expect(hash('c')).toBe(H.c)
    expect(hash('d')).toBe(H.d)
  })

  it('is deterministic across calls', () => {
    expect(hash('hello')).toBe(hash('hello'))
  })

  it('is sensitive to input — different inputs produce different hashes', () => {
    expect(hash('a')).not.toBe(hash('b'))
  })
})

// ---------------------------------------------------------------------------
// buildTree() + getRoot()
// ---------------------------------------------------------------------------
describe('buildTree()', () => {
  it('throws on empty leaves', () => {
    expect(() => buildTree([])).toThrow()
  })

  it('single leaf — root equals hash of that leaf', () => {
    const tree = buildTree(['a'])
    expect(getRoot(tree, 1)).toBe(H.a)
  })

  it('4-leaf tree — root matches golden vector', () => {
    const tree = buildTree(['a', 'b', 'c', 'd'])
    expect(getRoot(tree, 4)).toBe(H.root4)
  })

  it('3-leaf tree (odd) — root matches golden vector', () => {
    const tree = buildTree(['a', 'b', 'c'])
    expect(getRoot(tree, 3)).toBe(H.root3)
  })

  it('is deterministic — same leaves always produce the same root', () => {
    const t1 = buildTree(['x', 'y', 'z'])
    const t2 = buildTree(['x', 'y', 'z'])
    expect(getRoot(t1, 3)).toBe(getRoot(t2, 3))
  })
})

// ---------------------------------------------------------------------------
// generateProof() — structure and golden sibling values
// ---------------------------------------------------------------------------
describe('generateProof()', () => {
  it('throws on empty leaves array', () => {
    expect(() => generateProof([], 0)).toThrow(/non-empty/)
  })

  it('throws on non-array input', () => {
    expect(() => generateProof(null as any, 0)).toThrow()
  })

  it('throws on non-string leaf', () => {
    expect(() => generateProof([1 as any], 0)).toThrow()
  })

  it('throws on non-integer leafIndex', () => {
    expect(() => generateProof(['a', 'b'], 0.5)).toThrow(/integer/i)
  })

  it('throws on negative leafIndex', () => {
    expect(() => generateProof(['a', 'b'], -1)).toThrow(/out of range/)
  })

  it('throws on leafIndex >= leaves.length', () => {
    expect(() => generateProof(['a', 'b'], 2)).toThrow(/out of range/)
  })

  it('single leaf — proof is empty (leaf IS the root)', () => {
    const proof = generateProof(['a'], 0)
    expect(proof).toHaveLength(0)
  })

  it('2-leaf tree — proof has exactly 1 step', () => {
    const proof = generateProof(['a', 'b'], 0)
    expect(proof).toHaveLength(1)
  })

  it('4-leaf tree — proof has exactly 2 steps', () => {
    const proof = generateProof(['a', 'b', 'c', 'd'], 0)
    expect(proof).toHaveLength(2)
  })

  it('4-leaf tree, leaf 0 — golden sibling values', () => {
    const proof = generateProof(['a', 'b', 'c', 'd'], 0)
    // leaf 0 ('a'): sibling is h('b'), position right
    expect(proof[0]).toEqual({ sibling: H.b, position: 'right' })
    // next level: sibling is h(cd), position right
    expect(proof[1]).toEqual({ sibling: H.cd, position: 'right' })
  })

  it('4-leaf tree, leaf 2 — golden sibling values', () => {
    const proof = generateProof(['a', 'b', 'c', 'd'], 2)
    // leaf 2 ('c'): sibling is h('d'), position right
    expect(proof[0]).toEqual({ sibling: H.d, position: 'right' })
    // next level: sibling is h(ab), position left
    expect(proof[1]).toEqual({ sibling: H.ab, position: 'left' })
  })

  it('3-leaf tree, leaf 2 (odd) — sibling is duplicate of itself', () => {
    const proof = generateProof(['a', 'b', 'c'], 2)
    // leaf 2 ('c') has no right sibling → duplicated; sibling = h('c'), position right
    expect(proof[0].sibling).toBe(H.c)
    expect(proof[0].position).toBe('right')
  })
})

// ---------------------------------------------------------------------------
// verifyProof() — round-trip and rejection cases
// ---------------------------------------------------------------------------
describe('verifyProof()', () => {
  const leaves4 = ['a', 'b', 'c', 'd']
  const tree4 = buildTree(leaves4)
  const root4 = getRoot(tree4, 4)

  it('verifies all leaves in a 4-leaf tree', () => {
    for (let i = 0; i < leaves4.length; i++) {
      const proof = generateProof(leaves4, i)
      expect(verifyProof(leaves4[i], proof, root4)).toBe(true)
    }
  })

  it('verifies all leaves in a 3-leaf (odd) tree', () => {
    const leaves3 = ['a', 'b', 'c']
    const tree3 = buildTree(leaves3)
    const root3 = getRoot(tree3, 3)
    for (let i = 0; i < leaves3.length; i++) {
      const proof = generateProof(leaves3, i)
      expect(verifyProof(leaves3[i], proof, root3)).toBe(true)
    }
  })

  it('verifies a single-leaf tree (empty proof)', () => {
    expect(verifyProof('a', [], H.a)).toBe(true)
  })

  it('root matches golden vector for 4-leaf tree', () => {
    expect(root4).toBe(H.root4)
  })

  it('rejects wrong leaf', () => {
    const proof = generateProof(leaves4, 0)
    expect(verifyProof('z', proof, root4)).toBe(false)
  })

  it('rejects wrong root', () => {
    const proof = generateProof(leaves4, 0)
    expect(verifyProof('a', proof, H.root3)).toBe(false)
  })

  it('rejects a tampered sibling', () => {
    const proof = generateProof(leaves4, 0)
    const tampered = [
      { ...proof[0], sibling: proof[0].sibling.replace(/^./, '0') },
      ...proof.slice(1),
    ]
    expect(verifyProof('a', tampered, root4)).toBe(false)
  })

  it('rejects a flipped position', () => {
    const proof = generateProof(leaves4, 0)
    const flipped = [
      { ...proof[0], position: 'left' as const },
      ...proof.slice(1),
    ]
    expect(verifyProof('a', flipped, root4)).toBe(false)
  })

  it('accepts 0x-prefixed root and siblings', () => {
    const proof = generateProof(leaves4, 1)
    const prefixed = proof.map((s) => ({ ...s, sibling: `0x${s.sibling}` }))
    expect(verifyProof('b', prefixed, `0x${root4}`)).toBe(true)
  })

  it('rejects non-hex sibling', () => {
    const proof = generateProof(leaves4, 0)
    const bad = [{ ...proof[0], sibling: 'not-hex' }, ...proof.slice(1)]
    expect(verifyProof('a', bad as any, root4)).toBe(false)
  })

  it('rejects invalid position value', () => {
    const proof = generateProof(leaves4, 0)
    const bad = [{ ...proof[0], position: 'up' as any }, ...proof.slice(1)]
    expect(verifyProof('a', bad as any, root4)).toBe(false)
  })

  it('rejects proof exceeding MERKLE_PROOF_MAX_STEPS', () => {
    const proof = generateProof(leaves4, 0)
    const long = Array.from({ length: MERKLE_PROOF_MAX_STEPS + 1 }, () => proof[0])
    expect(verifyProof('a', long, root4)).toBe(false)
  })

  it('returns false for non-string leaf', () => {
    const proof = generateProof(leaves4, 0)
    expect(verifyProof(42 as any, proof, root4)).toBe(false)
  })

  it('returns false for invalid root hex', () => {
    const proof = generateProof(leaves4, 0)
    expect(verifyProof('a', proof, 'not-a-hash')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------
describe('isHashHex()', () => {
  it('accepts a valid 64-char lowercase hex string', () => {
    expect(isHashHex(H.a)).toBe(true)
  })

  it('accepts uppercase hex', () => {
    expect(isHashHex(H.a.toUpperCase())).toBe(true)
  })

  it('rejects strings shorter than 64 chars', () => {
    expect(isHashHex('abc')).toBe(false)
  })

  it('rejects non-hex characters', () => {
    expect(isHashHex('z'.repeat(64))).toBe(false)
  })

  it('rejects non-string values', () => {
    expect(isHashHex(null)).toBe(false)
    expect(isHashHex(123)).toBe(false)
  })
})

describe('normalizeHashHex()', () => {
  it('strips 0x prefix and lowercases', () => {
    expect(normalizeHashHex(`0x${H.a.toUpperCase()}`)).toBe(H.a)
  })

  it('returns null for invalid input', () => {
    expect(normalizeHashHex('short')).toBeNull()
    expect(normalizeHashHex(42 as any)).toBeNull()
  })
})

describe('isProofStep()', () => {
  it('accepts a valid step', () => {
    expect(isProofStep({ sibling: H.a, position: 'left' })).toBe(true)
    expect(isProofStep({ sibling: H.b, position: 'right' })).toBe(true)
  })

  it('rejects invalid position', () => {
    expect(isProofStep({ sibling: H.a, position: 'up' })).toBe(false)
  })

  it('rejects non-hex sibling', () => {
    expect(isProofStep({ sibling: 'nothex', position: 'left' })).toBe(false)
  })

  it('rejects non-object', () => {
    expect(isProofStep(null)).toBe(false)
    expect(isProofStep('string')).toBe(false)
  })
})

describe('isProof()', () => {
  it('accepts an empty proof array', () => {
    expect(isProof([])).toBe(true)
  })

  it('accepts a valid proof', () => {
    const proof = generateProof(['a', 'b', 'c', 'd'], 0)
    expect(isProof(proof)).toBe(true)
  })

  it('rejects non-array', () => {
    expect(isProof(null)).toBe(false)
    expect(isProof('string')).toBe(false)
  })

  it('rejects array exceeding MERKLE_PROOF_MAX_STEPS', () => {
    const step = { sibling: H.a, position: 'left' as const }
    const long = Array.from({ length: MERKLE_PROOF_MAX_STEPS + 1 }, () => step)
    expect(isProof(long)).toBe(false)
  })

  it('rejects array containing an invalid step', () => {
    expect(isProof([{ sibling: 'bad', position: 'left' }])).toBe(false)
  })
})
