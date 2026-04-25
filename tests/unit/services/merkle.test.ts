import { describe, it, expect } from 'vitest'
import MerkleTree from '../../../src/services/merkle'
import { buildTree, getRoot } from '../../../src/services/merkle/buildTree'
import {
  generateProof,
  verifyProof,
  MERKLE_MAX_LEAVES,
  MERKLE_PROOF_MAX_STEPS,
} from '../../../src/services/merkle/generateProof'

describe('MerkleTree', () => {
  const leaves = ['a', 'b', 'c', 'd', 'e']

  it('produces a deterministic root', () => {
    const t1 = new MerkleTree(leaves)
    const t2 = new MerkleTree(leaves)
    expect(t1.getRoot()).toBe(t2.getRoot())
  })

  it('verifies a valid proof', () => {
    const tree = new MerkleTree(leaves)
    const index = 2
    const proof = tree.getProof(index)
    const root = tree.getRoot()
    const ok = MerkleTree.verifyProof(leaves[index], proof, root, index)
    expect(ok).toBe(true)
  })

  it('rejects a tampered proof', () => {
    const tree = new MerkleTree(leaves)
    const index = 2
    const proof = tree.getProof(index)
    const root = tree.getRoot()
    const badProof = [...proof]
    if (badProof.length > 0) {
      badProof[0] = badProof[0].replace(/^[0-9a-f]/, (c) => (c === '0' ? '1' : '0'))
    }
    const bad = MerkleTree.verifyProof(leaves[index], badProof, root, index)
    expect(bad).toBe(false)
  })

  // --- perf / guard cases ---

  it('rejects leaf count above MERKLE_MAX_LEAVES', () => {
    // Build a stub array that reports a length above the cap without allocating 1M strings.
    const oversized = { length: MERKLE_MAX_LEAVES + 1, [Symbol.iterator]: [][Symbol.iterator] } as unknown as string[]
    // MerkleTree checks leaves.length before iterating, so this is safe.
    expect(() => new MerkleTree(oversized as any)).toThrow(/MERKLE_MAX_LEAVES/)
  })

  it('completes a 1 000-leaf tree within 500 ms', () => {
    const big = Array.from({ length: 1_000 }, (_, i) => `leaf-${i}`)
    const t0 = performance.now()
    const tree = new MerkleTree(big)
    const elapsed = performance.now() - t0
    expect(tree.getRoot()).toHaveLength(64)
    expect(elapsed).toBeLessThan(500)
  })

  it('proof depth is O(log n) for a 1 024-leaf tree', () => {
    const n = 1_024
    const big = Array.from({ length: n }, (_, i) => `leaf-${i}`)
    const tree = new MerkleTree(big)
    const proof = tree.getProof(0)
    // log2(1024) = 10
    expect(proof.length).toBe(Math.ceil(Math.log2(n)))
  })
})

describe('MerkleProofGuards', () => {
  const leaves = ['a', 'b', 'c', 'd']
  const tree = buildTree(leaves)
  const root = getRoot(tree, leaves.length)

  it('accepts 0x-prefixed root and siblings', () => {
    const index = 1
    const proof = generateProof(leaves, index)
    const prefixedProof = proof.map((step) => ({
      ...step,
      sibling: `0x${step.sibling}`,
    }))
    const ok = verifyProof(leaves[index], prefixedProof, `0x${root}`)
    expect(ok).toBe(true)
  })

  it('rejects invalid proof position', () => {
    const index = 0
    const proof = generateProof(leaves, index)
    const badProof = proof.map((step, i) =>
      i === 0 ? { ...step, position: 'up' as any } : step
    )
    const ok = verifyProof(leaves[index], badProof as any, root)
    expect(ok).toBe(false)
  })

  it('rejects non-hex siblings', () => {
    const index = 0
    const proof = generateProof(leaves, index)
    const badProof = [
      { ...proof[0], sibling: 'nothex' },
      ...proof.slice(1),
    ]
    const ok = verifyProof(leaves[index], badProof as any, root)
    expect(ok).toBe(false)
  })

  it('rejects proofs that exceed the guard max length', () => {
    const index = 0
    const proof = generateProof(leaves, index)
    const longProof = Array.from(
      { length: MERKLE_PROOF_MAX_STEPS + 1 },
      () => ({ sibling: proof[0].sibling, position: 'left' as const })
    )
    const ok = verifyProof(leaves[index], longProof as any, root)
    expect(ok).toBe(false)
  })

  it('throws on non-integer leaf index', () => {
    expect(() => generateProof(leaves, 1.5)).toThrow(/integer/i)
  })

  // --- perf / guard cases ---

  it('rejects leaf count above MERKLE_MAX_LEAVES', () => {
    const oversized = new Array(MERKLE_MAX_LEAVES + 1).fill('x')
    expect(() => generateProof(oversized, 0)).toThrow(/MERKLE_MAX_LEAVES/)
  })

  it('generateProof completes a 1 000-leaf proof within 500 ms', () => {
    const big = Array.from({ length: 1_000 }, (_, i) => `leaf-${i}`)
    const t0 = performance.now()
    const proof = generateProof(big, 0)
    const elapsed = performance.now() - t0
    expect(proof.length).toBeGreaterThan(0)
    expect(elapsed).toBeLessThan(500)
  })

  it('proof depth is O(log n) for 1 024 leaves', () => {
    const n = 1_024
    const big = Array.from({ length: n }, (_, i) => `leaf-${i}`)
    const proof = generateProof(big, 0)
    expect(proof.length).toBe(Math.ceil(Math.log2(n)))
  })

  it('verifyProof round-trips a large proof correctly', () => {
    const big = Array.from({ length: 256 }, (_, i) => `leaf-${i}`)
    const bigTree = buildTree(big)
    const bigRoot = getRoot(bigTree, big.length)
    const index = 127
    const proof = generateProof(big, index)
    expect(verifyProof(big[index], proof, bigRoot)).toBe(true)
  })
})
