import { describe, it, expect } from 'vitest'
import MerkleTree from '../../../src/services/merkle'
import { buildTree, getRoot } from '../../../src/services/merkle/buildTree'
import {
  generateProof,
  verifyProof,
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
})
