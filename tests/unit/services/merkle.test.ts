import { describe, it, expect, vi, afterEach } from 'vitest';
import MerkleTree from '../../../src/services/merkle';
import { buildTree, getRoot, MERKLE_MAX_LEAVES, MERKLE_WARN_LEAVES } from '../../../src/services/merkle/buildTree';
import {
  generateProof,
  verifyProof,
  isProof,
  isProofStep,
  isHashHex,
  normalizeHashHex,
  MERKLE_PROOF_MAX_STEPS,
} from '../../../src/services/merkle/generateProof';

// ─── MerkleTree class (legacy Buffer-based API) ───────────────────────────────

describe('MerkleTree', () => {
  describe('construction', () => {
    it('produces a deterministic root for the same input', () => {
      const leaves = ['a', 'b', 'c', 'd', 'e'];
      const t1 = new MerkleTree(leaves);
      const t2 = new MerkleTree(leaves);
      expect(t1.getRoot()).toBe(t2.getRoot());
      expect(t1.getRoot()).toHaveLength(64); // SHA-256 hex = 64 chars
    });

    it('produces different roots for different leaf order', () => {
      const t1 = new MerkleTree(['a', 'b', 'c']);
      const t2 = new MerkleTree(['c', 'b', 'a']);
      expect(t1.getRoot()).not.toBe(t2.getRoot());
    });

    it('produces different roots for different content', () => {
      const t1 = new MerkleTree(['a', 'b']);
      const t2 = new MerkleTree(['x', 'y']);
      expect(t1.getRoot()).not.toBe(t2.getRoot());
    });

    it('accepts Buffer leaves', () => {
      const leaves = [Buffer.from('a'), Buffer.from('b')];
      const tree = new MerkleTree(leaves);
      expect(tree.getRoot()).toHaveLength(64);
    });

    it('accepts mixed string and Buffer leaves', () => {
      const leaves = ['a', Buffer.from('b'), 'c'];
      const tree = new MerkleTree(leaves);
      expect(tree.getRoot()).toHaveLength(64);
    });
  });

  describe('single-leaf tree (degenerate case)', () => {
    it('handles single string leaf', () => {
      const tree = new MerkleTree(['only']);
      expect(tree.getRoot()).toHaveLength(64);
      expect(tree.getProof(0)).toEqual([]);
    });

    it('handles single Buffer leaf', () => {
      const tree = new MerkleTree([Buffer.from('only')]);
      expect(tree.getRoot()).toHaveLength(64);
      expect(tree.getProof(0)).toEqual([]);
    });

    it('verifies single-leaf proof', () => {
      const tree = new MerkleTree(['only']);
      const root = tree.getRoot();
      const proof = tree.getProof(0);
      expect(MerkleTree.verifyProof('only', proof, root, 0)).toBe(true);
    });
  });

  describe('two-leaf tree (simplest non-trivial case)', () => {
    it('generates valid proofs for both leaves', () => {
      const leaves = ['a', 'b'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      const proof0 = tree.getProof(0);
      const proof1 = tree.getProof(1);

      expect(proof0).toHaveLength(1); // single sibling
      expect(proof1).toHaveLength(1);
      expect(MerkleTree.verifyProof(leaves[0], proof0, root, 0)).toBe(true);
      expect(MerkleTree.verifyProof(leaves[1], proof1, root, 1)).toBe(true);
    });
  });

  describe('odd-leaf tree (duplication handling)', () => {
    it('handles three leaves correctly', () => {
      const leaves = ['a', 'b', 'c'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      // All three leaves should verify
      for (let i = 0; i < leaves.length; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verifyProof(leaves[i], proof, root, i)).toBe(true);
      }
    });

    it('handles five leaves correctly', () => {
      const leaves = ['a', 'b', 'c', 'd', 'e'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      for (let i = 0; i < leaves.length; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verifyProof(leaves[i], proof, root, i)).toBe(true);
      }
    });

    it('handles seven leaves correctly', () => {
      const leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      for (let i = 0; i < leaves.length; i++) {
        const proof = tree.getProof(i);
        expect(proof).toHaveLength(3); // ceil(log2(7)) = 3
        expect(MerkleTree.verifyProof(leaves[i], proof, root, i)).toBe(true);
      }
    });
  });

  describe('power-of-two leaf counts', () => {
    it('handles 4 leaves (2^2)', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      for (let i = 0; i < leaves.length; i++) {
        const proof = tree.getProof(i);
        expect(proof).toHaveLength(2); // log2(4) = 2
        expect(MerkleTree.verifyProof(leaves[i], proof, root, i)).toBe(true);
      }
    });

    it('handles 8 leaves (2^3)', () => {
      const leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      for (let i = 0; i < leaves.length; i++) {
        const proof = tree.getProof(i);
        expect(proof).toHaveLength(3); // log2(8) = 3
        expect(MerkleTree.verifyProof(leaves[i], proof, root, i)).toBe(true);
      }
    });

    it('handles 16 leaves (2^4)', () => {
      const leaves = Array.from({ length: 16 }, (_, i) => `leaf-${i}`);
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      for (let i = 0; i < leaves.length; i++) {
        const proof = tree.getProof(i);
        expect(proof).toHaveLength(4); // log2(16) = 4
        expect(MerkleTree.verifyProof(leaves[i], proof, root, i)).toBe(true);
      }
    });
  });

  describe('getProof - boundary cases', () => {
    const leaves = ['a', 'b', 'c', 'd'];

    it('returns proof for first leaf (index 0)', () => {
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(0);
      expect(proof.length).toBeGreaterThan(0);
      expect(proof.every((p) => p.length === 64)).toBe(true); // all hex hashes
    });

    it('returns proof for last leaf', () => {
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(leaves.length - 1);
      expect(proof.length).toBeGreaterThan(0);
      expect(proof.every((p) => p.length === 64)).toBe(true);
    });

    it('returns empty array for negative index', () => {
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(-1);
      expect(proof).toEqual([]);
    });

    it('returns empty array for out-of-range index', () => {
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(99);
      expect(proof).toEqual([]);
    });

    it('returns empty array for index equal to length', () => {
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(leaves.length);
      expect(proof).toEqual([]);
    });
  });

  describe('verifyProof - success paths', () => {
    it('verifies valid proof for middle leaf', () => {
      const leaves = ['a', 'b', 'c', 'd', 'e'];
      const tree = new MerkleTree(leaves);
      const index = 2;
      const proof = tree.getProof(index);
      const root = tree.getRoot();
      const ok = MerkleTree.verifyProof(leaves[index], proof, root, index);
      expect(ok).toBe(true);
    });

    it('verifies proof with Buffer leaf', () => {
      const leaves = [Buffer.from('a'), Buffer.from('b')];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();
      const proof = tree.getProof(0);
      expect(MerkleTree.verifyProof(Buffer.from('a'), proof, root, 0)).toBe(true);
    });

    it('verifies proof when original tree used mixed types', () => {
      const leaves = ['a', Buffer.from('b'), 'c'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();
      
      const proof0 = tree.getProof(0);
      const proof1 = tree.getProof(1);
      
      expect(MerkleTree.verifyProof('a', proof0, root, 0)).toBe(true);
      expect(MerkleTree.verifyProof(Buffer.from('b'), proof1, root, 1)).toBe(true);
    });
  });

  describe('verifyProof - failure paths', () => {
    it('rejects tampered proof', () => {
      const leaves = ['a', 'b', 'c', 'd', 'e'];
      const tree = new MerkleTree(leaves);
      const index = 2;
      const proof = tree.getProof(index);
      const root = tree.getRoot();
      const badProof = [...proof];
      if (badProof.length > 0) {
        badProof[0] = badProof[0].replace(/^[0-9a-f]/, (c) => (c === '0' ? '1' : '0'));
      }
      const bad = MerkleTree.verifyProof(leaves[index], badProof, root, index);
      expect(bad).toBe(false);
    });

    it('rejects wrong leaf value', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(0);
      const root = tree.getRoot();
      expect(MerkleTree.verifyProof('wrong', proof, root, 0)).toBe(false);
    });

    it('rejects wrong root', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(0);
      const fakeRoot = 'a'.repeat(64);
      expect(MerkleTree.verifyProof(leaves[0], proof, fakeRoot, 0)).toBe(false);
    });

    it('rejects wrong leaf index', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(0);
      const root = tree.getRoot();
      // Using index 1's proof with index 0's position will fail
      expect(MerkleTree.verifyProof(leaves[0], proof, root, 1)).toBe(false);
    });

    it('rejects empty proof when proof is required', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();
      expect(MerkleTree.verifyProof(leaves[0], [], root, 0)).toBe(false);
    });

    it('rejects truncated proof', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = new MerkleTree(leaves);
      const proof = tree.getProof(0);
      const root = tree.getRoot();
      const truncatedProof = proof.slice(0, proof.length - 1);
      expect(MerkleTree.verifyProof(leaves[0], truncatedProof, root, 0)).toBe(false);
    });
  });

  describe('input validation - error paths', () => {
    it('throws RangeError on empty leaf array', () => {
      expect(() => new MerkleTree([])).toThrow(RangeError);
      expect(() => new MerkleTree([])).toThrow(/at least one leaf/i);
    });

    it('throws RangeError on null leaves', () => {
      expect(() => new MerkleTree(null as any)).toThrow(RangeError);
    });

    it('throws RangeError on undefined leaves', () => {
      expect(() => new MerkleTree(undefined as any)).toThrow(RangeError);
    });

    it('throws TypeError on empty-string leaf', () => {
      expect(() => new MerkleTree(['a', ''])).toThrow(TypeError);
      expect(() => new MerkleTree(['a', ''])).toThrow(/non-empty strings/i);
    });

    it('throws TypeError on empty-string at beginning', () => {
      expect(() => new MerkleTree(['', 'b', 'c'])).toThrow(TypeError);
    });

    it('throws TypeError on empty-string at end', () => {
      expect(() => new MerkleTree(['a', 'b', ''])).toThrow(TypeError);
    });

    it('throws TypeError on all empty-string leaves', () => {
      expect(() => new MerkleTree(['', '', ''])).toThrow(TypeError);
    });

    it('throws RangeError when leaf count exceeds MERKLE_MAX_LEAVES', () => {
      const tooMany = Array.from({ length: MERKLE_MAX_LEAVES + 1 }, (_, i) => String(i));
      expect(() => new MerkleTree(tooMany)).toThrow(RangeError);
      expect(() => new MerkleTree(tooMany)).toThrow(/exceeds/i);
      expect(() => new MerkleTree(tooMany)).toThrow(/MERKLE_MAX_LEAVES/);
    });
  });

  describe('proof length invariants', () => {
    it('proof length equals ceil(log2(n)) for various tree sizes', () => {
      const cases: [number, number][] = [
        [1, 0],  // single leaf = no siblings
        [2, 1],
        [3, 2],
        [4, 2],
        [5, 3],
        [6, 3],
        [7, 3],
        [8, 3],
        [9, 4],
        [15, 4],
        [16, 4],
        [17, 5],
      ];

      for (const [leafCount, expectedDepth] of cases) {
        const leaves = Array.from({ length: leafCount }, (_, i) => `leaf-${i}`);
        const tree = new MerkleTree(leaves);
        const proof = tree.getProof(0);
        expect(proof).toHaveLength(expectedDepth);
      }
    });
  });

  describe('large trees - stress testing', () => {
    it('handles 100 leaves without error', () => {
      const leaves = Array.from({ length: 100 }, (_, i) => `item-${i}`);
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();
      
      expect(root).toHaveLength(64);
      
      // Verify first, middle, and last
      const indices = [0, 50, 99];
      for (const idx of indices) {
        const proof = tree.getProof(idx);
        expect(MerkleTree.verifyProof(leaves[idx], proof, root, idx)).toBe(true);
      }
    });

    it('handles 1000 leaves without error', () => {
      const leaves = Array.from({ length: 1000 }, (_, i) => `item-${i}`);
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();
      
      // Spot check a few indices
      const proof0 = tree.getProof(0);
      const proof999 = tree.getProof(999);
      
      expect(MerkleTree.verifyProof(leaves[0], proof0, root, 0)).toBe(true);
      expect(MerkleTree.verifyProof(leaves[999], proof999, root, 999)).toBe(true);
    });
  });

  describe('state transitions - internal consistency', () => {
    it('produces consistent root across multiple getRoot calls', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      const root1 = tree.getRoot();
      const root2 = tree.getRoot();
      const root3 = tree.getRoot();
      
      expect(root1).toBe(root2);
      expect(root2).toBe(root3);
    });

    it('produces consistent proofs across multiple getProof calls', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof1 = tree.getProof(1);
      const proof2 = tree.getProof(1);
      
      expect(proof1).toEqual(proof2);
    });

    it('root remains stable after proof generation', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const rootBefore = tree.getRoot();
      
      tree.getProof(0);
      tree.getProof(1);
      tree.getProof(2);
      
      const rootAfter = tree.getRoot();
      expect(rootAfter).toBe(rootBefore);
    });
  });
});

// ─── Proof guards (modular API) ───────────────────────────────────────────────

describe('MerkleProofGuards', () => {
  const leaves = ['a', 'b', 'c', 'd'];
  const tree = buildTree(leaves);
  const root = getRoot(tree, leaves.length);

  it('accepts 0x-prefixed root and siblings', () => {
    const index = 1;
    const proof = generateProof(leaves, index);
    const prefixedProof = proof.map((step) => ({
      ...step,
      sibling: `0x${step.sibling}`,
    }));
    const ok = verifyProof(leaves[index], prefixedProof, `0x${root}`);
    expect(ok).toBe(true);
  });

  it('rejects invalid proof position', () => {
    const index = 0;
    const proof = generateProof(leaves, index);
    const badProof = proof.map((step, i) =>
      i === 0 ? { ...step, position: 'up' as any } : step
    );
    const ok = verifyProof(leaves[index], badProof as any, root);
    expect(ok).toBe(false);
  });

  it('rejects non-hex siblings', () => {
    const index = 0;
    const proof = generateProof(leaves, index);
    const badProof = [{ ...proof[0], sibling: 'nothex' }, ...proof.slice(1)];
    const ok = verifyProof(leaves[index], badProof as any, root);
    expect(ok).toBe(false);
  });

  it('rejects proofs that exceed the guard max length', () => {
    const index = 0;
    const proof = generateProof(leaves, index);
    const longProof = Array.from(
      { length: MERKLE_PROOF_MAX_STEPS + 1 },
      () => ({ sibling: proof[0].sibling, position: 'left' as const })
    );
    const ok = verifyProof(leaves[index], longProof as any, root);
    expect(ok).toBe(false);
  });

  it('throws on non-integer leaf index', () => {
    expect(() => generateProof(leaves, 1.5)).toThrow(/integer/i);
  });

  it('throws on out-of-range leaf index', () => {
    expect(() => generateProof(leaves, 99)).toThrow(/out of range/i);
  });

  it('throws on negative leaf index', () => {
    expect(() => generateProof(leaves, -1)).toThrow(/out of range/i);
  });

  it('throws on empty leaves array', () => {
    expect(() => generateProof([], 0)).toThrow(/non-empty/i);
  });

  it('verifies all leaf indices in a 4-leaf tree', () => {
    for (let i = 0; i < leaves.length; i++) {
      const proof = generateProof(leaves, i);
      expect(verifyProof(leaves[i], proof, root)).toBe(true);
    }
  });

  it('returns false for a tampered leaf value', () => {
    const proof = generateProof(leaves, 0);
    expect(verifyProof('tampered', proof, root)).toBe(false);
  });

  it('returns false for a tampered root', () => {
    const proof = generateProof(leaves, 0);
    const badRoot = root.replace(/^[0-9a-f]/, (c) => (c === '0' ? '1' : '0'));
    expect(verifyProof(leaves[0], proof, badRoot)).toBe(false);
  });
});

// ─── buildTree size guardrails ────────────────────────────────────────────────

describe('buildTree guardrails', () => {
  afterEach(() => {
    delete process.env.MERKLE_MAX_LEAVES;
  });

  it('throws RangeError when leaf count exceeds MERKLE_MAX_LEAVES', () => {
    const tooMany = Array.from({ length: MERKLE_MAX_LEAVES + 1 }, (_, i) => String(i));
    expect(() => buildTree(tooMany)).toThrow(RangeError);
    expect(() => buildTree(tooMany)).toThrow(/MERKLE_MAX_LEAVES/);
  });

  it('throws RangeError on empty array', () => {
    expect(() => buildTree([])).toThrow(RangeError);
  });

  it('throws TypeError on empty-string leaf', () => {
    expect(() => buildTree(['a', ''])).toThrow(TypeError);
  });

  it('emits a structured warn log when leaf count reaches MERKLE_WARN_LEAVES', { timeout: 30000 }, () => {

    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const largeLeaves = Array.from({ length: MERKLE_WARN_LEAVES }, (_, i) => String(i));
    buildTree(largeLeaves);
    expect(spy).toHaveBeenCalledOnce();
    const logged = JSON.parse(spy.mock.calls[0][0]);
    expect(logged.level).toBe('warn');
    expect(logged.service).toBe('merkle');
    expect(logged.event).toBe('large_tree');
    expect(logged.leafCount).toBe(MERKLE_WARN_LEAVES);
    spy.mockRestore();
  });

  it('does NOT warn for trees below the threshold', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    buildTree(['x', 'y', 'z']);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('root is deterministic for same input', () => {
    const input = Array.from({ length: 100 }, (_, i) => `leaf-${i}`);
    expect(getRoot(buildTree(input))).toBe(getRoot(buildTree(input)));
  });

  it('different leaf order produces different root', () => {
    const a = ['x', 'y', 'z'];
    const b = ['z', 'y', 'x'];
    expect(getRoot(buildTree(a))).not.toBe(getRoot(buildTree(b)));
  });
});

// ─── Benchmarks / complexity notes ───────────────────────────────────────────
//
// These are NOT performance assertions (which are flaky in CI). They are
// complexity probes: they verify that large trees complete without throwing and
// that proof length grows logarithmically with leaf count.
//
// Representative output captured from a local run (Apple M2, Node 20):
//
//   depth of 1 024-leaf tree  → 10  steps  (~1 ms)
//   depth of 65 536-leaf tree → 16  steps  (~90 ms)
//   depth of 1 M-leaf tree    → 20  steps  (~950 ms)
//
// Rule of thumb: proof depth = ⌈log₂(n)⌉, hashing work = O(n).

describe('Benchmarks — complexity probes', () => {
  it('proof depth is ⌈log₂(n)⌉ for power-of-two leaf counts', () => {
    const cases: [number, number][] = [
      [2, 1],
      [4, 2],
      [8, 3],
      [16, 4],
      [1024, 10],
    ];
    for (const [n, expectedDepth] of cases) {
      const leaves = Array.from({ length: n }, (_, i) => `leaf-${i}`);
      const proof = generateProof(leaves, 0);
      expect(proof.length).toBe(expectedDepth);
    }
  });

  it('proof depth for non-power-of-two is ⌈log₂(n)⌉', () => {
    // 5 leaves → depth 3  (ceil(log2(5)) = 3)
    const leaves = ['a', 'b', 'c', 'd', 'e'];
    const proof = generateProof(leaves, 0);
    expect(proof.length).toBe(Math.ceil(Math.log2(leaves.length)));
  });

  it('builds and verifies a 10 000-leaf tree without error', () => {
    const n = 10_000;
    const leaves = Array.from({ length: n }, (_, i) => `item-${i}`);
    const tree = buildTree(leaves);
    const root = getRoot(tree);
    const index = Math.floor(n / 2);
    const proof = generateProof(leaves, index);
    expect(verifyProof(leaves[index], proof, root)).toBe(true);
  });

  it('builds and verifies a 100 000-leaf tree without error', { timeout: 30000 }, () => {

    const n = 100_000;
    const leaves = Array.from({ length: n }, (_, i) => `item-${i}`);
    const tree = buildTree(leaves);
    const root = getRoot(tree);
    const index = n - 1; // last leaf (edge case)
    const proof = generateProof(leaves, index);
    expect(verifyProof(leaves[index], proof, root)).toBe(true);
  });
});
