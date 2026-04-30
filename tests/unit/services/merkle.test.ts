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
  const leaves = ['a', 'b', 'c', 'd', 'e'];

  it('produces a deterministic root', () => {
    const t1 = new MerkleTree(leaves);
    const t2 = new MerkleTree(leaves);
    expect(t1.getRoot()).toBe(t2.getRoot());
  });

  it('verifies a valid proof', () => {
    const tree = new MerkleTree(leaves);
    const index = 2;
    const proof = tree.getProof(index);
    const root = tree.getRoot();
    const ok = MerkleTree.verifyProof(leaves[index], proof, root, index);
    expect(ok).toBe(true);
  });

  it('rejects a tampered proof', () => {
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

  it('handles a single-leaf tree', () => {
    const tree = new MerkleTree(['only']);
    expect(tree.getRoot()).toHaveLength(64);
    expect(tree.getProof(0)).toEqual([]);
  });

  it('throws on empty leaf array', () => {
    expect(() => new MerkleTree([])).toThrow(RangeError);
  });

  it('throws on empty-string leaf', () => {
    expect(() => new MerkleTree(['a', ''])).toThrow(TypeError);
  });

  it('throws when leaf count exceeds MERKLE_MAX_LEAVES', () => {
    const original = process.env.MERKLE_MAX_LEAVES;
    // Temporarily lower the cap via the module constant by crafting oversized input
    // We test via the class directly — use a tiny cap via env trick in buildTree tests.
    // Here we just verify the guard message contains the right shape.
    const tooMany = Array.from({ length: MERKLE_MAX_LEAVES + 1 }, (_, i) => String(i));
    expect(() => new MerkleTree(tooMany)).toThrow(/exceeds/i);
    void original;
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
