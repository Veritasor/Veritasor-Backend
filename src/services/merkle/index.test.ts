import { describe, it, expect } from "vitest";
import {
  hash,
  buildTree,
  getRoot,
  MERKLE_MAX_LEAVES,
  MERKLE_WARN_LEAVES,
} from "./index.js";

import {
  generateProof,
  verifyProof,
  normalizeHashHex,
  isHashHex,
  isProofStep,
  isProof,
  MERKLE_PROOF_MAX_STEPS,
} from "./index.js";

import type { ProofStep, Proof } from "./index.js";

describe("merkle index – exported behavior", () => {
  describe("hash()", () => {
    it('returns a 64-character lowercase hex string', () => {
      const result = hash('hello');
      expect(result).toHaveLength(64);
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    });

    it('is deterministic – same input always produces the same output', () => {
      expect(hash('veritasor')).toBe(hash('veritasor'));
    });

    it('produces distinct output for distinct inputs', () => {
      expect(hash('a')).not.toBe(hash('b'));
    });
  });

  describe("MERKLE_MAX_LEAVES", () => {
    it('defaults to 1_048_576 when not set', () => {
      expect(MERKLE_MAX_LEAVES).toBe(1_048_576);
    });
  });

  describe("MERKLE_WARN_LEAVES", () => {
    it('is defined', () => {
      expect(typeof MERKLE_WARN_LEAVES).toBe('number');
    });
  });

  describe("MERKLE_PROOF_MAX_STEPS", () => {
    it('is 256', () => {
      expect(MERKLE_PROOF_MAX_STEPS).toBe(256);
    });
  });
});

describe("merkle index – success paths", () => {
  describe("buildTree() – happy paths", () => {
    it('single leaf: returns array of length 1', () => {
      const tree = buildTree(['alice']);
      expect(tree).toHaveLength(1);
      expect(tree[0]).toBe(hash('alice'));
    });

    it('single leaf: root equals the only element', () => {
      const tree = buildTree(['only']);
      expect(getRoot(tree)).toBe(tree[0]);
    });

    it('two leaves: returns [h0, h1, hash(h0+h1)]', () => {
      const tree = buildTree(['a', 'b']);
      const h0 = hash('a');
      const h1 = hash('b');
      expect(tree).toHaveLength(3);
      expect(tree[0]).toBe(h0);
      expect(tree[1]).toBe(h1);
      expect(tree[2]).toBe(hash(h0 + h1));
    });

    it('four leaves: correct 7-node tree', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      expect(tree).toHaveLength(7);
      const [h0, h1, h2, h3] = leaves.map(hash);
      expect(tree[0]).toBe(h0);
      expect(tree[1]).toBe(h1);
      expect(tree[2]).toBe(h2);
      expect(tree[3]).toBe(h3);
      const p01 = hash(h0 + h1);
      const p23 = hash(h2 + h3);
      expect(tree[4]).toBe(p01);
      expect(tree[5]).toBe(p23);
      expect(tree[6]).toBe(hash(p01 + p23));
    });

    it('odd leaf count: last leaf duplicated when pairing', () => {
      const tree = buildTree(['a', 'b', 'c']);
      const ha = hash('a');
      const hb = hash('b');
      const hc = hash('c');
      const p01 = hash(ha + hb);
      const p22 = hash(hc + hc);
      const root = hash(p01 + p22);
      expect(tree[tree.length - 1]).toBe(root);
    });

    it('root is always the last element', () => {
      for (const n of [1, 2, 3, 4, 5, 6, 7, 8]) {
        const leaves = Array.from({ length: n }, (_, i) => `leaf-${i}`);
        const tree = buildTree(leaves);
        expect(tree[tree.length - 1]).toBe(getRoot(tree));
      }
    });

    it('all nodes are 64-char hex strings', () => {
      const tree = buildTree(['foo', 'bar', 'baz']);
      for (const node of tree) {
        expect(node).toMatch(/^[0-9a-f]{64}$/);
      }
    });
  });

  describe("generateProof() – success paths", () => {
    it('generates valid proof for each leaf in a 4-leaf tree', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      leaves.forEach((leaf, i) => {
        const proof = generateProof(leaves, i);
        expect(verifyProof(leaf, proof, root)).toBe(true);
      });
    });

    it('handles odd number of leaves', () => {
      const oddLeaves = ['a', 'b', 'c'];
      const tree = buildTree(oddLeaves);
      const root = getRoot(tree, oddLeaves.length);
      const proof = generateProof(oddLeaves, 2);
      expect(verifyProof('c', proof, root)).toBe(true);
    });

    it('proof for first leaf in 3-leaf tree', () => {
      const oddLeaves = ['a', 'b', 'c'];
      const tree = buildTree(oddLeaves);
      const root = getRoot(tree, oddLeaves.length);
      const proof = generateProof(oddLeaves, 0);
      expect(verifyProof('a', proof, root)).toBe(true);
    });

    it('proof for second leaf in 3-leaf tree', () => {
      const oddLeaves = ['a', 'b', 'c'];
      const tree = buildTree(oddLeaves);
      const root = getRoot(tree, oddLeaves.length);
      const proof = generateProof(oddLeaves, 1);
      expect(verifyProof('b', proof, root)).toBe(true);
    });
  });

  describe("verifyProof() – success paths", () => {
    it('valid proof round-trips successfully', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      leaves.forEach((leaf, i) => {
        const proof = generateProof(leaves, i);
        expect(verifyProof(leaf, proof, root)).toBe(true);
      });
    });

    it('returns false for mismatched root', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const wrongRoot = '0'.repeat(64);
      const proof = generateProof(leaves, 0);
      expect(verifyProof('a', proof, wrongRoot)).toBe(false);
    });

    it('returns false for invalid leaf type', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      const proof = generateProof(leaves, 0);
      expect(verifyProof(123 as unknown as string, proof, root)).toBe(false);
    });

    it('returns false for invalid proof type', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      expect(verifyProof('a', {} as any, root)).toBe(false);
    });

    it('returns false for null leaf', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      const proof = generateProof(leaves, 0);
      expect(verifyProof(null as unknown as string, proof, root)).toBe(false);
    });

    it('returns false for null proof', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      expect(verifyProof('a', null as unknown as any, root)).toBe(false);
    });

    it('returns false for empty proof when tree has >1 leaf', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      expect(verifyProof('a', [], root)).toBe(false);
    });
  });
});

describe("merkle index – invalid inputs", () => {
  describe("hash() – invalid inputs", () => {
    it('handles various inputs as per buildTree contract', () => {
      expect(hash('')).toMatch(/^[0-9a-f]{64}$/);
      expect(hash('x')).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe("generateProof() – invalid inputs", () => {
    it('throws for empty leaves array', () => {
      expect(() => generateProof([], 0)).toThrow(
        'leaves must be a non-empty array of strings'
      );
    });

    it('throws for non-integer leafIndex', () => {
      expect(() => generateProof(['a'], 1.5)).toThrow(
        'leafIndex must be an integer'
      );
    });

    it('throws for leafIndex out of range (too high)', () => {
      expect(() => generateProof(['a', 'b'], 5)).toThrow(
        'leafIndex out of range'
      );
    });

    it('throws for leafIndex out of range (negative)', () => {
      expect(() => generateProof(['a', 'b'], -1)).toThrow(
        'leafIndex out of range'
      );
    });

    it('throws for non-string leaf in array', () => {
      expect(() => generateProof([42 as any], 0)).toThrow(
        'leaves must be a non-empty array of strings'
      );
    });
  });

  describe("verifyProof() – invalid inputs", () => {
    it('returns false for non-string leaf', () => {
      expect(verifyProof(123 as unknown as string, [] as any, 'root')).toBe(false);
    });

    it('returns false for null root', () => {
      expect(verifyProof('a', [], null as unknown as string)).toBe(false);
    });

    it('returns false for invalid proof structure', () => {
      expect(verifyProof('a', { sibling: 'x', position: 'right' } as any, 'root')).toBe(
        false
      );
    });

    it('returns false for non-hex root', () => {
      expect(verifyProof('a', [], 'not-hex')).toBe(false);
    });

    it('returns false for undefined leaf', () => {
      expect(verifyProof(undefined as unknown as string, [], 'root')).toBe(
        false
      );
    });
  });

  describe("normalizeHashHex() – invalid inputs", () => {
    it('returns null for non-string input', () => {
      expect(normalizeHashHex(123)).toBeNull();
    });

    it('returns null for string with invalid hex format', () => {
      expect(normalizeHashHex('not-hex')).toBeNull();
    });

    it('returns lowercase hex without 0x prefix', () => {
      expect(normalizeHashHex('0x' + 'a'.repeat(64))).toBe('a'.repeat(64));
    });

    it('returns lowercase hex with 0x prefix', () => {
      expect(normalizeHashHex('0x' + 'A'.repeat(64))).toBe('a'.repeat(64));
    });

    it('returns plain lowercase hex as-is', () => {
      expect(normalizeHashHex('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')).toBe(
        'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
      );
    });
  });

  describe("isHashHex() – invalid inputs", () => {
    it('returns true for valid 64-char hex string', () => {
      expect(isHashHex('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')).toBe(
        true
      );
    });

    it('returns true for hex with 0x prefix', () => {
      expect(isHashHex('0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')).toBe(
        true
      );
    });

    it('returns false for non-string', () => {
      expect(isHashHex(123)).toBe(false);
    });

    it('returns false for invalid hex', () => {
      expect(isHashHex('not-hex')).toBe(false);
    });

    it('returns false for too-short hex', () => {
      expect(isHashHex('abcd')).toBe(false);
    });
  });

  describe("isProofStep() – invalid inputs", () => {
    it('returns true for valid step', () => {
      expect(isProofStep({ sibling: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', position: 'right' })).toBe(
        true
      );
    });

    it('returns true for valid step with left position', () => {
      expect(isProofStep({ sibling: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', position: 'left' })).toBe(
        true
      );
    });

    it('returns false for missing position', () => {
      expect(isProofStep({ sibling: 'abcdef...' } as any)).toBe(false);
    });

    it('returns false for invalid position', () => {
      expect(isProofStep({ sibling: 'abcdef...', position: 'up' } as any)).toBe(false);
    });

    it('returns false for non-object', () => {
      expect(isProofStep('string' as any)).toBe(false);
    });

    it('returns false for null', () => {
      expect(isProofStep(null as any)).toBe(false);
    });
  });

  describe("isProof() – invalid inputs", () => {
    it('returns true for valid proof array', () => {
      expect(isProof([{ sibling: 'a'.repeat(64), position: 'right' }])).toBe(true);
    });

    it('returns false for non-array', () => {
      expect(isProof('string' as any)).toBe(false);
    });

    it('returns false for proof exceeding max steps', () => {
      const tooMany = new Array(MERKLE_PROOF_MAX_STEPS + 1).fill({ sibling: 'a'.repeat(64), position: 'right' });
      expect(isProof(tooMany as any)).toBe(false);
    });

    it('returns false for array with invalid step', () => {
      expect(isProof([{ sibling: 'a'.repeat(64), position: 'invalid' } as any])).toBe(false);
    });

    it('returns false for empty array', () => {
      expect(isProof([])).toBe(false);
    });
  });
});

describe("merkle index – primary state transitions", () => {
  it('generateProof followed by verifyProof round-trips for all indices in 7-leaf tree', () => {
    const leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
    const tree = buildTree(leaves);
    const root = getRoot(tree, leaves.length);
    leaves.forEach((leaf, i) => {
      const proof = generateProof(leaves, i);
      expect(verifyProof(leaf, proof, root)).toBe(true);
    });
  });

  it('buildTree with exactly MERKLE_MAX_LEAVES leaves succeeds', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '5');
    vi.resetModules();
    const { buildTree } = await import('./index.js');
    const exactly5 = ['a', 'b', 'c', 'd', 'e'];
    expect(() => buildTree(exactly5)).not.toThrow();
  });

  it('buildTree with one over MERKLE_MAX_LEAVES throws RangeError', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '3');
    vi.resetModules();
    const { buildTree } = await import('./index.js');
    const oversized = ['a', 'b', 'c', 'd'];
    expect(() => buildTree(oversized)).toThrow(RangeError);
  });

  it('verifyProof correctly validates proof length bounds', () => {
    const leaves = ['a', 'b', 'c', 'd'];
    const tree = buildTree(leaves);
    const root = getRoot(tree, leaves.length);
    const proof = generateProof(leaves, 0);
    expect(proof.length).toBe(2);
    expect(verifyProof(leaves[0], proof, root)).toBe(true);
  });

  it('isProof rejects proofs longer than MERKLE_PROOF_MAX_STEPS', () => {
    const tooManySteps = new Array(MERKLE_PROOF_MAX_STEPS + 1).fill({
      sibling: 'a'.repeat(64),
      position: 'right',
    });
    expect(isProof(tooManySteps as any)).toBe(false);
  });

  it('isProof accepts proof at exactly MERKLE_PROOF_MAX_STEPS length', () => {
    const exactlyAtLimit = new Array(MERKLE_PROOF_MAX_STEPS).fill({
      sibling: 'a'.repeat(64),
      position: 'right',
    });
    expect(isProof(exactlyAtLimit as any)).toBe(true);
  });
});