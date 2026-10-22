import { describe, expect, it } from 'vitest';

import { buildTree, buildTreeV1, hashNodeV2, hashV2 } from '../buildTree.js';
import {
  generateProof,
  generateProofV1,
  verifyProof,
  verifyProofV1,
} from '../generateProof.js';

describe('Merkle domain separation and proof validation', () => {
  it('v2 roots differ for [a,b,c] versus [a,b,c,c]', () => {
    const root1 = buildTree(['a', 'b', 'c'], 2).at(-1)!;
    const root2 = buildTree(['a', 'b', 'c', 'c'], 2).at(-1)!;
    expect(root1).not.toBe(root2);
  });

  it('a proof with an extra or missing step is rejected when treeSize is supplied', () => {
    const leaves = ['a', 'b', 'c', 'd'];
    const leaf = leaves[1];
    const root = buildTree(leaves, 2).at(-1)!;
    const proof = generateProof(leaves, 1, 2);

    expect(verifyProof(leaf, proof, root, 1, leaves.length, 2)).toBe(true);
    expect(verifyProof(leaf, proof.slice(0, -1), root, 1, leaves.length, 2)).toBe(false);
    expect(verifyProof(leaf, [...proof, proof[0]], root, 1, leaves.length, 2)).toBe(false);
  });

  it('an internal node preimage used as a leaf fails v2 verification', () => {
    const leaves = ['a', 'b', 'c'];
    const root = buildTree(leaves, 2).at(-1)!;
    const proof = generateProof(leaves, 0, 2);
    const forgedLeaf = hashNodeV2(hashV2('a'), hashV2('b'));
    const forgedProof = proof.slice(1);

    expect(verifyProof(forgedLeaf, forgedProof, root, 0, leaves.length, 2)).toBe(false);
  });

  it('legacy v1 roots still verify using the v1 verifier', () => {
    const leaves = ['a', 'b', 'c'];
    const root = buildTreeV1(leaves).at(-1)!;
    const proof = generateProofV1(leaves, 1);
    const leaf = leaves[1];

    expect(verifyProofV1(leaf, proof, root, 1, leaves.length)).toBe(true);
  });
});
