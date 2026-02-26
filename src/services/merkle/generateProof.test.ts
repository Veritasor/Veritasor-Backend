import { buildTree, getRoot, hash } from './buildTree';
import { generateProof, verifyProof } from './generateProof';
const leaves = ['a', 'b', 'c', 'd'];

describe('Merkle proof', () => {
  it('generates a valid proof for each leaf', () => {
    const tree = buildTree(leaves);
    const root = getRoot(tree, leaves.length);

    leaves.forEach((leaf, i) => {
      const proof = generateProof(leaves, i);
      expect(verifyProof(leaf, proof, root)).toBe(true);
    });
  });

  it('fails verification with wrong root', () => {
    const proof = generateProof(leaves, 0);
    expect(verifyProof('a', proof, 'wrongroot')).toBe(false);
  });

  it('fails verification with wrong leaf', () => {
    const tree = buildTree(leaves);
    const root = getRoot(tree, leaves.length);
    const proof = generateProof(leaves, 0);
    expect(verifyProof('z', proof, root)).toBe(false);
  });

  it('handles odd number of leaves', () => {
    const oddLeaves = ['a', 'b', 'c'];
    const tree = buildTree(oddLeaves);
    const root = getRoot(tree, oddLeaves.length);
    const proof = generateProof(oddLeaves, 2);
    expect(verifyProof('c', proof, root)).toBe(true);
  });
});