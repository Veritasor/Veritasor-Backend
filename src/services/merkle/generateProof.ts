import { buildTree, hash } from './buildTree';

/**
 * Proof format:
 * An array of { sibling: string, position: 'left' | 'right' } objects.
 * To verify: starting from the hashed leaf, repeatedly hash(sibling + current)
 * or hash(current + sibling) depending on position, until you reach the root.
 */
export interface ProofStep {
  sibling: string;
  position: 'left' | 'right';
}

export type Proof = ProofStep[];

export function generateProof(leaves: string[], leafIndex: number): Proof {
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error('leafIndex out of range');
  }

  let level: string[] = leaves.map((l) => hash(l));
  let index = leafIndex;
  const proof: Proof = [];

  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    const sibling = siblingIndex < level.length ? level[siblingIndex] : level[index]; // duplicate if odd

    proof.push({
      sibling,
      position: index % 2 === 0 ? 'right' : 'left',
    });

    // Move up to next level
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(hash(left + right));
    }
    level = next;
    index = Math.floor(index / 2);
  }

  return proof;
}

/**
 * Verify a proof against a known root.
 */
export function verifyProof(leaf: string, proof: Proof, root: string): boolean {
  let current = hash(leaf);

  for (const step of proof) {
    if (step.position === 'right') {
      current = hash(current + step.sibling);
    } else {
      current = hash(step.sibling + current);
    }
  }

  return current === root;
}