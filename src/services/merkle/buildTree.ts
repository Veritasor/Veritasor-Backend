import { createHash } from 'crypto';

export function hash(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function buildTree(leaves: string[]): string[] {
  if (leaves.length === 0) throw new Error('Cannot build tree from empty leaves');

  // Hash all leaves
  let level: string[] = leaves.map((l) => hash(l));
  const tree: string[] = [...level];

  // Build up each level until we reach the root
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left; // duplicate last node if odd
      next.push(hash(left + right));
    }
    tree.push(...next);
    level = next;
  }

  return tree; // last element is the root
}

export function getRoot(tree: string[], leafCount: number): string {
  return tree[tree.length - 1];
}