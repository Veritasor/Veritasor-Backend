/**
 * @file merkle.ts
 * @description Public entry-point for the Merkle service.
 *
 * Exports the legacy `MerkleTree` class (Buffer-based API kept for backwards
 * compatibility) and re-exports everything from the modular implementation so
 * callers that import from `src/services/merkle` or
 * `src/services/merkle/buildTree` / `src/services/merkle/generateProof` all
 * resolve correctly.
 *
 * Performance guardrails live in `src/services/merkle/buildTree.ts`.
 * Proof guards live in `src/services/merkle/generateProof.ts`.
 */

import crypto from 'crypto';
import { MERKLE_MAX_LEAVES } from './merkle/buildTree.js';

// Re-export modular API so `import ... from 'src/services/merkle'` works.
export * from './merkle/index.js';

// ─── Internal helper (kept local to not pollute the module barrel) ────────────

function sha(data: Buffer, version: 1 | 2 = 2): Buffer {
  const hashFn = crypto.createHash('sha256');
  if (version === 1) {
    return hashFn.update(data).digest();
  }
  return hashFn.update(Buffer.concat([Buffer.from([0x00]), data])).digest();
}

function nodeHash(left: Buffer, right: Buffer, version: 1 | 2 = 2): Buffer {
  const hashFn = crypto.createHash('sha256');
  if (version === 1) {
    return hashFn.update(Buffer.concat([left, right])).digest();
  }
  return hashFn.update(Buffer.concat([Buffer.from([0x01]), left, right])).digest();
}

function expectedProofLength(leafIndex: number, treeSize: number): number {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return -1;
  if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) return -1;

  let currentIndex = leafIndex;
  let currentSize = treeSize;
  let length = 0;

  while (currentSize > 1) {
    if (currentIndex % 2 === 0) {
      if (currentIndex + 1 < currentSize) length += 1;
    } else {
      length += 1;
    }

    currentIndex = Math.floor(currentIndex / 2);
    currentSize = Math.ceil(currentSize / 2);
  }

  return length;
}

// ─── Legacy class ─────────────────────────────────────────────────────────────

/**
 * Buffer-based Merkle tree.
 *
 * Kept for backwards compatibility.  New code should prefer the functional API
 * (`buildTree` / `generateProof` / `verifyProof`) exported from this same
 * module.
 *
 * @throws {RangeError}  If leaf count is 0 or exceeds {@link MERKLE_MAX_LEAVES}.
 * @throws {TypeError}   If any leaf is an empty string.
 */
export class MerkleTree {
  private levels: Buffer[][] = [];

  constructor(leaves: (string | Buffer)[], version: 1 | 2 = 2) {
    if (!leaves || leaves.length === 0) {
      throw new RangeError('MerkleTree requires at least one leaf');
    }

    if (leaves.length > MERKLE_MAX_LEAVES) {
      throw new RangeError(
        `MerkleTree leaf count ${leaves.length} exceeds the maximum allowed (${MERKLE_MAX_LEAVES}). ` +
          'Raise MERKLE_MAX_LEAVES env var if intentional.'
      );
    }

    if (leaves.some((l) => typeof l === 'string' && l.length === 0)) {
      throw new TypeError('MerkleTree leaf values must be non-empty strings');
    }

    // level 0 (bottom) = hashed leaves
    this.levels[0] = leaves.map((l) =>
      typeof l === 'string' ? sha(Buffer.from(l), version) : sha(l, version)
    );

    let level = this.levels[0];
    while (level.length > 1) {
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        if (i + 1 < level.length) {
          const right = level[i + 1];
          next.push(nodeHash(left, right, version));
        } else {
          next.push(left);
        }
      }
      this.levels.unshift(next); // root ends up at levels[0]
      level = next;
    }
  }

  getRoot(): string {
    if (!this.levels || this.levels.length === 0) return '';
    return this.levels[0][0].toString('hex');
  }

  getProof(leafIndex: number): string[] {
    if (!this.levels || this.levels.length === 0) return [];
    const proof: string[] = [];
    let index = leafIndex;
    const bottomLevel = this.levels[this.levels.length - 1];
    if (index < 0 || index >= bottomLevel.length) return proof;

    for (let lvl = this.levels.length - 1; lvl > 0; lvl--) {
      const level = this.levels[lvl];
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
      if (siblingIndex >= 0 && siblingIndex < level.length) {
        proof.push(level[siblingIndex].toString('hex'));
      }
      index = Math.floor(index / 2);
    }

    return proof;
  }

  static verifyProof(
    leaf: string | Buffer,
    proof: string[],
    rootHex: string,
    leafIndex = 0,
    treeSize?: number,
    version: 1 | 2 = 2
  ): boolean {
    if (typeof treeSize === 'number') {
      const expectedLength = expectedProofLength(leafIndex, treeSize);
      if (expectedLength < 0 || proof.length !== expectedLength) return false;
    }

    let hashValue = typeof leaf === 'string' ? sha(Buffer.from(leaf), version) : sha(leaf, version);
    let index = leafIndex;
    for (const sibHex of proof) {
      const sibling = Buffer.from(sibHex, 'hex');
      hashValue =
        index % 2 === 0
          ? nodeHash(hashValue, sibling, version)
          : nodeHash(sibling, hashValue, version);
      index = Math.floor(index / 2);
    }
    return hashValue.toString('hex') === rootHex;
  }

  static verifyProofV1(
    leaf: string | Buffer,
    proof: string[],
    rootHex: string,
    leafIndex = 0,
    treeSize?: number
  ): boolean {
    return MerkleTree.verifyProof(leaf, proof, rootHex, leafIndex, treeSize, 1);
  }
}

export default MerkleTree;