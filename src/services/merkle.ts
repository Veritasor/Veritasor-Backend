import crypto from 'crypto';

function sha(data: Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

export class MerkleTree {
  private levels: Buffer[][] = [];

  constructor(leaves: (string | Buffer)[]) {
    if (!leaves || leaves.length === 0) {
      throw new Error('MerkleTree requires at least one leaf');
    }

    if (leaves.some((l) => (typeof l === 'string' && l.length === 0))) {
      throw new Error('MerkleTree leaf values must be non-empty strings');
    }

    // level 0 = hashed leaves
    this.levels[0] = leaves.map((l) =>
      typeof l === 'string' ? sha(Buffer.from(l)) : sha(l)
    );

    // build upper levels
    let level = this.levels[0];
    while (level.length > 1) {
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = i + 1 < level.length ? level[i + 1] : level[i];
        next.push(sha(Buffer.concat([left, right])));
      }
      this.levels.unshift(next); // put at front so root becomes levels[0]
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
    // start from bottom level which is last element in this.levels
    let index = leafIndex;
    const bottomLevel = this.levels[this.levels.length - 1];
    if (index < 0 || index >= bottomLevel.length) return proof;

    for (let lvl = this.levels.length - 1; lvl > 0; lvl--) {
      const level = this.levels[lvl];
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
      const sibling = siblingIndex < level.length ? level[siblingIndex] : level[index];
      proof.push(sibling.toString('hex'));
      index = Math.floor(index / 2);
    }

    return proof;
  }

  static verifyProof(leaf: string | Buffer, proof: string[], rootHex: string, leafIndex = 0): boolean {
    let hash = typeof leaf === 'string' ? sha(Buffer.from(leaf)) : sha(leaf);
    let index = leafIndex;
    for (const sibHex of proof) {
      const sibling = Buffer.from(sibHex, 'hex');
      if (index % 2 === 0) {
        hash = sha(Buffer.concat([hash, sibling]));
      } else {
        hash = sha(Buffer.concat([sibling, hash]));
      }
      index = Math.floor(index / 2);
    }
    return hash.toString('hex') === rootHex;
  }
}

export default MerkleTree;
