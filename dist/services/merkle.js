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
function sha(data) {
    return crypto.createHash('sha256').update(data).digest();
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
    levels = [];
    constructor(leaves) {
        if (!leaves || leaves.length === 0) {
            throw new RangeError('MerkleTree requires at least one leaf');
        }
        if (leaves.length > MERKLE_MAX_LEAVES) {
            throw new RangeError(`MerkleTree leaf count ${leaves.length} exceeds the maximum allowed (${MERKLE_MAX_LEAVES}). ` +
                'Raise MERKLE_MAX_LEAVES env var if intentional.');
        }
        if (leaves.some((l) => typeof l === 'string' && l.length === 0)) {
            throw new TypeError('MerkleTree leaf values must be non-empty strings');
        }
        // level 0 (bottom) = hashed leaves
        this.levels[0] = leaves.map((l) => typeof l === 'string' ? sha(Buffer.from(l)) : sha(l));
        let level = this.levels[0];
        while (level.length > 1) {
            const next = [];
            for (let i = 0; i < level.length; i += 2) {
                const left = level[i];
                const right = i + 1 < level.length ? level[i + 1] : level[i];
                next.push(sha(Buffer.concat([left, right])));
            }
            this.levels.unshift(next); // root ends up at levels[0]
            level = next;
        }
    }
    getRoot() {
        if (!this.levels || this.levels.length === 0)
            return '';
        return this.levels[0][0].toString('hex');
    }
    getProof(leafIndex) {
        if (!this.levels || this.levels.length === 0)
            return [];
        const proof = [];
        let index = leafIndex;
        const bottomLevel = this.levels[this.levels.length - 1];
        if (index < 0 || index >= bottomLevel.length)
            return proof;
        for (let lvl = this.levels.length - 1; lvl > 0; lvl--) {
            const level = this.levels[lvl];
            const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
            const sibling = siblingIndex < level.length ? level[siblingIndex] : level[index];
            proof.push(sibling.toString('hex'));
            index = Math.floor(index / 2);
        }
        return proof;
    }
    static verifyProof(leaf, proof, rootHex, leafIndex = 0) {
        let hash = typeof leaf === 'string' ? sha(Buffer.from(leaf)) : sha(leaf);
        let index = leafIndex;
        for (const sibHex of proof) {
            const sibling = Buffer.from(sibHex, 'hex');
            hash =
                index % 2 === 0
                    ? sha(Buffer.concat([hash, sibling]))
                    : sha(Buffer.concat([sibling, hash]));
            index = Math.floor(index / 2);
        }
        return hash.toString('hex') === rootHex;
    }
}
export default MerkleTree;
