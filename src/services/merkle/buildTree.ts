/**
 * Merkle tree builder for revenue entries or pre-hashed leaves.
 *
 * Hash: SHA-256 (same as ../merkle.ts).
 * Encoding (entries): Canonical string per entry = JSON with sorted keys for
 *   id, amount, currency, date, source only (raw excluded). Key order: amount, currency, date, id, source.
 * Order: Leaves are sorted by hash (hex string ascending) before building so
 *   the same set of inputs always yields the same root.
 */

import crypto from 'crypto';
import MerkleTree from '../merkle.js';
import type { RevenueEntry } from '../revenue/razorpayFetch.js';

const CANONICAL_KEYS = ['amount', 'currency', 'date', 'id', 'source'] as const;

function sha(data: Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

/** Canonical encoding for a revenue entry (sorted keys, no raw). */
export function entryToLeafInput(entry: RevenueEntry): string {
  const obj: Record<string, unknown> = {};
  for (const k of CANONICAL_KEYS) {
    obj[k] = entry[k];
  }
  return JSON.stringify(obj);
}

function hashLeaf(data: string | Buffer): Buffer {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return sha(buf);
}

export type BuildTreeInput =
  | { kind: 'entries'; entries: RevenueEntry[] }
  | { kind: 'leaves'; leaves: (Buffer | string)[] };

export type BuildTreeResult = {
  /** Merkle root, 32 bytes */
  root: Buffer;
  /** Optional tree for proof generation */
  tree?: MerkleTree;
};

/**
 * Build a Merkle tree from revenue entries or pre-hashed leaves.
 * Deterministic: same inputs (as set) produce the same root.
 */
export function buildTree(input: BuildTreeInput): BuildTreeResult {
  let hashed: Buffer[];

  if (input.kind === 'entries') {
    if (!input.entries.length) {
      const tree = MerkleTree.fromHashedLeaves([]);
      return {
        root: Buffer.alloc(0),
        tree,
      };
    }
    hashed = input.entries.map((e) => hashLeaf(entryToLeafInput(e)));
  } else {
    if (!input.leaves.length) {
      const tree = MerkleTree.fromHashedLeaves([]);
      return {
        root: Buffer.alloc(0),
        tree,
      };
    }
    hashed = input.leaves.map((l) =>
      typeof l === 'string' ? Buffer.from(l, 'hex') : l
    );
  }

  const sorted = [...hashed].sort((a, b) =>
    a.toString('hex').localeCompare(b.toString('hex'))
  );
  const tree = MerkleTree.fromHashedLeaves(sorted);
  const rootHex = tree.getRoot();
  const root = rootHex ? Buffer.from(rootHex, 'hex') : Buffer.alloc(0);

  return { root, tree };
}
