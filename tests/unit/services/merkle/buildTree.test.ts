import crypto from 'crypto';
import { describe, it, expect } from 'vitest';
import { buildTree, entryToLeafInput } from '../../../../src/services/merkle/buildTree';
import MerkleTree from '../../../../src/services/merkle';
import type { RevenueEntry } from '../../../../src/services/revenue/razorpayFetch';

const hash = (s: string) => crypto.createHash('sha256').update(Buffer.from(s)).digest();

const sampleEntries: RevenueEntry[] = [
  { id: 'pay_1', amount: 100, currency: 'INR', date: '2025-01-01T00:00:00.000Z', source: 'razorpay' },
  { id: 'pay_2', amount: 200, currency: 'INR', date: '2025-01-02T00:00:00.000Z', source: 'razorpay' },
  { id: 'pay_3', amount: 150, currency: 'INR', date: '2025-01-03T00:00:00.000Z', source: 'razorpay' },
];

describe('buildTree', () => {
  it('produces a 32-byte root for entries', () => {
    const { root } = buildTree({ kind: 'entries', entries: sampleEntries });
    expect(root.length).toBe(32);
  });

  it('produces a 32-byte root for leaves', () => {
    const leaves = [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(32, 3)];
    const { root } = buildTree({ kind: 'leaves', leaves });
    expect(root.length).toBe(32);
  });

  it('is deterministic for entries (same order)', () => {
    const a = buildTree({ kind: 'entries', entries: sampleEntries });
    const b = buildTree({ kind: 'entries', entries: sampleEntries });
    expect(a.root.equals(b.root)).toBe(true);
  });

  it('is deterministic for entries (different order)', () => {
    const reversed = [...sampleEntries].reverse();
    const a = buildTree({ kind: 'entries', entries: sampleEntries });
    const b = buildTree({ kind: 'entries', entries: reversed });
    expect(a.root.equals(b.root)).toBe(true);
  });

  it('is deterministic for leaves (different order)', () => {
    const leaves = [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(32, 3)];
    const shuffled = [leaves[1], leaves[2], leaves[0]];
    const a = buildTree({ kind: 'leaves', leaves });
    const b = buildTree({ kind: 'leaves', leaves: shuffled });
    expect(a.root.equals(b.root)).toBe(true);
  });

  it('entries path: optional tree verifies proof with MerkleTree.verifyProof', () => {
    const { root, tree } = buildTree({ kind: 'entries', entries: sampleEntries });
    expect(tree).toBeDefined();
    const allHashed = sampleEntries.map((e) => hash(entryToLeafInput(e)));
    const sorted = [...allHashed].sort((a, b) => a.toString('hex').localeCompare(b.toString('hex')));
    const sortedIndex = 0;
    const leafHashAt0 = sorted[0];
    const entryIndex = sampleEntries.findIndex((e) => hash(entryToLeafInput(e)).equals(leafHashAt0));
    expect(entryIndex).toBeGreaterThanOrEqual(0);
    const proof = tree!.getProof(sortedIndex);
    const ok = MerkleTree.verifyProof(entryToLeafInput(sampleEntries[entryIndex]), proof, root.toString('hex'), sortedIndex);
    expect(ok).toBe(true);
  });

  it('leaves path: optional tree verifies proof with verifyProofWithHashedLeaf', () => {
    const leaves = [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(32, 3)];
    const { root, tree } = buildTree({ kind: 'leaves', leaves });
    expect(tree).toBeDefined();
    const index = 1;
    const proof = tree!.getProof(index);
    const sorted = [...leaves].sort((a, b) => a.toString('hex').localeCompare(b.toString('hex')));
    const leafHash = sorted[index];
    const ok = MerkleTree.verifyProofWithHashedLeaf(leafHash, proof, root.toString('hex'), index);
    expect(ok).toBe(true);
  });

  it('encoding: same canonical encoding produces same leaf hash', () => {
    const e1: RevenueEntry = { id: 'x', amount: 1, currency: 'INR', date: '2025-01-01', source: 'razorpay' };
    const e2: RevenueEntry = { id: 'x', amount: 1, currency: 'INR', date: '2025-01-01', source: 'razorpay', raw: { extra: 1 } };
    expect(entryToLeafInput(e1)).toBe(entryToLeafInput(e2));
    const r1 = buildTree({ kind: 'entries', entries: [e1] });
    const r2 = buildTree({ kind: 'entries', entries: [e2] });
    expect(r1.root.equals(r2.root)).toBe(true);
  });

  it('empty entries returns empty root and tree', () => {
    const { root, tree } = buildTree({ kind: 'entries', entries: [] });
    expect(root.length).toBe(0);
    expect(tree?.getRoot()).toBe('');
  });

  it('empty leaves returns empty root and tree', () => {
    const { root, tree } = buildTree({ kind: 'leaves', leaves: [] });
    expect(root.length).toBe(0);
    expect(tree?.getRoot()).toBe('');
  });
});
