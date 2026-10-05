/**
 * Regression suite for src/services/merkle/buildTree.ts
 *
 * Covers every branch identified in issue #996:
 *   - MERKLE_MAX_LEAVES IIFE – invalid env var throws Error (line 30, the
 *     primary regression target), zero / negative / non-integer / over-cap
 *     values, and the valid-override happy-path.
 *   - buildTree() – all RangeError / TypeError input guards, the large-tree
 *     console.warn path, single-leaf, two-leaf, odd-leaf, and even-leaf trees.
 *   - hash() – SHA-256 contract: 64-char lowercase hex, deterministic, unique.
 *   - getRoot() – empty / null sentinel returns '' , root equals last element.
 *
 * Framework: vitest (globals: true, environment: node, pool: vmForks).
 * Imports use the .js extension as required by NodeNext module resolution.
 */

import { createHash } from 'node:crypto';
import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
  type SpyInstance,
} from 'vitest';

// ─── helpers ─────────────────────────────────────────────────────────────────

/** Compute an expected SHA-256 hex independently of the module under test. */
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

// ─── hash() ──────────────────────────────────────────────────────────────────

describe('hash()', () => {
  it('returns a 64-character lowercase hex string', async () => {
    const { hash } = await import('./buildTree.js');
    const result = hash('hello');
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic – same input always produces the same output', async () => {
    const { hash } = await import('./buildTree.js');
    expect(hash('veritasor')).toBe(hash('veritasor'));
  });

  it('produces distinct output for distinct inputs', async () => {
    const { hash } = await import('./buildTree.js');
    expect(hash('a')).not.toBe(hash('b'));
  });

  it('matches an independent SHA-256 implementation', async () => {
    const { hash } = await import('./buildTree.js');
    const inputs = ['', 'x', 'leaf-1', 'The quick brown fox'];
    for (const input of inputs) {
      // '' is technically valid for hash() even though buildTree() rejects it
      expect(hash(input)).toBe(sha256(input));
    }
  });
});

// ─── MERKLE_MAX_LEAVES IIFE – issue #996 regression ─────────────────────────

describe('MERKLE_MAX_LEAVES env-var validation (issue #996 regression)', () => {
  /**
   * The IIFE executes at module-load time, so each case that needs a different
   * env value must reload the module in isolation.
   */
  afterEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
  });

  // ── default (no env var) ──────────────────────────────────────────────────

  it('defaults to 1_048_576 when MERKLE_MAX_LEAVES is not set', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '');
    vi.resetModules();
    const { MERKLE_MAX_LEAVES } = await import('./buildTree.js');
    expect(MERKLE_MAX_LEAVES).toBe(1_048_576);
  });

  // ── valid overrides ───────────────────────────────────────────────────────

  it('accepts "1" as a valid override', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '1');
    vi.resetModules();
    const { MERKLE_MAX_LEAVES } = await import('./buildTree.js');
    expect(MERKLE_MAX_LEAVES).toBe(1);
  });

  it('accepts the maximum allowed value "16777216" (2^24)', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '16777216');
    vi.resetModules();
    const { MERKLE_MAX_LEAVES } = await import('./buildTree.js');
    expect(MERKLE_MAX_LEAVES).toBe(16_777_216);
  });

  it('accepts an arbitrary valid positive integer', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '500');
    vi.resetModules();
    const { MERKLE_MAX_LEAVES } = await import('./buildTree.js');
    expect(MERKLE_MAX_LEAVES).toBe(500);
  });

  // ── invalid values – the #996 regression paths (line 30 throw) ───────────

  it('throws Error (not RangeError) with the exact message prefix for "0"', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '0');
    vi.resetModules();
    await expect(import('./buildTree.js')).rejects.toThrow(Error);
    await expect(import('./buildTree.js')).rejects.toThrow(
      'MERKLE_MAX_LEAVES must be a positive integer'
    );
  });

  it('throws for a negative integer "-1"', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '-1');
    vi.resetModules();
    await expect(import('./buildTree.js')).rejects.toThrow(
      'MERKLE_MAX_LEAVES must be a positive integer'
    );
  });

  it('throws for a value exceeding the cap "16777217"', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '16777217');
    vi.resetModules();
    await expect(import('./buildTree.js')).rejects.toThrow(
      /MERKLE_MAX_LEAVES must be a positive integer/
    );
  });

  it('throws for a non-integer float "1.5"', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '1.5');
    vi.resetModules();
    await expect(import('./buildTree.js')).rejects.toThrow(
      /MERKLE_MAX_LEAVES must be a positive integer/
    );
  });

  it('throws for a non-numeric string "banana"', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', 'banana');
    vi.resetModules();
    await expect(import('./buildTree.js')).rejects.toThrow(
      /MERKLE_MAX_LEAVES must be a positive integer/
    );
  });

  it('error message includes the bad value in quotes', async () => {
    const bad = 'notANumber';
    vi.stubEnv('MERKLE_MAX_LEAVES', bad);
    vi.resetModules();
    await expect(import('./buildTree.js')).rejects.toThrow(`got: "${bad}"`);
  });

  it('throws a plain Error (not RangeError, not TypeError) for invalid env', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', 'bad');
    vi.resetModules();
    // Must be exactly Error – not a subclass – so the IIFE contract is stable
    await expect(import('./buildTree.js')).rejects.toSatisfy(
      (e: unknown) => (e as Error).constructor === Error
    );
  });
});

// ─── buildTree() – input validation ──────────────────────────────────────────

describe('buildTree() – input validation', () => {
  it('throws RangeError for an empty array', async () => {
    const { buildTree } = await import('./buildTree.js');
    expect(() => buildTree([])).toThrow(RangeError);
    expect(() => buildTree([])).toThrow('buildTree requires at least one leaf');
  });

  it('throws RangeError when called with a non-array (null)', async () => {
    const { buildTree } = await import('./buildTree.js');
    // @ts-expect-error intentional invalid input for runtime guard test
    expect(() => buildTree(null)).toThrow(RangeError);
  });

  it('throws RangeError when called with a non-array (string)', async () => {
    const { buildTree } = await import('./buildTree.js');
    // @ts-expect-error intentional invalid input for runtime guard test
    expect(() => buildTree('leaf')).toThrow(RangeError);
  });

  it('throws RangeError when called with a non-array (undefined)', async () => {
    const { buildTree } = await import('./buildTree.js');
    // @ts-expect-error intentional invalid input for runtime guard test
    expect(() => buildTree(undefined)).toThrow(RangeError);
  });

  it('throws TypeError for an array containing an empty string', async () => {
    const { buildTree } = await import('./buildTree.js');
    expect(() => buildTree(['a', '', 'b'])).toThrow(TypeError);
    expect(() => buildTree(['a', '', 'b'])).toThrow(
      'Every leaf must be a non-empty string'
    );
  });

  it('throws TypeError for an array containing a number', async () => {
    const { buildTree } = await import('./buildTree.js');
    // @ts-expect-error intentional invalid input for runtime guard test
    expect(() => buildTree([42])).toThrow(TypeError);
  });

  it('throws TypeError for an array containing null', async () => {
    const { buildTree } = await import('./buildTree.js');
    // @ts-expect-error intentional invalid input for runtime guard test
    expect(() => buildTree([null])).toThrow(TypeError);
  });

  it('throws TypeError for mixed valid / invalid leaves', async () => {
    const { buildTree } = await import('./buildTree.js');
    // @ts-expect-error intentional invalid input for runtime guard test
    expect(() => buildTree(['good', 123, 'also-good'])).toThrow(TypeError);
  });

  it('throws RangeError when leaf count exceeds MERKLE_MAX_LEAVES', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '3');
    vi.resetModules();
    const { buildTree } = await import('./buildTree.js');
    const oversized = ['a', 'b', 'c', 'd']; // 4 > 3
    expect(() => buildTree(oversized)).toThrow(RangeError);
    expect(() => buildTree(oversized)).toThrow('exceeds MERKLE_MAX_LEAVES');
  });

  it('RangeError for over-cap includes both leaf count and cap in the message', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '2');
    vi.resetModules();
    const { buildTree } = await import('./buildTree.js');
    let caught: Error | undefined;
    try {
      buildTree(['a', 'b', 'c']); // 3 > 2
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).toBeInstanceOf(RangeError);
    expect(caught!.message).toMatch(/3/);  // leaf count
    expect(caught!.message).toMatch(/2/);  // cap value
  });

  afterEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
  });
});

// ─── buildTree() – happy paths ────────────────────────────────────────────────

describe('buildTree() – correct output', () => {
  afterEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
  });

  it('single leaf: returns an array of length 1 containing hash(leaf)', async () => {
    const { buildTree, hash } = await import('./buildTree.js');
    const result = buildTree(['alice']);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(hash('alice'));
  });

  it('single leaf: root equals the only element', async () => {
    const { buildTree, getRoot } = await import('./buildTree.js');
    const tree = buildTree(['only']);
    expect(getRoot(tree)).toBe(tree[0]);
  });

  it('two leaves: returns [h0, h1, hash(h0+h1)]', async () => {
    const { buildTree, hash } = await import('./buildTree.js');
    const tree = buildTree(['a', 'b']);
    const h0 = hash('a');
    const h1 = hash('b');
    expect(tree).toHaveLength(3);
    expect(tree[0]).toBe(h0);
    expect(tree[1]).toBe(h1);
    expect(tree[2]).toBe(hash(h0 + h1));
  });

  it('two leaves: last element is the root', async () => {
    const { buildTree } = await import('./buildTree.js');
    const tree = buildTree(['x', 'y']);
    expect(tree[tree.length - 1]).toBe(tree[2]);
  });

  it('four leaves: correct 7-node tree (4 leaves + 2 parents + 1 root)', async () => {
    const { buildTree, hash } = await import('./buildTree.js');
    const leaves = ['a', 'b', 'c', 'd'];
    const tree = buildTree(leaves);
    // 4 leaf hashes + 2 parent hashes + 1 root = 7
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
    expect(tree[6]).toBe(hash(p01 + p23)); // root
  });

  it('odd leaf count: last leaf is duplicated when pairing', async () => {
    const { buildTree, hash } = await import('./buildTree.js');
    const tree = buildTree(['a', 'b', 'c']);
    // Level-0: h(a), h(b), h(c)
    // Level-1: h(h(a)+h(b)),  h(h(c)+h(c))  ← duplication
    // Level-2 (root): h(level1[0]+level1[1])
    const ha = hash('a');
    const hb = hash('b');
    const hc = hash('c');
    const p01 = hash(ha + hb);
    const p22 = hash(hc + hc); // duplicated
    const root = hash(p01 + p22);
    expect(tree[tree.length - 1]).toBe(root);
  });

  it('five leaves: correct shape with cascading odd-leaf duplication', async () => {
    const { buildTree, hash } = await import('./buildTree.js');
    const leaves = ['1', '2', '3', '4', '5'];
    const tree = buildTree(leaves);

    const [h1, h2, h3, h4, h5] = leaves.map(hash);
    // L1: pair (h1,h2), (h3,h4), (h5,h5) → 3 parents
    const p12 = hash(h1 + h2);
    const p34 = hash(h3 + h4);
    const p55 = hash(h5 + h5);
    // L2: pair (p12,p34), (p55,p55) → 2 parents
    const p1234 = hash(p12 + p34);
    const p5555 = hash(p55 + p55);
    // Root
    const root = hash(p1234 + p5555);
    expect(tree[tree.length - 1]).toBe(root);
  });

  it('root is always the last element of the returned array', async () => {
    const { buildTree, getRoot } = await import('./buildTree.js');
    for (const n of [1, 2, 3, 4, 5, 6, 7, 8]) {
      const leaves = Array.from({ length: n }, (_, i) => `leaf-${i}`);
      const tree = buildTree(leaves);
      expect(tree[tree.length - 1]).toBe(getRoot(tree));
    }
  });

  it('all 64-char hex strings appear in the output', async () => {
    const { buildTree } = await import('./buildTree.js');
    const tree = buildTree(['foo', 'bar', 'baz']);
    for (const node of tree) {
      expect(node).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('accepts a single-character leaf without throwing', async () => {
    const { buildTree } = await import('./buildTree.js');
    expect(() => buildTree(['x'])).not.toThrow();
  });

  it('accepts leaves at exactly MERKLE_MAX_LEAVES limit (no throw)', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '4');
    vi.resetModules();
    const { buildTree } = await import('./buildTree.js');
    const exactly4 = ['a', 'b', 'c', 'd'];
    expect(() => buildTree(exactly4)).not.toThrow();
  });
});

// ─── buildTree() – large-tree console.warn path ──────────────────────────────

describe('buildTree() – large-tree structured warning', () => {
  let warnSpy: SpyInstance;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
    vi.resetModules();
    vi.unstubAllEnvs();
  });

  it('does NOT warn for trees below the warn threshold', async () => {
    // Use a small cap so the threshold is easily tested without building huge trees
    vi.stubEnv('MERKLE_MAX_LEAVES', '100');
    vi.resetModules();
    const { buildTree, MERKLE_WARN_LEAVES } = await import('./buildTree.js');

    // Build a tree just under the threshold
    const safeCount = MERKLE_WARN_LEAVES - 1;
    const leaves = Array.from({ length: safeCount }, (_, i) => `leaf-${i}`);
    buildTree(leaves);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('emits console.warn when leaf count reaches MERKLE_WARN_LEAVES', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '100');
    vi.resetModules();
    const { buildTree, MERKLE_WARN_LEAVES } = await import('./buildTree.js');

    const leaves = Array.from({ length: MERKLE_WARN_LEAVES }, (_, i) => `leaf-${i}`);
    buildTree(leaves);
    expect(warnSpy).toHaveBeenCalledOnce();
  });

  it('warn payload is valid JSON containing expected fields', async () => {
    vi.stubEnv('MERKLE_MAX_LEAVES', '100');
    vi.resetModules();
    const { buildTree, MERKLE_WARN_LEAVES, MERKLE_MAX_LEAVES } = await import('./buildTree.js');

    const leaves = Array.from({ length: MERKLE_WARN_LEAVES }, (_, i) => `leaf-${i}`);
    buildTree(leaves);

    const raw: string = warnSpy.mock.calls[0][0];
    const payload = JSON.parse(raw);
    expect(payload.level).toBe('warn');
    expect(payload.service).toBe('merkle');
    expect(payload.event).toBe('large_tree');
    expect(payload.leafCount).toBe(MERKLE_WARN_LEAVES);
    expect(payload.warnThreshold).toBe(MERKLE_WARN_LEAVES);
    expect(payload.maxAllowed).toBe(MERKLE_MAX_LEAVES);
    expect(typeof payload.message).toBe('string');
  });
});

// ─── getRoot() ────────────────────────────────────────────────────────────────

describe('getRoot()', () => {
  afterEach(() => {
    vi.resetModules();
  });

  it('returns "" for an empty array', async () => {
    const { getRoot } = await import('./buildTree.js');
    expect(getRoot([])).toBe('');
  });

  it('returns "" for null (API compat)', async () => {
    const { getRoot } = await import('./buildTree.js');
    // @ts-expect-error intentional null for runtime guard test
    expect(getRoot(null)).toBe('');
  });

  it('returns "" for undefined (API compat)', async () => {
    const { getRoot } = await import('./buildTree.js');
    // @ts-expect-error intentional undefined for runtime guard test
    expect(getRoot(undefined)).toBe('');
  });

  it('returns the single element for a one-element tree', async () => {
    const { buildTree, getRoot } = await import('./buildTree.js');
    const tree = buildTree(['solo']);
    expect(getRoot(tree)).toBe(tree[0]);
  });

  it('returns tree[tree.length - 1] for a multi-node tree', async () => {
    const { buildTree, getRoot } = await import('./buildTree.js');
    const tree = buildTree(['a', 'b', 'c', 'd']);
    expect(getRoot(tree)).toBe(tree[tree.length - 1]);
  });

  it('ignores the optional _leafCount parameter (backward compat)', async () => {
    const { buildTree, getRoot } = await import('./buildTree.js');
    const tree = buildTree(['x', 'y']);
    const rootWithCount = getRoot(tree, 2);
    const rootWithout = getRoot(tree);
    expect(rootWithCount).toBe(rootWithout);
  });
});
