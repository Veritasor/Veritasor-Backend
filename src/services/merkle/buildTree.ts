import { createHash } from 'crypto';

// ─── Hash primitive ───────────────────────────────────────────────────────────

/**
 * SHA-256 over a UTF-8 string, returned as lowercase hex.
 * All tree construction and proof verification funnels through this function
 * so the algorithm is trivially swappable.
 */
export function hash(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

// ─── Performance guardrails ───────────────────────────────────────────────────

/**
 * Hard cap on the number of leaves accepted per tree.
 *
 * Default: 2^20 (~1 M leaves). A tree that size has a 20-step proof path and
 * hashes ~2 M nodes — well within milliseconds on commodity hardware, but
 * large enough that a runaway caller will trip this before causing OOM.
 *
 * Override via env var MERKLE_MAX_LEAVES (positive integer ≤ 2^24).
 */
export const MERKLE_MAX_LEAVES: number = (() => {
  const raw = process.env.MERKLE_MAX_LEAVES;
  if (!raw) return 1_048_576; // 2^20
  const parsed = parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 16_777_216) {
    throw new Error(
      `MERKLE_MAX_LEAVES must be a positive integer ≤ 16777216, got: "${raw}"`
    );
  }
  return parsed;
})();

/**
 * Soft warn threshold — emits a structured log entry when leaf count reaches
 * this value. Defaults to 10 % of the hard cap so operators get early notice.
 */
export const MERKLE_WARN_LEAVES: number = Math.floor(MERKLE_MAX_LEAVES * 0.1);

// ─── Tree builder ─────────────────────────────────────────────────────────────

/**
 * Build a complete Merkle tree from an array of string leaf values.
 *
 * The returned flat array contains ALL nodes in bottom-up level order:
 * hashed leaves first, then parent levels, root last.
 *
 *   tree[tree.length - 1]  →  root
 *
 * This matches the shape the existing `getRoot` signature expects.
 *
 * @throws {RangeError}  Leaf count is 0 or exceeds MERKLE_MAX_LEAVES.
 * @throws {TypeError}   Any leaf is not a non-empty string.
 */
export function buildTree(leaves: string[]): string[] {
  // ── Validation ────────────────────────────────────────────────────────────
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new RangeError('buildTree requires at least one leaf');
  }

  if (leaves.length > MERKLE_MAX_LEAVES) {
    throw new RangeError(
      `Leaf count ${leaves.length} exceeds MERKLE_MAX_LEAVES (${MERKLE_MAX_LEAVES}). ` +
        'Raise the MERKLE_MAX_LEAVES env var if this is intentional.'
    );
  }

  for (const leaf of leaves) {
    if (typeof leaf !== 'string' || leaf.length === 0) {
      throw new TypeError('Every leaf must be a non-empty string');
    }
  }

  // ── Structured warning for large trees ───────────────────────────────────
  if (leaves.length >= MERKLE_WARN_LEAVES) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        service: 'merkle',
        event: 'large_tree',
        leafCount: leaves.length,
        warnThreshold: MERKLE_WARN_LEAVES,
        maxAllowed: MERKLE_MAX_LEAVES,
        message: `Building Merkle tree with ${leaves.length} leaves — approaching size guardrail`,
      })
    );
  }

  // ── Construction ──────────────────────────────────────────────────────────
  let level: string[] = leaves.map((l) => hash(l));
  const tree: string[] = [...level];

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

  return tree; // tree[tree.length - 1] is the root
}

/**
 * Extract the root from a flat tree array returned by {@link buildTree}.
 *
 * @param tree       Flat node array.
 * @param _leafCount Unused — retained for API compatibility with test imports.
 */
export function getRoot(tree: string[], _leafCount?: number): string {
  if (!tree || tree.length === 0) return '';
  return tree[tree.length - 1];
}