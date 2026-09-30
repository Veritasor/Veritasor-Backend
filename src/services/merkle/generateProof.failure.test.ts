import { describe, it, expect } from "vitest";
import {
  generateProof,
  verifyProof,
  normalizeHashHex,
  isHashHex,
  isProofStep,
  isProof,
  MERKLE_PROOF_MAX_STEPS,
} from "./generateProof.js";
import { buildTree, getRoot } from "./buildTree.js";

/**
 * Regression coverage for issue #997 — ProofStep failure handling.
 *
 * Focuses on the guard branches in `generateProof.ts`:
 *   - normalizeHashHex   : typeof guard + HASH_HEX_REGEX guard
 *   - isHashHex / isProofStep / isProof : malformed / boundary inputs
 *   - generateProof      : exact throw contract for invalid leaves and index
 *   - verifyProof        : false on every guard failure, true on valid proof
 *
 * Complements (does not duplicate) `generateProof.test.ts` and
 * `tests/unit/services/merkle.test.ts`.
 */

const VALID_HASH = "abcdef0123456789".repeat(4); // 64 lowercase hex chars
const UPPER_HASH = "ABCDEF0123456789".repeat(4); // 64 uppercase hex chars
const VALID_STEP = { sibling: VALID_HASH, position: "left" as const };

/** Capture a thrown Error deterministically so the exact message can be asserted. */
function captureError(fn: () => unknown): Error {
  try {
    fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected function to throw, but it did not");
}

// ─── normalizeHashHex ─────────────────────────────────────────────────────────

describe("normalizeHashHex (issue #997)", () => {
  it("accepts a bare 64-char lowercase hex string", () => {
    expect(normalizeHashHex(VALID_HASH)).toBe(VALID_HASH);
  });

  it("accepts and strips a lowercase 0x prefix", () => {
    expect(normalizeHashHex(`0x${VALID_HASH}`)).toBe(VALID_HASH);
  });

  it("accepts and strips an uppercase 0X prefix", () => {
    expect(normalizeHashHex(`0X${VALID_HASH}`)).toBe(VALID_HASH);
  });

  it("lowercases upper-case hex input", () => {
    expect(normalizeHashHex(UPPER_HASH)).toBe(VALID_HASH);
    expect(normalizeHashHex(`0x${UPPER_HASH}`)).toBe(VALID_HASH);
  });

  it("returns null for non-string inputs (typeof guard at :33)", () => {
    expect(normalizeHashHex(null as any)).toBeNull();
    expect(normalizeHashHex(undefined as any)).toBeNull();
    expect(normalizeHashHex(123 as any)).toBeNull();
    expect(normalizeHashHex({} as any)).toBeNull();
    expect(normalizeHashHex([] as any)).toBeNull();
  });

  it("returns null for wrong lengths (63 and 65 chars)", () => {
    expect(normalizeHashHex("a".repeat(63))).toBeNull();
    expect(normalizeHashHex("a".repeat(65))).toBeNull();
    expect(normalizeHashHex(`0x${"a".repeat(63)}`)).toBeNull();
  });

  it("returns null for non-hex characters (regex guard at :35)", () => {
    expect(normalizeHashHex("g".repeat(64))).toBeNull();
    expect(normalizeHashHex(`${"a".repeat(63)}g`)).toBeNull();
  });

  it("returns null for the empty string", () => {
    expect(normalizeHashHex("")).toBeNull();
  });
});

// ─── isHashHex / isProofStep / isProof ────────────────────────────────────────

describe("isHashHex guard (issue #997)", () => {
  it("accepts valid hashes with and without a 0x prefix", () => {
    expect(isHashHex(VALID_HASH)).toBe(true);
    expect(isHashHex(`0x${VALID_HASH}`)).toBe(true);
  });

  it("rejects non-strings, wrong lengths and non-hex values", () => {
    expect(isHashHex(123)).toBe(false);
    expect(isHashHex(null)).toBe(false);
    expect(isHashHex(undefined)).toBe(false);
    expect(isHashHex({})).toBe(false);
    expect(isHashHex("a".repeat(63))).toBe(false);
    expect(isHashHex("g".repeat(64))).toBe(false);
    expect(isHashHex("")).toBe(false);
  });
});

describe("isProofStep guard (issue #997)", () => {
  it("accepts a well-formed step", () => {
    expect(isProofStep(VALID_STEP)).toBe(true);
    expect(isProofStep({ sibling: `0x${VALID_HASH}`, position: "right" })).toBe(true);
  });

  it("rejects non-object values", () => {
    expect(isProofStep(null)).toBe(false);
    expect(isProofStep(undefined)).toBe(false);
    expect(isProofStep("left")).toBe(false);
    expect(isProofStep(42)).toBe(false);
    expect(isProofStep([])).toBe(false);
  });

  it("rejects a bad position", () => {
    expect(isProofStep({ sibling: VALID_HASH, position: "up" })).toBe(false);
    expect(isProofStep({ sibling: VALID_HASH, position: "leftright" })).toBe(false);
    expect(isProofStep({ sibling: VALID_HASH })).toBe(false);
  });

  it("rejects a bad sibling", () => {
    expect(isProofStep({ sibling: "nothex", position: "left" })).toBe(false);
    expect(isProofStep({ sibling: "a".repeat(63), position: "left" })).toBe(false);
    expect(isProofStep({ position: "left" })).toBe(false);
  });
});

describe("isProof guard (issue #997)", () => {
  it("accepts an empty proof array (boundary: 0 steps)", () => {
    expect(isProof([])).toBe(true);
  });

  it("accepts exactly MERKLE_PROOF_MAX_STEPS valid steps", () => {
    const maxProof = Array.from({ length: MERKLE_PROOF_MAX_STEPS }, () => ({ ...VALID_STEP }));
    expect(isProof(maxProof)).toBe(true);
  });

  it("rejects a proof of length MERKLE_PROOF_MAX_STEPS + 1", () => {
    const tooLong = Array.from({ length: MERKLE_PROOF_MAX_STEPS + 1 }, () => ({ ...VALID_STEP }));
    expect(isProof(tooLong)).toBe(false);
  });

  it("rejects non-array values", () => {
    expect(isProof(null)).toBe(false);
    expect(isProof(undefined)).toBe(false);
    expect(isProof("proof")).toBe(false);
    expect(isProof({})).toBe(false);
  });

  it("rejects an array containing a single bad element", () => {
    expect(isProof([VALID_STEP, { sibling: "nothex", position: "left" }])).toBe(false);
    expect(isProof([VALID_STEP, { sibling: VALID_HASH, position: "up" }])).toBe(false);
    expect(isProof([VALID_STEP, null])).toBe(false);
  });
});

// ─── generateProof throw contract ─────────────────────────────────────────────

describe("generateProof failure contract (issue #997)", () => {
  const leaves = ["a", "b", "c"];

  it("throws the leaves message for a non-array first argument", () => {
    const message = "leaves must be a non-empty array of strings";
    for (const bad of [null, undefined, "abc", {}, 42]) {
      expect(captureError(() => generateProof(bad as any, 0)).message).toBe(message);
    }
  });

  it("throws the leaves message for an empty array", () => {
    expect(captureError(() => generateProof([], 0)).message).toBe(
      "leaves must be a non-empty array of strings",
    );
  });

  it("throws the leaves message when any leaf is not a string", () => {
    const message = "leaves must be a non-empty array of strings";
    expect(captureError(() => generateProof(["a", 1] as any, 0)).message).toBe(message);
    expect(captureError(() => generateProof([null] as any, 0)).message).toBe(message);
    expect(captureError(() => generateProof([{}] as any, 0)).message).toBe(message);
  });

  it("throws the integer message for non-integer indices", () => {
    const message = "leafIndex must be an integer";
    expect(captureError(() => generateProof(leaves, 1.5)).message).toBe(message);
    expect(captureError(() => generateProof(leaves, NaN)).message).toBe(message);
    expect(captureError(() => generateProof(leaves, Infinity)).message).toBe(message);
    expect(captureError(() => generateProof(leaves, -Infinity)).message).toBe(message);
  });

  it("throws the range message for negative and out-of-range indices", () => {
    const message = "leafIndex out of range";
    expect(captureError(() => generateProof(leaves, -1)).message).toBe(message);
    expect(captureError(() => generateProof(leaves, leaves.length)).message).toBe(message);
    expect(captureError(() => generateProof(leaves, leaves.length + 99)).message).toBe(message);
  });
});

// ─── generateProof normal-path boundaries ─────────────────────────────────────

describe("generateProof normal-path boundaries (issue #997)", () => {
  it("produces an empty proof for a single-leaf tree that verifies against the root", () => {
    const leaves = ["only"];
    const root = getRoot(buildTree(leaves), leaves.length);
    const proof = generateProof(leaves, 0);
    expect(proof).toEqual([]);
    expect(verifyProof(leaves[0], proof, root)).toBe(true);
  });

  it("produces verifying proofs for both leaves of a 2-leaf tree", () => {
    const leaves = ["a", "b"];
    const root = getRoot(buildTree(leaves), leaves.length);
    for (let i = 0; i < leaves.length; i += 1) {
      const proof = generateProof(leaves, i);
      expect(proof).toHaveLength(1);
      expect(verifyProof(leaves[i], proof, root)).toBe(true);
    }
  });
});

// ─── verifyProof failure / boundary handling ──────────────────────────────────

describe("verifyProof failure and boundary handling (issue #997)", () => {
  const leaves = ["a", "b", "c", "d"];
  const root = getRoot(buildTree(leaves), leaves.length);
  const proof = generateProof(leaves, 1);

  it("returns true for a valid generated proof", () => {
    expect(verifyProof(leaves[1], proof, root)).toBe(true);
  });

  it("returns false for a non-string leaf", () => {
    expect(verifyProof(null as any, proof, root)).toBe(false);
    expect(verifyProof(undefined as any, proof, root)).toBe(false);
    expect(verifyProof(123 as any, proof, root)).toBe(false);
  });

  it("returns false for a malformed root", () => {
    expect(verifyProof(leaves[1], proof, "nothex")).toBe(false);
    expect(verifyProof(leaves[1], proof, "a".repeat(63))).toBe(false);
    expect(verifyProof(leaves[1], proof, null as any)).toBe(false);
    expect(verifyProof(leaves[1], proof, undefined as any)).toBe(false);
  });

  it("returns false for a malformed or non-array proof", () => {
    expect(verifyProof(leaves[1], null as any, root)).toBe(false);
    expect(verifyProof(leaves[1], undefined as any, root)).toBe(false);
    expect(verifyProof(leaves[1], "proof" as any, root)).toBe(false);
    expect(verifyProof(leaves[1], [{ sibling: "nothex", position: "left" }] as any, root)).toBe(
      false,
    );
  });

  it("returns false for a bad sibling or bad position step", () => {
    const badSibling = proof.map((step, i) => (i === 0 ? { ...step, sibling: "nothex" } : step));
    expect(verifyProof(leaves[1], badSibling as any, root)).toBe(false);
    const badPosition = proof.map((step, i) => (i === 0 ? { ...step, position: "up" } : step));
    expect(verifyProof(leaves[1], badPosition as any, root)).toBe(false);
  });

  it("returns false when the root does not match", () => {
    const wrongRoot = "0000000000000000000000000000000000000000000000000000000000000000";
    expect(verifyProof(leaves[1], proof, wrongRoot)).toBe(false);
  });

  it("normalizes 0x/0X prefixes on root and siblings", () => {
    const prefixedProof = proof.map((step) => ({ ...step, sibling: `0x${step.sibling}` }));
    expect(verifyProof(leaves[1], prefixedProof, `0x${root}`)).toBe(true);

    const upperPrefixedProof = proof.map((step) => ({ ...step, sibling: `0X${step.sibling.toUpperCase()}` }));
    expect(verifyProof(leaves[1], upperPrefixedProof, `0X${root.toUpperCase()}`)).toBe(true);
  });
});
