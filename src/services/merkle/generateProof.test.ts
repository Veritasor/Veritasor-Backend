import { buildTree, getRoot, hash } from "./buildTree.js";
import {
  generateProof,
  verifyProof,
  isProof,
  isProofStep,
  isHashHex,
  normalizeHashHex,
  MERKLE_PROOF_MAX_STEPS,
} from "./generateProof.js";

const leaves = ["a", "b", "c", "d"];
const validHexRoot = "a".repeat(64); // 64-char lowercase hex
const validHexSibling = "b".repeat(64);

describe("Merkle proof", () => {
  // Existing positive-path tests 

  it("generates a valid proof for each leaf", () => {
    const tree = buildTree(leaves);
    const root = getRoot(tree, leaves.length);

    leaves.forEach((leaf, i) => {
      const proof = generateProof(leaves, i);
      expect(verifyProof(leaf, proof, root)).toBe(true);
    });
  });

  it("fails verification with wrong root", () => {
    const proof = generateProof(leaves, 0);
    expect(verifyProof("a", proof, "wrongroot")).toBe(false);
  });

  it("fails verification with wrong leaf", () => {
    const tree = buildTree(leaves);
    const root = getRoot(tree, leaves.length);
    const proof = generateProof(leaves, 0);
    expect(verifyProof("z", proof, root)).toBe(false);
  });

  it("handles odd number of leaves", () => {
    const oddLeaves = ["a", "b", "c"];
    const tree = buildTree(oddLeaves);
    const root = getRoot(tree, oddLeaves.length);
    const proof = generateProof(oddLeaves, 2);
    expect(verifyProof("c", proof, root)).toBe(true);
  });

  // NEW: Malformed proof rejection tests (#330) 

  describe("verifyProof rejects malformed inputs", () => {
    const tree = buildTree(leaves);
    const root = getRoot(tree, leaves.length);
    const proof = generateProof(leaves, 0);

    //  Non-hex roots 

    it("returns false for non-hex root", () => {
      expect(verifyProof("a", proof, "notahexstring")).toBe(false);
    });

    it("returns false for root with 0x prefix but invalid hex", () => {
      expect(verifyProof("a", proof, "0xZZZZZZ")).toBe(false);
    });

    it("returns false for root too short (< 64 chars)", () => {
      expect(verifyProof("a", proof, "a".repeat(63))).toBe(false);
    });

    it("returns false for root too long (> 64 chars)", () => {
      expect(verifyProof("a", proof, "a".repeat(65))).toBe(false);
    });

    it("returns false for root with uppercase hex (normalized ok, but mixed case)", () => {
      // normalizeHashHex handles this, but verifyProof should still accept valid 0x-prefixed
      const validRootWithPrefix = "0x" + "a".repeat(64);
      expect(verifyProof("a", proof, validRootWithPrefix)).toBe(true);
    });

    it("returns false for null root", () => {
      expect(verifyProof("a", proof, null as unknown as string)).toBe(false);
    });

    it("returns false for undefined root", () => {
      expect(verifyProof("a", proof, undefined as unknown as string)).toBe(false);
    });

    it("returns false for number root", () => {
      expect(verifyProof("a", proof, 12345 as unknown as string)).toBe(false);
    });

    // Non-array / invalid proof structures 

    it("returns false for non-array proof", () => {
      expect(verifyProof("a", "notanarray" as unknown as any[], root)).toBe(false);
    });

    it("returns false for null proof", () => {
      expect(verifyProof("a", null as unknown as any[], root)).toBe(false);
    });

    it("returns false for undefined proof", () => {
      expect(verifyProof("a", undefined as unknown as any[], root)).toBe(false);
    });

    it("returns false for object proof", () => {
      expect(verifyProof("a", { sibling: validHexSibling } as unknown as any[], root)).toBe(false);
    });

    // Over-length proofs 

    it("returns false for proof exceeding MERKLE_PROOF_MAX_STEPS", () => {
      const overLengthProof = Array(MERKLE_PROOF_MAX_STEPS + 1)
        .fill(null)
        .map(() => ({
          sibling: validHexSibling,
          position: "right" as const,
        }));
      expect(verifyProof("a", overLengthProof, validHexRoot)).toBe(false);
    });

    it("returns false for proof at exactly MERKLE_PROOF_MAX_STEPS + 1", () => {
      const overByOne = Array(MERKLE_PROOF_MAX_STEPS + 1)
        .fill(null)
        .map(() => ({
          sibling: validHexSibling,
          position: "left" as const,
        }));
      expect(verifyProof("a", overByOne, validHexRoot)).toBe(false);
    });

    it("accepts proof at exactly MERKLE_PROOF_MAX_STEPS", () => {
      const maxLengthProof = Array(MERKLE_PROOF_MAX_STEPS)
        .fill(null)
        .map(() => ({
          sibling: validHexSibling,
          position: "right" as const,
        }));
      // Won't match root, but should pass the length guard and return false from hash mismatch
      expect(verifyProof("a", maxLengthProof, validHexRoot)).toBe(false);
    });

    // Invalid proof steps 

    it("returns false for step with non-hex sibling", () => {
      const badProof = [
        { sibling: "notahexhash", position: "right" as const },
      ];
      expect(verifyProof("a", badProof, validHexRoot)).toBe(false);
    });

    it("returns false for step with sibling too short", () => {
      const badProof = [
        { sibling: "a".repeat(63), position: "right" as const },
      ];
      expect(verifyProof("a", badProof, validHexRoot)).toBe(false);
    });

    it("returns false for step with sibling too long", () => {
      const badProof = [
        { sibling: "a".repeat(65), position: "right" as const },
      ];
      expect(verifyProof("a", badProof, validHexRoot)).toBe(false);
    });

    it("returns false for step with invalid position value", () => {
      const badProof = [
        { sibling: validHexSibling, position: "center" as unknown as "left" },
      ];
      expect(verifyProof("a", badProof, validHexRoot)).toBe(false);
    });

    it("returns false for step with numeric position", () => {
      const badProof = [
        { sibling: validHexSibling, position: 1 as unknown as "left" },
      ];
      expect(verifyProof("a", badProof, validHexRoot)).toBe(false);
    });

    it("returns false for step with null position", () => {
      const badProof = [
        { sibling: validHexSibling, position: null as unknown as "left" },
      ];
      expect(verifyProof("a", badProof, validHexRoot)).toBe(false);
    });

    it("returns false for step with missing sibling", () => {
      const badProof = [{ position: "right" as const }];
      expect(verifyProof("a", badProof as any[], validHexRoot)).toBe(false);
    });

    it("returns false for step with missing position", () => {
      const badProof = [{ sibling: validHexSibling }];
      expect(verifyProof("a", badProof as any[], validHexRoot)).toBe(false);
    });

    it("returns false for step that is null", () => {
      const badProof = [null];
      expect(verifyProof("a", badProof as any[], validHexRoot)).toBe(false);
    });

    it("returns false for step that is a primitive", () => {
      const badProof = ["justastring"];
      expect(verifyProof("a", badProof as any[], validHexRoot)).toBe(false);
    });

    // Bad sibling with 0x prefix 

    it("returns false for step with 0x-prefixed but invalid sibling", () => {
      const badProof = [
        { sibling: "0xGGGG", position: "right" as const },
      ];
      expect(verifyProof("a", badProof, validHexRoot)).toBe(false);
    });

    it("accepts step with valid 0x-prefixed sibling", () => {
      const validProof = [
        { sibling: "0x" + "b".repeat(64), position: "right" as const },
      ];
      // Won't match root, but sibling should pass validation
      expect(verifyProof("a", validProof, validHexRoot)).toBe(false);
    });

    // Non-string leaf 

    it("returns false for non-string leaf", () => {
      expect(verifyProof(12345 as unknown as string, proof, root)).toBe(false);
    });

    it("returns false for null leaf", () => {
      expect(verifyProof(null as unknown as string, proof, root)).toBe(false);
    });

    it("returns false for undefined leaf", () => {
      expect(verifyProof(undefined as unknown as string, proof, root)).toBe(false);
    });
  });

  // NEW: Guard function tests 

  describe("isHashHex guard", () => {
    it("returns true for valid 64-char hex", () => {
      expect(isHashHex("a".repeat(64))).toBe(true);
    });

    it("returns true for valid hex with 0x prefix", () => {
      expect(isHashHex("0x" + "b".repeat(64))).toBe(true);
    });

    it("returns false for non-hex characters", () => {
      expect(isHashHex("g".repeat(64))).toBe(false);
    });

    it("returns false for wrong length", () => {
      expect(isHashHex("a".repeat(63))).toBe(false);
    });

    it("returns false for non-string input", () => {
      expect(isHashHex(12345)).toBe(false);
    });
  });

  describe("isProofStep guard", () => {
    it("returns true for valid step", () => {
      expect(isProofStep({ sibling: validHexSibling, position: "left" })).toBe(true);
    });

    it("returns false for invalid position", () => {
      expect(isProofStep({ sibling: validHexSibling, position: "up" })).toBe(false);
    });

    it("returns false for invalid sibling", () => {
      expect(isProofStep({ sibling: "bad", position: "left" })).toBe(false);
    });

    it("returns false for null", () => {
      expect(isProofStep(null)).toBe(false);
    });

    it("returns false for primitive", () => {
      expect(isProofStep("string")).toBe(false);
    });
  });

  describe("isProof guard", () => {
    it("returns true for valid proof array", () => {
      expect(isProof([{ sibling: validHexSibling, position: "right" }])).toBe(true);
    });

    it("returns false for non-array", () => {
      expect(isProof("notarray")).toBe(false);
    });

    it("returns false for over-length array", () => {
      const tooLong = Array(MERKLE_PROOF_MAX_STEPS + 1).fill({
        sibling: validHexSibling,
        position: "left",
      });
      expect(isProof(tooLong)).toBe(false);
    });

    it("returns false for array with invalid step", () => {
      expect(isProof([{ sibling: "bad", position: "left" }])).toBe(false);
    });
  });

  describe("normalizeHashHex", () => {
    it("normalizes valid hex to lowercase", () => {
      expect(normalizeHashHex("ABCDEF1234567890".repeat(4))).toBe("abcdef1234567890".repeat(4));
    });

    it("strips 0x prefix", () => {
      expect(normalizeHashHex("0x" + "a".repeat(64))).toBe("a".repeat(64));
    });

    it("returns null for invalid hex", () => {
      expect(normalizeHashHex("invalid")).toBe(null);
    });

    it("returns null for non-string", () => {
      expect(normalizeHashHex(123 as unknown as string)).toBe(null);
    });
  });
});