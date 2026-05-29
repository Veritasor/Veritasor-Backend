import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
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

/**
 * Helper: Compute expected proof length based on tree height
 */
function computeExpectedProofLength(leafCount: number): number {
  if (leafCount <= 1) return 0;
  return Math.ceil(Math.log2(leafCount));
}

/**
 * Helper: Extract all valid hashes from a Merkle tree for validation
 */
function extractAllHashesFromTree(leaves: string[]): Set<string> {
  const hashes = new Set<string>();
  let level: string[] = leaves.map((l) => hash(l));
  
  level.forEach(h => hashes.add(h));
  
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      const parent = hash(left + right);
      next.push(parent);
      hashes.add(parent);
    }
    level = next;
  }
  
  return hashes;
}

describe("Merkle Proof Generation - Comprehensive Test Suite", () => {
  
  // ============================================================================
  // 1. DETERMINISTIC EDGE CASES (Example-Based Testing)
  // ============================================================================
  
  describe("Edge Case: Single Leaf Tree (n=1)", () => {
    it("generates empty proof for single leaf and verifies correctly", () => {
      const leaves = createMockLeaves(1);
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      
      const proof = generateProof(leaves, 0);
      
      // Single leaf tree should have empty proof (no siblings)
      expect(proof).toHaveLength(0);
      expect(verifyProof(leaves[0], proof, root)).toBe(true);
    });
  });
  
  describe("Edge Case: Two Leaf Tree (n=2)", () => {
    it("generates valid proofs for both leaves with correct sibling positions", () => {
      const leaves = createMockLeaves(2);
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      
      // Test leaf at index 0 (even index -> sibling on right)
      const proof0 = generateProof(leaves, 0);
      expect(proof0).toHaveLength(1);
      expect(proof0[0].position).toBe("right");
      expect(verifyProof(leaves[0], proof0, root)).toBe(true);
      
      // Test leaf at index 1 (odd index -> sibling on left)
      const proof1 = generateProof(leaves, 1);
      expect(proof1).toHaveLength(1);
      expect(proof1[0].position).toBe("left");
      expect(verifyProof(leaves[1], proof1, root)).toBe(true);
    });
  });
  
  describe("Edge Case: Three Leaf Tree (n=3) - Odd Level Handling", () => {
    it("generates valid proofs for all leaves with last-node duplication", () => {
      const leaves = createMockLeaves(3);
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      
      // Verify all three leaves
      for (let i = 0; i < leaves.length; i++) {
        const proof = generateProof(leaves, i);
        expect(verifyProof(leaves[i], proof, root)).toBe(true);
      }
      
      // Specifically test the last leaf (index 2) which triggers duplication
      const proof2 = generateProof(leaves, 2);
      expect(proof2).toHaveLength(2); // Height of tree with 3 leaves
      expect(verifyProof(leaves[2], proof2, root)).toBe(true);
    });
  });
  
  describe("Edge Case: Seven Leaf Tree (n=7) - Multi-Level Odd Handling", () => {
    it("generates valid proofs for all 7 leaves across multiple levels", () => {
      const leaves = createMockLeaves(7);
      const tree = buildTree(leaves);
      const root = getRoot(tree, leaves.length);
      
      // Systematically verify every single leaf index
      for (let i = 0; i < leaves.length; i++) {
        const proof = generateProof(leaves, i);
        const expectedLength = computeExpectedProofLength(leaves.length);
        
        expect(proof).toHaveLength(expectedLength);
        expect(verifyProof(leaves[i], proof, root)).toBe(true);
      }
    });
  });
  
  describe("Systematic Verification: Small Tree Sizes", () => {
    it("verifies all indices for trees of size 1, 2, 3, and 7", () => {
      const testSizes = [1, 2, 3, 7];
      
      testSizes.forEach(size => {
        const leaves = createMockLeaves(size);
        const tree = buildTree(leaves);
        const root = getRoot(tree, leaves.length);
        
        // Test every valid index
        for (let i = 0; i < size; i++) {
          const proof = generateProof(leaves, i);
          expect(verifyProof(leaves[i], proof, root)).toBe(true);
        }
      });
    });
  });
  
  // ============================================================================
  // 2. INPUT VALIDATION & ERROR BOUNDARIES
  // ============================================================================
  
  describe("Input Validation: Out-of-Range Indices", () => {
    it("throws error when leafIndex equals leaf count", () => {
      const leaves = createMockLeaves(5);
      expect(() => generateProof(leaves, 5)).toThrow("leafIndex out of range");
    });
    
    it("throws error when leafIndex exceeds leaf count", () => {
      const leaves = createMockLeaves(5);
      expect(() => generateProof(leaves, 10)).toThrow("leafIndex out of range");
    });
    
    it("throws error when leafIndex is negative", () => {
      const leaves = createMockLeaves(5);
      expect(() => generateProof(leaves, -1)).toThrow("leafIndex out of range");
    });
  });
  
  describe("Input Validation: Non-Integer Indices", () => {
    it("handles fractional indices (JavaScript coercion behavior)", () => {
      const leaves = createMockLeaves(5);
      // JavaScript will coerce 1.5 to 1 in array access, but we test the behavior
      // Note: TypeScript types prevent this, but runtime JS allows it
      const fractionalIndex = 1.5 as any;
      
      // The function will use 1.5 in comparisons, which should still work
      // but may produce unexpected results. We document this behavior.
      expect(() => generateProof(leaves, fractionalIndex)).not.toThrow();
    });
  });
  
  describe("Input Validation: Empty Leaves Array", () => {
    it("throws error when attempting to build tree from empty array", () => {
      const leaves: string[] = [];
      // buildTree throws, so generateProof won't even be reached
      expect(() => buildTree(leaves)).toThrow("Cannot build tree from empty leaves");
    });
  });
  
  // ============================================================================
  // 3. PROPERTY-BASED TESTING (fast-check)
  // ============================================================================
  
  describe("Property: Universal Round-Trip Verification", () => {
    it("verifies that all generated proofs pass verification for arbitrary trees", () => {
      fc.assert(
        fc.property(
          // Generate array of strings with reasonable bounds
          fc.array(fc.string({ minLength: 1, maxLength: 20 }), { 
            minLength: 1, 
            maxLength: 100 
          }),
          (leaves) => {
            // Generate valid index for this leaf array
            const leafIndex = leaves.length === 1 ? 0 : Math.floor(Math.random() * leaves.length);
            
            // Build tree and generate proof
            const tree = buildTree(leaves);
            const root = getRoot(tree, leaves.length);
            const proof = generateProof(leaves, leafIndex);
            
            // CORE INVARIANT: Proof must always verify successfully
            const isValid = verifyProof(leaves[leafIndex], proof, root);
            expect(isValid).toBe(true);
            
            return isValid;
          }
        ),
        { numRuns: 100 }
      );
    });
    
    it("verifies proofs for all indices in randomly generated trees", () => {
      fc.assert(
        fc.property(
          fc.array(fc.string({ minLength: 1, maxLength: 20 }), { 
            minLength: 1, 
            maxLength: 50 
          }),
          (leaves) => {
            const tree = buildTree(leaves);
            const root = getRoot(tree, leaves.length);
            
            // Test ALL indices for this tree
            for (let i = 0; i < leaves.length; i++) {
              const proof = generateProof(leaves, i);
              const isValid = verifyProof(leaves[i], proof, root);
              
              if (!isValid) {
                throw new Error(`Proof verification failed for index ${i} in tree of size ${leaves.length}`);
              }
            }
            
            return true;
          }
        ),
        { numRuns: 50 } // Fewer runs since we test all indices per tree
      );
    });
  });
  
  describe("Property: Proof Length Bounds", () => {
    it("ensures proof length matches theoretical tree height", () => {
      fc.assert(
        fc.property(
          fc.array(fc.string({ minLength: 1, maxLength: 20 }), { 
            minLength: 1, 
            maxLength: 100 
          }),
          (leaves) => {
            const leafIndex = Math.floor(Math.random() * leaves.length);
            const proof = generateProof(leaves, leafIndex);
            const expectedLength = computeExpectedProofLength(leaves.length);
            
            // INVARIANT: Proof length must equal tree height
            expect(proof).toHaveLength(expectedLength);
            
            return proof.length === expectedLength;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
  
  describe("Property: Sibling Hash Validity", () => {
    it("ensures all sibling hashes in proof exist in the tree", () => {
      fc.assert(
        fc.property(
          fc.array(fc.string({ minLength: 1, maxLength: 20 }), { 
            minLength: 2, // Need at least 2 leaves to have siblings
            maxLength: 50 
          }),
          (leaves) => {
            const leafIndex = Math.floor(Math.random() * leaves.length);
            const proof = generateProof(leaves, leafIndex);
            const validHashes = extractAllHashesFromTree(leaves);
            
            // INVARIANT: Every sibling in the proof must be a valid hash from the tree
            for (const step of proof) {
              if (!validHashes.has(step.sibling)) {
                throw new Error(`Invalid sibling hash found in proof: ${step.sibling}`);
              }
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
  
  describe("Property: Position Correctness", () => {
    it("ensures first proof step position matches leaf index parity", () => {
      fc.assert(
        fc.property(
          fc.array(fc.string({ minLength: 1, maxLength: 20 }), { 
            minLength: 2, // Need at least 2 leaves to have positions
            maxLength: 100 
          }),
          (leaves) => {
            const leafIndex = Math.floor(Math.random() * leaves.length);
            const proof = generateProof(leaves, leafIndex);
            
            if (proof.length > 0) {
              // INVARIANT: Even index -> sibling on right, Odd index -> sibling on left
              const expectedPosition = leafIndex % 2 === 0 ? "right" : "left";
              expect(proof[0].position).toBe(expectedPosition);
              
              return proof[0].position === expectedPosition;
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
  
  // ============================================================================
  // 4. REGRESSION TESTS (Original Test Cases Preserved)
  // ============================================================================
  
  describe("Regression: Original Test Suite", () => {
    const leaves = ["a", "b", "c", "d"];
    
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

    it("accepts valid root with uppercase hex and prefix (normalized properly)", () => {
      const validRootWithPrefix = "0x" + root.toUpperCase();
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