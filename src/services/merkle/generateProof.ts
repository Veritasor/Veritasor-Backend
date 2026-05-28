import { hash } from "./buildTree.js";

/**
 * Proof format:
 * An array of { sibling: string, position: 'left' | 'right' } objects.
 * To verify: starting from the hashed leaf, repeatedly hash(sibling + current)
 * or hash(current + sibling) depending on position, until you reach the root.
 */
export interface ProofStep {
  sibling: string;
  position: "left" | "right";
}

export type Proof = ProofStep[];

/**
 * @notice Maximum number of proof steps accepted by verification guards.
 * @dev 256 steps supports trees up to 2^256 leaves and caps CPU work.
 */
export const MERKLE_PROOF_MAX_STEPS = 256;

const HASH_HEX_REGEX = /^[0-9a-f]{64}$/i;

function stripHexPrefix(value: string): string {
  return value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
}

/**
 * @notice Normalize a 32-byte hash encoded as hex.
 * @dev Accepts optional 0x prefix and returns lowercase hex or null if invalid.
 */
export function normalizeHashHex(value: string): string | null {
  if (typeof value !== "string") return null;
  const stripped = stripHexPrefix(value);
  if (!HASH_HEX_REGEX.test(stripped)) return null;
  return stripped.toLowerCase();
}

/**
 * @notice Type guard for a hex-encoded SHA-256 hash.
 */
export function isHashHex(value: unknown): value is string {
  return typeof value === "string" && normalizeHashHex(value) !== null;
}

/**
 * @notice Type guard for a Merkle proof step.
 */
export function isProofStep(value: unknown): value is ProofStep {
  if (!value || typeof value !== "object") return false;
  const step = value as ProofStep;
  if (step.position !== "left" && step.position !== "right") return false;
  return isHashHex(step.sibling);
}

/**
 * @notice Type guard for a Merkle proof array.
 * @dev Enforces a max proof length to avoid unbounded verification loops.
 */
export function isProof(value: unknown): value is Proof {
  if (!Array.isArray(value)) return false;
  if (value.length > MERKLE_PROOF_MAX_STEPS) return false;
  return value.every((step) => isProofStep(step));
}

/**
 * @notice Generate a Merkle proof for a leaf at a specific index.
 * @dev Guards validate inputs to prevent malformed proofs.
 */
export function generateProof(leaves: string[], leafIndex: number): Proof {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error("leaves must be a non-empty array of strings");
  }
  for (const leaf of leaves) {
    if (typeof leaf !== "string") {
      throw new Error("leaves must be a non-empty array of strings");
    }
  }
  if (!Number.isInteger(leafIndex)) {
    throw new Error("leafIndex must be an integer");
  }
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error("leafIndex out of range");
  }

  let level: string[] = leaves.map((l) => hash(l));
  let index = leafIndex;
  const proof: Proof = [];

  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    const sibling =
      siblingIndex < level.length ? level[siblingIndex] : level[index]; // duplicate if odd

    proof.push({
      sibling,
      position: index % 2 === 0 ? "right" : "left",
    });

    // Move up to next level
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(hash(left + right));
    }
    level = next;
    index = Math.floor(index / 2);
  }

  return proof;
}

/**
 * @notice Verify a Merkle proof against a known root.
 * @dev Returns false on guard failures (invalid inputs, malformed proof, bad root).
 */
export function verifyProof(leaf: string, proof: Proof, root: string): boolean {
  if (typeof leaf !== "string") return false;
  const normalizedRoot = normalizeHashHex(root);
  if (!normalizedRoot) return false;
  if (!isProof(proof)) return false;

  let current = hash(leaf);

  for (const step of proof) {
    const sibling = normalizeHashHex(step.sibling);
    if (!sibling) return false;

    if (step.position === "right") {
      current = hash(current + sibling);
    } else {
      current = hash(sibling + current);
    }
  }

  return current === normalizedRoot;
}
