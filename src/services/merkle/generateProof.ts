import {
  hash as hashLeaf,
  hashNode,
  hashV1,
  hashV2,
  type MerkleAlgorithmVersion,
} from "./buildTree.js";

export type MerkleProofVersion = MerkleAlgorithmVersion;

/**
 * Proof format:
 * An array of { sibling: string, position: 'left' | 'right' } objects.
 * To verify: starting from the hashed leaf, repeatedly hash(sibling || current)
 * or hash(current || sibling) depending on position, until you reach the root.
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
export function generateProof(
  leaves: string[],
  leafIndex: number,
  version: MerkleAlgorithmVersion = 2
): Proof {
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

  let level: string[] = leaves.map((l) => hashLeaf(l, version));
  let index = leafIndex;
  const proof: Proof = [];

  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    if (siblingIndex >= 0 && siblingIndex < level.length) {
      proof.push({
        sibling: level[siblingIndex],
        position: index % 2 === 0 ? "right" : "left",
      });
    }

    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      if (i + 1 < level.length) {
        next.push(hashNode(left, level[i + 1], version));
      } else {
        next.push(left);
      }
    }
    level = next;
    index = Math.floor(index / 2);
  }

  return proof;
}

export function generateProofV1(leaves: string[], leafIndex: number): Proof {
  return generateProof(leaves, leafIndex, 1);
}

export function generateProofV2(leaves: string[], leafIndex: number): Proof {
  return generateProof(leaves, leafIndex, 2);
}

function expectedProofLength(leafIndex: number, treeSize: number): number {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return -1;
  if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) return -1;

  let currentIndex = leafIndex;
  let currentSize = treeSize;
  let length = 0;

  while (currentSize > 1) {
    if (currentIndex % 2 === 0) {
      if (currentIndex + 1 < currentSize) {
        length += 1;
      }
    } else {
      length += 1;
    }

    currentIndex = Math.floor(currentIndex / 2);
    currentSize = Math.ceil(currentSize / 2);
  }

  return length;
}

/**
 * @notice Verify a Merkle proof against a known root.
 * @dev Returns false on guard failures (invalid inputs, malformed proof, bad root).
 * When leafIndex and treeSize are provided, the proof length must match the exact
 * path expected for that leaf in a tree of that size.
 */
export function verifyProof(
  leaf: string,
  proof: Proof,
  root: string,
  leafIndex?: number,
  treeSize?: number,
  version: MerkleAlgorithmVersion = 2
): boolean {
  if (typeof leaf !== "string") return false;
  const normalizedRoot = normalizeHashHex(root);
  if (!normalizedRoot) return false;
  if (!isProof(proof)) return false;

  if (typeof leafIndex === "number" && typeof treeSize === "number") {
    const expectedLength = expectedProofLength(leafIndex, treeSize);
    if (expectedLength < 0 || proof.length !== expectedLength) return false;
  }

  let current = hashLeaf(leaf, version);

  for (const step of proof) {
    const sibling = normalizeHashHex(step.sibling);
    if (!sibling) return false;

    if (step.position === "right") {
      current = hashNode(current, sibling, version);
    } else {
      current = hashNode(sibling, current, version);
    }
  }

  return current === normalizedRoot;
}

export function verifyProofV1(
  leaf: string,
  proof: Proof,
  root: string,
  leafIndex?: number,
  treeSize?: number
): boolean {
  return verifyProof(leaf, proof, root, leafIndex, treeSize, 1);
}

export function verifyProofV2(
  leaf: string,
  proof: Proof,
  root: string,
  leafIndex?: number,
  treeSize?: number
): boolean {
  return verifyProof(leaf, proof, root, leafIndex, treeSize, 2);
}

export { hashV1, hashV2 };
export const hash = hashV2;
export const hashLegacy = hashV1;
