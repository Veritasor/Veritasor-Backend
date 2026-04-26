export { hash, buildTree, getRoot, MERKLE_MAX_LEAVES, MERKLE_WARN_LEAVES } from './buildTree.js';
export {
  generateProof,
  verifyProof,
  normalizeHashHex,
  isHashHex,
  isProofStep,
  isProof,
  MERKLE_PROOF_MAX_STEPS,
} from './generateProof.js';
export type { ProofStep, Proof } from './generateProof.js';