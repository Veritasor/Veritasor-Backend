import { describe, it, expect } from "vitest";
import { buildTree, getRoot } from "./buildTree.js";
import { generateProof, verifyProof } from "./generateProof.js";
describe("Merkle proof", () => {
    const leaves = ["a", "b", "c", "d"];
    it("generates a valid proof for each leaf", () => {
        const tree = buildTree(leaves);
        const root = getRoot(tree, leaves.length);
        leaves.forEach((leaf, i) => {
            const proof = generateProof(leaves, i);
            expect(verifyProof(leaf, proof, root)).toBe(true);
        });
    });
    it("handles odd number of leaves", () => {
        const oddLeaves = ["a", "b", "c"];
        const tree = buildTree(oddLeaves);
        const root = getRoot(tree, oddLeaves.length);
        const proof = generateProof(oddLeaves, 2);
        expect(verifyProof("c", proof, root)).toBe(true);
    });
});
