import { describe, expect, it } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";
import { validateBatchParams } from "../../../../src/services/soroban/batchSubmitTransport.js";
import { SorobanSubmissionError } from "../../../../src/services/soroban/submitAttestation.js";

describe("validateBatchParams", () => {
  const keypair = Keypair.random();

  it("accepts valid params with an inline signer secret", () => {
    expect(() =>
      validateBatchParams({
        business: "biz",
        period: "2025-10",
        merkleRoot: "root",
        timestamp: 1,
        version: "1.0.0",
        sourcePublicKey: keypair.publicKey(),
        signerSecret: keypair.secret(),
      }),
    ).not.toThrow();
  });

  it("rejects invalid public keys", () => {
    expect(() =>
      validateBatchParams({
        business: "biz",
        period: "2025-10",
        merkleRoot: "root",
        timestamp: 1,
        version: "1.0.0",
        sourcePublicKey: "not-a-key",
        signerSecret: keypair.secret(),
      }),
    ).toThrow(SorobanSubmissionError);
  });

  it("requires a signer when submit is true", () => {
    const previous = process.env.SOROBAN_SOURCE_SECRET;
    delete process.env.SOROBAN_SOURCE_SECRET;

    try {
      expect(() =>
        validateBatchParams({
          business: "biz",
          period: "2025-10",
          merkleRoot: "root",
          timestamp: 1,
          version: "1.0.0",
          sourcePublicKey: keypair.publicKey(),
        }),
      ).toThrow(SorobanSubmissionError);
    } finally {
      if (previous !== undefined) {
        process.env.SOROBAN_SOURCE_SECRET = previous;
      }
    }
  });
});
