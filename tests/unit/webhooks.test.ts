import crypto from "crypto";
import { describe, it, expect } from "vitest";
import {
  signAndPrepareDelivery,
  verifyWebhookSignature,
  WebhookSubscription,
} from "../../src/services/webhooks/dispatcher";

describe("Business Fan-out Webhooks Dispatch Verification Matrix", () => {
  const mockSubscription: WebhookSubscription = {
    id: "sub-123",
    businessId: "biz-456",
    url: "https://client.site/webhook",
    secret: "super-secret-crypto-signing-key-string-padding-32b",
  };

  const mockEvent = { event: "attestation.created", root: "0xhash" };

  it("constructs a signature receipt conforming to structured parameters (default HMAC-SHA256)", () => {
    const { headers, receipt } = signAndPrepareDelivery(mockEvent, mockSubscription, 1);

    expect(headers["X-Veritasor-Signature"]).toBeDefined();
    expect(headers["X-Veritasor-Signature-Alg"]).toBe("hmac-sha256");
    expect(receipt).toMatchObject({
      delivery_id: expect.any(String),
      attempt: 1,
      signature: headers["X-Veritasor-Signature"],
      algo: "hmac-sha256",
      timestamp: expect.any(String),
    });

    const isValid = verifyWebhookSignature(
      mockEvent,
      receipt.delivery_id,
      receipt.attempt,
      receipt.signature,
      mockSubscription.secret,
      "hmac-sha256"
    );
    expect(isValid).toBe(true);
  });

  it("signs and verifies using explicit hmac-sha256 algorithm", () => {
    const sub: WebhookSubscription = {
      ...mockSubscription,
      algo: "hmac-sha256",
    };
    const { headers, receipt } = signAndPrepareDelivery(mockEvent, sub, 2);

    expect(headers["X-Veritasor-Signature-Alg"]).toBe("hmac-sha256");
    expect(receipt.algo).toBe("hmac-sha256");

    const isValid = verifyWebhookSignature(
      mockEvent,
      receipt.delivery_id,
      2,
      receipt.signature,
      sub.secret,
      "hmac-sha256"
    );
    expect(isValid).toBe(true);
  });

  it("signs and verifies using ed25519 algorithm for enterprise tenants", () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const ed25519Sub: WebhookSubscription = {
      id: "sub-enterprise-999",
      businessId: "biz-ent-1",
      url: "https://enterprise.client/webhook",
      secret: privateKey,
      algo: "ed25519",
    };

    const { headers, receipt } = signAndPrepareDelivery(mockEvent, ed25519Sub, 1);

    expect(headers["X-Veritasor-Signature-Alg"]).toBe("ed25519");
    expect(receipt.algo).toBe("ed25519");
    expect(receipt.signature).toBeDefined();

    const isValid = verifyWebhookSignature(
      mockEvent,
      receipt.delivery_id,
      receipt.attempt,
      receipt.signature,
      publicKey,
      "ed25519"
    );
    expect(isValid).toBe(true);
  });

  it("rejects unknown signature algorithms with an error", () => {
    const invalidSub: WebhookSubscription = {
      ...mockSubscription,
      algo: "invalid-sha999",
    };

    expect(() => signAndPrepareDelivery(mockEvent, invalidSub, 1)).toThrow(
      /Unsupported webhook signature algorithm: invalid-sha999/
    );

    expect(() =>
      verifyWebhookSignature(mockEvent, "d-1", 1, "sig", "secret", "unknown-algo")
    ).toThrow(/Unsupported webhook signature algorithm: unknown-algo/);
  });
});