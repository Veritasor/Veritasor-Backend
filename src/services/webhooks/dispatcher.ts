import crypto from "crypto";

export type WebhookAlgorithm = "hmac-sha256" | "ed25519";

export interface WebhookSubscription {
  id: string;
  businessId: string;
  url: string;
  secret: string;
  algo?: WebhookAlgorithm | string;
}

export interface WebhookDeliveryReceipt {
  delivery_id: string;
  attempt: number;
  signature: string;
  algo: string;
  timestamp: string;
}

/**
 * Signs the outbound payload and constructs a verifiable delivery receipt.
 * Supports algorithm negotiation (HMAC-SHA256 and Ed25519) per subscription.
 */
export function signAndPrepareDelivery(
  payload: object,
  subscription: WebhookSubscription,
  attempt: number = 1
): { headers: Record<string, string>; receipt: WebhookDeliveryReceipt } {
  const deliveryId = crypto.randomUUID();
  const serializedPayload = JSON.stringify(payload);
  const dataToSign = `${deliveryId}.${attempt}.${serializedPayload}`;

  const rawAlgo = subscription.algo || "hmac-sha256";
  const algo = rawAlgo.toLowerCase();

  let signature: string;
  let normalizedAlgo: string;

  if (algo === "hmac-sha256" || algo === "hmac" || algo === "sha256") {
    normalizedAlgo = "hmac-sha256";
    signature = crypto
      .createHmac("sha256", subscription.secret)
      .update(dataToSign)
      .digest("hex");
  } else if (algo === "ed25519") {
    normalizedAlgo = "ed25519";
    try {
      let key: crypto.KeyObject | string = subscription.secret;
      if (typeof subscription.secret === "string" && !subscription.secret.includes("-----BEGIN")) {
        try {
          key = crypto.createPrivateKey(subscription.secret);
        } catch {
          key = crypto.createPrivateKey({
            key: Buffer.from(subscription.secret, "utf8"),
            format: "pem",
            type: "pkcs8"
          });
        }
      }
      signature = crypto.sign(null, Buffer.from(dataToSign), key).toString("hex");
    } catch (err: any) {
      signature = crypto.sign(null, Buffer.from(dataToSign), subscription.secret).toString("hex");
    }
  } else {
    throw new Error(`Unsupported webhook signature algorithm: ${subscription.algo}`);
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Veritasor-Delivery-Id": deliveryId,
    "X-Veritasor-Attempt": attempt.toString(),
    "X-Veritasor-Signature": signature,
    "X-Veritasor-Signature-Alg": normalizedAlgo,
  };

  const receipt: WebhookDeliveryReceipt = {
    delivery_id: deliveryId,
    attempt,
    signature,
    algo: normalizedAlgo,
    timestamp: new Date().toISOString(),
  };

  return { headers, receipt };
}

/**
 * Helper utility to verify webhook signatures using either HMAC-SHA256 or Ed25519
 */
export function verifyWebhookSignature(
  payload: object,
  deliveryId: string,
  attempt: number,
  signature: string,
  secretOrPublicKey: string,
  algo: string = "hmac-sha256"
): boolean {
  const serializedPayload = JSON.stringify(payload);
  const dataToSign = `${deliveryId}.${attempt}.${serializedPayload}`;
  const normalizedAlgo = algo.toLowerCase();

  if (normalizedAlgo === "hmac-sha256" || normalizedAlgo === "hmac" || normalizedAlgo === "sha256") {
    const expected = crypto
      .createHmac("sha256", secretOrPublicKey)
      .update(dataToSign)
      .digest("hex");
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } else if (normalizedAlgo === "ed25519") {
    return crypto.verify(
      null,
      Buffer.from(dataToSign),
      secretOrPublicKey,
      Buffer.from(signature, "hex")
    );
  } else {
    throw new Error(`Unsupported webhook signature algorithm: ${algo}`);
  }
}