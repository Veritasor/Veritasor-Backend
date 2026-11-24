# Webhook Signature Algorithm Negotiation & Key Rotation Guidance

## Overview

Veritasor supports per-subscription webhook signature algorithm negotiation. While standard subscriptions use `hmac-sha256` by default, enterprise tenants can configure subscriptions to use asymmetric `ed25519` key pairs for enhanced cryptographic security and non-repudiation.

## Supported Algorithms

1. **`hmac-sha256`** (Default): Symmetric HMAC signature computed over `${delivery_id}.${attempt}.${timestamp}.${payload}` using the shared subscription secret.
2. **`ed25519`**: Asymmetric signature generated using an Ed25519 private key (PKCS#8 PEM format) stored as the subscription secret. Recipients verify the signature using the corresponding Ed25519 public key (SPKI PEM format).

## HTTP Header Specification

Outbound webhook requests contain the following headers:

- `X-Veritasor-Delivery-Id`: Unique UUID string for the delivery attempt.
- `X-Veritasor-Attempt`: Retry attempt counter (integer starting at 1).
- `X-Veritasor-Timestamp`: Unix timestamp used in the signed payload.
- `X-Veritasor-Signature`: Hex-encoded signature string produced with the current secret.
- `X-Veritasor-Signature-Alg`: The signature algorithm negotiated for the subscription (`hmac-sha256` or `ed25519`).
- `X-Veritasor-Signature-Version`: Version of the secret used for `X-Veritasor-Signature`.
- `X-Veritasor-Previous-Signature`: Hex-encoded signature produced with the previous secret. Present only during a rotation grace window.
- `X-Veritasor-Previous-Signature-Version`: Version of the secret used for `X-Veritasor-Previous-Signature`.

## Signature Verification Payload

The data signed for both algorithms is constructed as:
```
<X-Veritasor-Delivery-Id>.<X-Veritasor-Attempt>.<X-Veritasor-Timestamp>.<JSON_Stringified_Body>
```

### Verification Examples

#### HMAC-SHA256 Verification (TypeScript / Node.js)
```typescript
import crypto from "crypto";

function verifyHmac(payload: object, deliveryId: string, attempt: number, timestamp: string, signature: string, secret: string): boolean {
  const data = `${deliveryId}.${attempt}.${timestamp}.${JSON.stringify(payload)}`;
  const expected = crypto.createHmac("sha256", secret).update(data).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
```

#### Ed25519 Verification (TypeScript / Node.js)
```typescript
import crypto from "crypto";

function verifyEd25519(payload: object, deliveryId: string, attempt: number, timestamp: string, signatureHex: string, publicKeyPem: string): boolean {
  const data = `${deliveryId}.${attempt}.${timestamp}.${JSON.stringify(payload)}`;
  return crypto.verify(null, Buffer.from(data), publicKeyPem, Buffer.from(signatureHex, "hex"));
}
```

## Explicit Secret Rotation

`POST /api/v1/webhook-subscriptions/:id/rotate-secret` generates a new signing secret server-side and returns it once in the response. The previous secret is stored encrypted together with an expiry (`gracePeriodSeconds`, default 300, maximum 86,400). During that window every delivery carries both `X-Veritasor-Signature` (new secret) and `X-Veritasor-Previous-Signature` (old secret). After expiry only the current signature is emitted. A second rotation is rejected with 409 while the previous grace window is still active.

Receivers should accept either header while both are present, and track the version headers to avoid reprocessing older deliveries. Listing and fetching subscriptions never returns the plaintext secret; only the last four characters are exposed for identification.

## Key Rotation Guidance for Enterprise Tenants

Enterprise tenants transitioning between signature algorithms or rotating cryptographic secrets should follow this zero-downtime rotation protocol:

### Step-by-Step Rotation Protocol

1. **Generate New Key Pair**:
   - For Ed25519 rotation, generate a new Ed25519 PKCS#8 private key and SPKI public key pair:
     ```bash
     openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
     openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem
     ```
2. **Pre-deploy Public Key to Receiver**:
   - Register the new public key on the webhook receiver side alongside the existing active key or secret.
3. **Update Subscription Algorithm and Secret**:
   - Update the webhook subscription setting `algo` to `ed25519` and `secret` to the new private key in Veritasor.
   - Outbound deliveries will immediately start signing with `ed25519` and advertising `X-Veritasor-Signature-Alg: ed25519`.
4. **Decommission Old Key**:
   - Once all active deliveries confirm success using the new signature, remove the legacy HMAC secret or previous Ed25519 public key from the receiver configuration.
