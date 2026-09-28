/**
 * Tests for src/services/webhooks/dispatcher.ts
 *
 * Coverage targets (issue #1018):
 *  - WebhookPayloadTooLargeError: explicit failure contract (code, statusCode)
 *  - signAndPrepareDelivery: payload-size rejection branch + audit log,
 *    normal signing path, and the exact-maxPayloadSize / utf8 byte-length boundary
 *  - resolveDotPath null / non-object guards (via shouldDeliverEvent object filters)
 *  - mTLS client-certificate expiry: thrown error contract + audit log + no delivery
 *  - verifyWebhookSignature: success, missing headers, NaN timestamp, replay window,
 *    wrong/tampered signatures, array-valued headers
 *  - sendWebhookDelivery: success result shape, HTTP/network failure paths,
 *    receipt persistence, response truncation
 *
 * mTLS tests use real X.509 fixtures (valid and expired) so the
 * crypto.X509Certificate parsing path is exercised for real.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as https from "node:https";

vi.mock("../../../../src/utils/secret-loader.js", () => ({
  secretLoader: { get: vi.fn() },
}));

vi.mock("../../../../src/repositories/auditLogRepository.js", () => ({
  createAuditLog: vi.fn().mockResolvedValue(true),
}));

vi.mock("../../../../src/repositories/deliveryReceiptRepository.js", () => ({
  createDeliveryReceipt: vi.fn().mockResolvedValue(true),
}));

vi.mock("../../../../src/metrics.js", () => ({
  staleWebhookDeliveries: { inc: vi.fn() },
}));

import { secretLoader } from "../../../../src/utils/secret-loader.js";
import { createAuditLog } from "../../../../src/repositories/auditLogRepository.js";
import { createDeliveryReceipt } from "../../../../src/repositories/deliveryReceiptRepository.js";
import { staleWebhookDeliveries } from "../../../../src/metrics.js";
import {
  WebhookPayloadTooLargeError,
  signAndPrepareDelivery,
  verifyWebhookSignature,
  shouldDeliverEvent,
  sendWebhookDelivery,
  type WebhookSubscription,
  type WebhookDeliveryReceipt,
} from "../../../../src/services/webhooks/dispatcher.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Self-signed certificate valid 2026-09-28 -> 2126-09-04
const VALID_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUR71dboXmWuAwbaPdDjB3tXvM5ewwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPdmVyaXRhc29yLXZhbGlkMCAXDTI2MDkyODA5MjUzOFoY
DzIxMjYwOTA0MDkyNTM4WjAaMRgwFgYDVQQDDA92ZXJpdGFzb3ItdmFsaWQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxzHOvtKPSnajJBdzJysSJZSN5
YGwsVxO4T9htpuZTjqxoUNqScDe4LlIRFsS1GHjPZdab8kK8XhQq1Zctu/X3mUTj
FtDC/jHTFlAkaXvpB+dvlMTGCG+A6dq20OmI1ct4FNVkDdzz73zn+UtMQWVvhRmt
soMKPDwSq21EveWlfx6OTX9CLRy1iLtSA/pboQBuiJSKHy4zECtBuHy3UDVVmFzH
/2hdvSkVk4unFqazfJ2uIrOc0OuvKrDSSRYkVFZip8oOZl8SxIfrOdSJdIWX4iQB
NMIG3bZKKOlLchR5MA4eeBmZ1q7rFmNHJnSg8TFVkauyibB9l0jnCDKnaM7DAgMB
AAGjUzBRMB0GA1UdDgQWBBRrUjV03X54sDIlKUV5ii0Ps29OTjAfBgNVHSMEGDAW
gBRrUjV03X54sDIlKUV5ii0Ps29OTjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQB0ves1ENgOfWegt4+pMKjbP4ZFzLU2CtTQxi5HInMJ0ZTH9W88
gAHWWVASAO+pHuf5l21ChZloFcvb940cFhkXDRxO7ofpIm/j9mmFgD22FySJ5YAG
2UkGS+bmhUsVzkhos5aVrdqYRjmcEs0qmUwrJggRH0WxkG4223y6fjpukestISOl
UIwFthiw4SpqpiaLLp4bugE8aBMsxD/mPL1QopGWj1yiUMBGUT3TgU3eK+M/gt0Q
llRkawDNiaSo11EMEZRx99QpOis0sAafhejec744klmxazl31s8+WGfIxOIMIR2C
/pkH0ofaiv5Kqenj0JH4Q52Uatq5oafHgMIH
-----END CERTIFICATE-----`;

const VALID_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCxzHOvtKPSnajJ
BdzJysSJZSN5YGwsVxO4T9htpuZTjqxoUNqScDe4LlIRFsS1GHjPZdab8kK8XhQq
1Zctu/X3mUTjFtDC/jHTFlAkaXvpB+dvlMTGCG+A6dq20OmI1ct4FNVkDdzz73zn
+UtMQWVvhRmtsoMKPDwSq21EveWlfx6OTX9CLRy1iLtSA/pboQBuiJSKHy4zECtB
uHy3UDVVmFzH/2hdvSkVk4unFqazfJ2uIrOc0OuvKrDSSRYkVFZip8oOZl8SxIfr
OdSJdIWX4iQBNMIG3bZKKOlLchR5MA4eeBmZ1q7rFmNHJnSg8TFVkauyibB9l0jn
CDKnaM7DAgMBAAECggEABiy3h86aMeJPzktp04g7MxpUFQ8IMrIDeU8skQJO1XAL
BMRqEtPa24agSv+jbTagW3OJ9HiBYNFTmfk4+tmgPS0Re2F7doolaNNJjTosl3cy
zmk4PDhmxu9YLSksMxhZrJ3sm0Dv/3i9ucCqoMdUon7Y2XNtoZld7LgPX2fI5epp
b15ziK5obNY0a6JlIyPqM49TeHgqkJIeNw/ikqO9zcP666brEvkKv3IJG85Ntroy
VgXhbj5VsqQehBDLw3NnFu+qTwd3nncp6MqYv19ZozNFlYKo9FFgjrgbxqFo3hiB
IBpE6xIlo8XPJVxz25NDDCr5ZhPoRhthRnhFHp1AgQKBgQDYJx5HwKV4eEPz9ptv
S8PlIT/1L/TzwFUJPmlM92Uy8qLc1wGXy3RnPtc+U2iIi4ueVayweHKOZuFqW0xE
7jy/PqNBYby8AeipI4qcv82s/+6qXLs3C5OULTvJHLIfUuX2VEYEqXPvI4ApLrvr
W9k/EXM+qm9zJ4WqstjVGFfcEQKBgQDSk0nikfVLsQzZJY1ZZiDkeMDbqdcaa+fP
i9is/b7eOV3NXh0Af9Mi9wqGQjMe8Jy+iJPElx9iHyPNaurXCEt+lRXwwEJPKjDc
iRb5enTKzzAgBaDboX6srNLACxLMQ2EgRRb45MsMf6mx3YXYAFsjXuLcfdUjdvOL
GXdlyGNhkwKBgEjN1Dsivhk3mNvBQlVYVaEFc/9nqb+4FmxIozsTUPi6FPUBTj4M
fyaPWfxaJ6lmJx6riMDfsOYZ7O7f1W6aN8fKlz5cZy+EDRN7LyLgz6vngEHNfhlq
Qsjz+2Ef0zcNuvsfI35KfQwdDvvQC+eYRjIh9Ik06tkEhNcb6kDMNDuhAoGBAIJP
O23GPTH2AqluH6avGLPKNi65T6++DtnVBOUosbD7dxzbnL7uW05L6mtjFBeVdqpC
Ao+ppXYnJxS7kVA4hd9zivxNPbuXtF0FSP5h1VycEn/+e6juq2FYIaNONvfIypYZ
qzmi/DRj3DOBjo44yi19To58ICWuOtBdlhGajEWZAoGBAMpSdWZ12lDK6Sp7Zx0c
En4qqO8s+dvDx5bLd+ENHrLLITs5Bhlqt/5BsJvya9QhTnqoGfUkIY2WsQ81HB39
pFCgTC6RuVWVCn7jHA1gv8wU1NmxuPEdOldmowqA4TIX/vOEIJe5Rf3kCOmsOyP0
JaTViIRgGst5JqAkOHJVBzVe
-----END PRIVATE KEY-----`;

// Self-signed certificate expired 2024-06-01
const EXPIRED_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIUfpL/xojcU/92/yhXvjlL/q8vmCQwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRdmVyaXRhc29yLWV4cGlyZWQwHhcNMjQwMTAxMDAwMDAw
WhcNMjQwNjAxMDAwMDAwWjAcMRowGAYDVQQDDBF2ZXJpdGFzb3ItZXhwaXJlZDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALzQJUgCkTT3kqJBax6IQZiS
5QiT0XG5/iSDxqciXIANtTpFI459otrE8n+W6sd73lWgGudAKfzmTvBCIO2OYuh+
Vv8bzv175/X/POpQx6ymEOH1sRkzT+N5TLEL8n7VkI/mYBSHqOCuy0hMFwZN+wZJ
nGntr8RC4zse7yHZemqykeKi3KnOir1llFLNPmyhiS3qb+7Qr2ZM+6prRO52qLlS
xjbF8JfcOvIcxpQJZOtEvJCPvHuMdxwY5hojs866PtPDvaEkqD4uufv+atugV+wI
tvSD1X9lp4Vti9y8Sw53YavPfUO3EtsL/Cd/QyZqdwMwnCfJW+s0xx9/ale9PX0C
AwEAAaNTMFEwHQYDVR0OBBYEFAdJIhQvG8aTJEYvh31DFTTGmCrsMB8GA1UdIwQY
MBaAFAdJIhQvG8aTJEYvh31DFTTGmCrsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAJ2ZW6/z0IMj9SSXTX+KJjieVIXp7TKtojnhdlomkqPWHVNa
I+51NrVyvdw/lEhi/Hzr0Dw/yc6l7/sGXS2nbiIyplzUWZdznrcTNmPFJwtiO867
DSC8wphqQc0ACGKz/07OjBrX3GndH4vE3TXDv/Y0pvTFexP0iw/0fV2sq+3jyOJB
DD2b5WYkVVcT412EEf9dlEhBuEnad9+VOBB3taYJo7F28ZIT2mhURBLTyCeNoFN7
JsHXtEyDihhYsoPpOkDPXigqVqZ5H3tKR4rLfxzKhsdVX7Fg5sB8yKHXLs9d1O1V
4Z2QnRhIKhpx08RJDukyLwNFffUy8a9ZYbjIrI8=
-----END CERTIFICATE-----`;

const EXPIRED_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC80CVIApE095Ki
QWseiEGYkuUIk9Fxuf4kg8anIlyADbU6RSOOfaLaxPJ/lurHe95VoBrnQCn85k7w
QiDtjmLoflb/G879e+f1/zzqUMesphDh9bEZM0/jeUyxC/J+1ZCP5mAUh6jgrstI
TBcGTfsGSZxp7a/EQuM7Hu8h2XpqspHiotypzoq9ZZRSzT5soYkt6m/u0K9mTPuq
a0Tudqi5UsY2xfCX3DryHMaUCWTrRLyQj7x7jHccGOYaI7POuj7Tw72hJKg+Lrn7
/mrboFfsCLb0g9V/ZaeFbYvcvEsOd2Grz31DtxLbC/wnf0MmancDMJwnyVvrNMcf
f2pXvT19AgMBAAECgf9a3WpG1vVw7oDV+3JecmeFa/jM9LyjmBHpgLR/um/8yc86
O6VHU/vYf7w0ETm4YEqfUNQID6W+3EpUIku2bZxfE6EwvcrfZY6ibcx8kMntf5dt
JtATtwRU2tgNj0vw8Tyg0KPS1xAIRBZdGw35lFptEplmx2Kb3ZSweJkC5HM4fq4q
YSr0KSSWwB8Zus/n8M2Rsbt3RLwfOw2fM1hiQ83Xj9Qq2ezVDHWc01T3yFmmlCHY
y7f3NWD4DQEFki1qLY1ZEWUa/tGOKn9DLvHpisHF4x1dkARdnAJAgYaJUpR6jmHP
+e8HUAVzBmEtvRb6hD8KGxDOra6zN+QlA83DF+ECgYEA/wt1eN8xPJe+SGpBmaQN
u9oRkpcddyLYIN94Y6YGHBaLYeCsrTmKZeqIZCJiXLQYC6paqkz3+ujtPBx8/cdm
5SnUdC79PXBOJSsxx1J9G6ZQhGckVLUx/ipLDQ6mO/JTQGOGj1zc/i51G0RnbUat
7E3hobrAb5gYQYBwOwVmgnsCgYEAvYUuxmxs5YZKZFJpv05+YXaN2UT/RSqX0LWk
ZyIvU+TteoJmXp+e8L8XaLD/uMUJZt9KwM67P/yq45s1rH/wGCfQpwH3XgYDYaO/
vYTNENAEe5XwlA5Nexk75Ij/yokoKNQB+fGPlmpqWdCPzBJssrIVaLyHEwTFrtdb
wnyG2mcCgYEAu1ufoHvVn72Ze3kTV9q8fBNmdVmtu6dNPljsB8gfFOM64Vw7fcWX
deck6uqXd6KVR3yNvi1svlX+cPo8l/G0FQT1naQnRMsLnSJuHw7p+TXkUF+0wMWb
RCutlpn8ZG1P2y1B3G9LqS5XuQA3On+BpOZRqo2WcGQ67WN9Dt6Yv6ECgYEAj/0g
DKFUGw5sdswmi7KXUnVAUFKbn3E85tUak0DltFe6Fdn87OdZWo/UuTXBFCCfhAki
QlrO6U6Oh17k6KpLQA7/9+MGjekDqKtAgjzjkGJ7BWpl3hb/xwbk+j0cGkUavepV
lhBxh1ZSdup+Vg2piBrFKU4TUd/OUYhNrvXtfwECgYBWMkG8aIsgjnlt+/SO08we
SEJkGBSqgE1IXwlCAq8O78t+5vfYrA+p4uqfUsN5C3hfxXqoelT8wCJtejZbVaJp
qGmCgWSx5Z6rDEjWA0wzaUtEfy6SZKeAz54D30Dj/xL3gmgqTdpjdxpnVsxWdbWU
f+dy4VEWgp+FgG9JXSIEJg==
-----END PRIVATE KEY-----`;

const SECRET = "test-webhook-secret";

function makeSubscription(overrides: Partial<WebhookSubscription> = {}): WebhookSubscription {
  return {
    id: "sub-1",
    businessId: "biz-1",
    url: "https://example.com/hook",
    secret: SECRET,
    ...overrides,
  };
}

const PAYLOAD = { event: "test.created", data: { id: 7 } };

const fetchMock = vi.fn();

function mockFetchOk(status = 200, body = "OK"): void {
  fetchMock.mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: vi.fn().mockResolvedValue(body),
  });
}

/**
 * Compute the HMAC the dispatcher must produce for the given receipt fields.
 * Mirrors the documented recipe: `${deliveryId}.${attempt}.${timestamp}.${body}`
 */
function expectedSignature(
  deliveryId: string,
  attempt: number,
  timestamp: string,
  body: string,
  secret = SECRET
): string {
  return crypto
    .createHmac("sha256", secret)
    .update(`${deliveryId}.${attempt}.${timestamp}.${body}`)
    .digest("hex");
}

import crypto from "node:crypto";

beforeEach(() => {
  vi.clearAllMocks();
  fetchMock.mockReset();
  mockFetchOk();
  vi.stubGlobal("fetch", fetchMock);
  vi.mocked(secretLoader.get).mockResolvedValue("unused");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// WebhookPayloadTooLargeError — explicit failure contract
// ---------------------------------------------------------------------------

describe("WebhookPayloadTooLargeError", () => {
  it("is an Error subclass with name, code and statusCode 413", () => {
    const err = new WebhookPayloadTooLargeError("too big");

    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("WebhookPayloadTooLargeError");
    expect(err.code).toBe("PAYLOAD_TOO_LARGE");
    expect(err.statusCode).toBe(413);
    expect(err.message).toBe("too big");
  });

  it("preserves distinguishability from generic Errors", () => {
    const err = new WebhookPayloadTooLargeError("too big");
    expect(err).not.toBeInstanceOf(TypeError);
    // Callers can branch on the code, not just the message
    expect((err as Error & { code?: string }).code).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// signAndPrepareDelivery — payload-size rejection + normal path
// ---------------------------------------------------------------------------

describe("signAndPrepareDelivery", () => {
  it("returns headers and receipt on the normal path", () => {
    const sub = makeSubscription();
    const { headers, receipt } = signAndPrepareDelivery(PAYLOAD, sub);

    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["X-Veritasor-Delivery-Id"]).toBe(receipt.delivery_id);
    expect(headers["X-Veritasor-Attempt"]).toBe("1");
    expect(headers["X-Veritasor-Timestamp"]).toBe(receipt.timestamp);
    expect(headers["X-Veritasor-Signature"]).toBe(receipt.signature);
  });

  it("produces a receipt with the full delivery contract", () => {
    const { receipt } = signAndPrepareDelivery(PAYLOAD, makeSubscription(), 3);

    const r: WebhookDeliveryReceipt = receipt;
    expect(r.delivery_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
    expect(r.attempt).toBe(3);
    expect(r.signature).toMatch(/^[a-f0-9]{64}$/);
    expect(r.timestamp).toMatch(/^\d+$/);
  });

  it("signs with HMAC-SHA256 over deliveryId.attempt.timestamp.body", () => {
    const { headers, receipt } = signAndPrepareDelivery(PAYLOAD, makeSubscription(), 2);
    const body = JSON.stringify(PAYLOAD);

    const expected = expectedSignature(
      receipt.delivery_id,
      2,
      receipt.timestamp,
      body
    );
    expect(headers["X-Veritasor-Signature"]).toBe(expected);
  });

  it("throws WebhookPayloadTooLargeError when the payload exceeds maxPayloadSize", () => {
    const sub = makeSubscription({ maxPayloadSize: 10 });

    expect(() => signAndPrepareDelivery(PAYLOAD, sub)).toThrow(
      WebhookPayloadTooLargeError
    );
    expect(() => signAndPrepareDelivery(PAYLOAD, sub)).toThrow(
      /payload size \(\d+ bytes\) exceeds maximum allowed size \(10 bytes\)/
    );
  });

  it("rejects at the exact byte boundary: max is inclusive, size > max fails", () => {
    const body = JSON.stringify(PAYLOAD);
    const byteLength = Buffer.byteLength(body, "utf8");
    const sub = makeSubscription({ maxPayloadSize: byteLength });

    // Exactly max bytes passes (boundary)
    expect(() => signAndPrepareDelivery(PAYLOAD, sub)).not.toThrow();

    // One byte over fails
    const overSub = makeSubscription({ maxPayloadSize: byteLength - 1 });
    expect(() => signAndPrepareDelivery(PAYLOAD, overSub)).toThrow(
      WebhookPayloadTooLargeError
    );
  });

  it("measures utf8 byte length, not character count", () => {
    // '{"k":"é"}' is 9 characters but 10 utf8 bytes (é is 2 bytes)
    const unicodePayload = { k: "é" };
    const charCount = JSON.stringify(unicodePayload).length;
    const byteLength = Buffer.byteLength(JSON.stringify(unicodePayload), "utf8");
    expect(charCount).toBe(9);
    expect(byteLength).toBe(10);

    const sub = makeSubscription({ maxPayloadSize: charCount });
    expect(() => signAndPrepareDelivery(unicodePayload, sub)).toThrow(
      WebhookPayloadTooLargeError
    );
  });

  it("skips the size check when maxPayloadSize is undefined", () => {
    const bigPayload = { blob: "x".repeat(10_000) };
    const sub = makeSubscription({ maxPayloadSize: undefined });

    expect(() => signAndPrepareDelivery(bigPayload, sub)).not.toThrow();
  });

  it("skips the size check when maxPayloadSize is null", () => {
    const bigPayload = { blob: "x".repeat(10_000) };
    const sub = makeSubscription({
      maxPayloadSize: null as unknown as number,
    });

    expect(() => signAndPrepareDelivery(bigPayload, sub)).not.toThrow();
  });

  it("writes a webhook_delivery_rejected audit log before throwing", () => {
    const sub = makeSubscription({ id: "sub-99", businessId: "biz-99", maxPayloadSize: 5 });

    expect(() => signAndPrepareDelivery(PAYLOAD, sub)).toThrow();

    expect(createAuditLog).toHaveBeenCalledExactlyOnceWith({
      userId: "biz-99",
      action: "webhook_delivery_rejected",
      resource: "webhook_subscription",
      resourceId: "sub-99",
      metadata: {
        reason: "PAYLOAD_TOO_LARGE",
        payloadSize: Buffer.byteLength(JSON.stringify(PAYLOAD), "utf8"),
        maxPayloadSize: 5,
      },
    });
  });

  it("does not write an audit log on the success path", () => {
    signAndPrepareDelivery(PAYLOAD, makeSubscription());
    expect(createAuditLog).not.toHaveBeenCalled();
  });

  it("generates unique delivery ids per call", () => {
    const a = signAndPrepareDelivery(PAYLOAD, makeSubscription()).receipt;
    const b = signAndPrepareDelivery(PAYLOAD, makeSubscription()).receipt;

    expect(a.delivery_id).not.toBe(b.delivery_id);
    expect(a.signature).not.toBe(b.signature);
  });
});

// ---------------------------------------------------------------------------
// shouldDeliverEvent — resolveDotPath null / non-object guards
// (evidence: dispatcher.ts:253-254)
// ---------------------------------------------------------------------------

describe("shouldDeliverEvent object filters (resolveDotPath guards)", () => {
  const filter = { "data.status": "confirmed" };

  it("delivers everything when no eventFilters are configured", () => {
    const sub = makeSubscription({ eventFilters: undefined });
    expect(shouldDeliverEvent("attestation.created", {}, sub)).toBe(true);

    const emptyFilters = makeSubscription({ eventFilters: {} });
    expect(shouldDeliverEvent("attestation.created", {}, emptyFilters)).toBe(true);
  });

  it("matches when the dot path resolves to the expected value (normal path)", () => {
    const sub = makeSubscription({ eventFilters: { "attestation.created": filter } });

    expect(
      shouldDeliverEvent(
        "attestation.created",
        { data: { status: "confirmed" } },
        sub
      )
    ).toBe(true);
  });

  it("coerces primitive matches via String() (42 vs '42')", () => {
    const sub = makeSubscription({
      eventFilters: { "attestation.created": { "data.id": "7" } },
    });

    expect(
      shouldDeliverEvent("attestation.created", { data: { id: 7 } }, sub)
    ).toBe(true);
  });

  it("returns false when an intermediate value is null (guard: current === null)", () => {
    const sub = makeSubscription({
      eventFilters: { "attestation.created": { "user.id": "42" } },
    });

    // 'user' resolves to null -> resolveDotPath must bail out with undefined
    expect(
      shouldDeliverEvent("attestation.created", { user: null }, sub)
    ).toBe(false);
  });

  it("returns false when an intermediate value is a primitive (guard: typeof !== object)", () => {
    const sub = makeSubscription({
      eventFilters: { "attestation.created": { "name.first": "Ada" } },
    });

    // 'name' resolves to the string 'alice'/'Ada' -> not an object -> undefined
    expect(
      shouldDeliverEvent("attestation.created", { name: "Ada Lovelace" }, sub)
    ).toBe(false);
  });

  it("returns false when the dot path resolves to undefined", () => {
    const sub = makeSubscription({ eventFilters: { "attestation.created": filter } });

    expect(
      shouldDeliverEvent("attestation.created", { data: {} }, sub)
    ).toBe(false);
    expect(shouldDeliverEvent("attestation.created", {}, sub)).toBe(false);
  });

  it("returns false when the value differs from the filter", () => {
    const sub = makeSubscription({ eventFilters: { "attestation.created": filter } });

    expect(
      shouldDeliverEvent(
        "attestation.created",
        { data: { status: "pending" } },
        sub
      )
    ).toBe(false);
  });

  it("applies object filters through segment wildcards (attestation.*)", () => {
    const wildcardSub = makeSubscription({
      eventFilters: { "attestation.*": filter },
    });

    expect(
      shouldDeliverEvent(
        "attestation.created",
        { data: { status: "confirmed" } },
        wildcardSub
      )
    ).toBe(true);
    expect(
      shouldDeliverEvent(
        "attestation.created",
        { data: { status: "revoked" } },
        wildcardSub
      )
    ).toBe(false);
  });

  it("applies object filters through the recursive wildcard (**)", () => {
    const recursiveSub = makeSubscription({
      eventFilters: { "**": filter },
    });

    expect(
      shouldDeliverEvent(
        "anything.at.all",
        { data: { status: "confirmed" } },
        recursiveSub
      )
    ).toBe(true);
    expect(
      shouldDeliverEvent(
        "anything.at.all",
        { data: { status: "nope" } },
        recursiveSub
      )
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sendWebhookDelivery — mTLS certificate expiry (evidence: dispatcher.ts:293)
// ---------------------------------------------------------------------------

describe("sendWebhookDelivery — mTLS certificate handling", () => {
  function mtlsSubscription(): WebhookSubscription {
    return makeSubscription({
      id: "sub-mtls",
      url: "https://secure.example.com/hook",
      mtlsConfig: {
        clientCertSecretId: "cert-secret",
        clientKeySecretId: "key-secret",
        caPinSecretId: "ca-secret",
      },
    });
  }

  function mockSecrets(cert: string, key: string): void {
    vi.mocked(secretLoader.get).mockReset();
    vi.mocked(secretLoader.get)
      .mockResolvedValueOnce(cert) // clientCertSecretId
      .mockResolvedValueOnce(key) // clientKeySecretId
      .mockResolvedValueOnce("pinned-ca-bytes"); // caPinSecretId
  }

  it("throws a descriptive error when the client certificate is expired", async () => {
    mockSecrets(EXPIRED_CERT_PEM, EXPIRED_KEY_PEM);

    await expect(
      sendWebhookDelivery({ subscription: mtlsSubscription(), payload: PAYLOAD })
    ).rejects.toThrow(
      /^Client certificate for subscription sub-mtls expired on \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/
    );
  });

  it("reports the certificate's actual notAfter date in the error", async () => {
    mockSecrets(EXPIRED_CERT_PEM, EXPIRED_KEY_PEM);

    // The fixture expired 2024-06-01T00:00:00Z; new Date(cert.validTo) must
    // surface exactly that instant in the thrown message
    await expect(
      sendWebhookDelivery({ subscription: mtlsSubscription(), payload: PAYLOAD })
    ).rejects.toThrow("expired on 2024-06-01T00:00:00.000Z");
  });

  it("the expired-cert error is a plain Error (no retryable code attached)", async () => {
    mockSecrets(EXPIRED_CERT_PEM, EXPIRED_KEY_PEM);

    const err = await sendWebhookDelivery({
      subscription: mtlsSubscription(),
      payload: PAYLOAD,
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(WebhookPayloadTooLargeError);
    expect((err as Error).message).toContain("sub-mtls");
  });

  it("writes an MTLS_CERT_EXPIRED audit log and aborts before delivery", async () => {
    mockSecrets(EXPIRED_CERT_PEM, EXPIRED_KEY_PEM);

    await expect(
      sendWebhookDelivery({ subscription: mtlsSubscription(), payload: PAYLOAD })
    ).rejects.toThrow();

    expect(createAuditLog).toHaveBeenCalledExactlyOnceWith({
      userId: "biz-1",
      action: "webhook_delivery_rejected",
      resource: "webhook_subscription",
      resourceId: "sub-mtls",
      metadata: {
        reason: "MTLS_CERT_EXPIRED",
        validTo: "2024-06-01T00:00:00.000Z",
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(createDeliveryReceipt).not.toHaveBeenCalled();
  });

  it("delivers with an mTLS agent when the certificate is valid", async () => {
    mockSecrets(VALID_CERT_PEM, VALID_KEY_PEM);

    const result = await sendWebhookDelivery({
      subscription: mtlsSubscription(),
      payload: PAYLOAD,
    });

    expect(secretLoader.get).toHaveBeenCalledTimes(3);
    expect(secretLoader.get).toHaveBeenCalledWith("cert-secret");
    expect(secretLoader.get).toHaveBeenCalledWith("key-secret");
    expect(secretLoader.get).toHaveBeenCalledWith("ca-secret");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const agent = init.agent as https.Agent;
    expect(agent).toBeInstanceOf(https.Agent);
    expect(agent.options.cert).toBe(VALID_CERT_PEM);
    expect(agent.options.key).toBe(VALID_KEY_PEM);
    expect(agent.options.ca).toBe("pinned-ca-bytes");
    expect(agent.options.rejectUnauthorized).toBe(true);
    expect(agent.options.keepAlive).toBe(true);

    expect(result.statusCode).toBe(200);
  });

  it("does not load mTLS secrets for subscriptions without mtlsConfig", async () => {
    await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(secretLoader.get).not.toHaveBeenCalled();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.agent).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// verifyWebhookSignature
// ---------------------------------------------------------------------------

describe("verifyWebhookSignature", () => {
  const payloadBody = JSON.stringify(PAYLOAD);

  /** Build a full, correctly-signed header set for the given timestamp. */
  function signedHeaders(
    timestampSeconds: number,
    secret = SECRET,
    deliveryId = "11111111-2222-3333-4444-555555555555"
  ): Record<string, string> {
    const timestamp = String(timestampSeconds);
    const signature = expectedSignature(deliveryId, 1, timestamp, payloadBody, secret);
    return {
      "X-Veritasor-Delivery-Id": deliveryId,
      "X-Veritasor-Attempt": "1",
      "X-Veritasor-Timestamp": timestamp,
      "X-Veritasor-Signature": signature,
    };
  }

  function nowSeconds(offsetSeconds = 0): number {
    return Math.floor(Date.now() / 1000) + offsetSeconds;
  }

  it("accepts a correctly signed, fresh delivery", () => {
    const valid = verifyWebhookSignature({
      payload: payloadBody,
      headers: signedHeaders(nowSeconds()),
      secret: SECRET,
    });
    expect(valid).toBe(true);
  });

  it("accepts a delivery at the exact tolerance boundary (300s old)", () => {
    const valid = verifyWebhookSignature({
      payload: payloadBody,
      headers: signedHeaders(nowSeconds(-300)),
      secret: SECRET,
    });
    expect(valid).toBe(true);
    expect(staleWebhookDeliveries.inc).not.toHaveBeenCalled();
  });

  it("rejects a replay outside the default 5-minute tolerance and bumps the metric", () => {
    const valid = verifyWebhookSignature({
      payload: payloadBody,
      headers: signedHeaders(nowSeconds(-301)),
      secret: SECRET,
    });
    expect(valid).toBe(false);
    expect(staleWebhookDeliveries.inc).toHaveBeenCalledOnce();
  });

  it("honours a custom toleranceMs", () => {
    const headers = signedHeaders(nowSeconds(-400));
    expect(
      verifyWebhookSignature({
        payload: payloadBody,
        headers,
        secret: SECRET,
        toleranceMs: 10 * 60 * 1000, // 10 min: -400s is fresh
      })
    ).toBe(true);
    expect(
      verifyWebhookSignature({
        payload: payloadBody,
        headers,
        secret: SECRET,
        toleranceMs: 60 * 1000, // 1 min: -400s is stale
      })
    ).toBe(false);
  });

  it("rejects when any required header is missing", () => {
    for (const missing of [
      "X-Veritasor-Delivery-Id",
      "X-Veritasor-Attempt",
      "X-Veritasor-Timestamp",
      "X-Veritasor-Signature",
    ]) {
      const headers = signedHeaders(nowSeconds());
      delete headers[missing];
      expect(
        verifyWebhookSignature({ payload: payloadBody, headers, secret: SECRET })
      ).toBe(false);
    }
    expect(staleWebhookDeliveries.inc).not.toHaveBeenCalled();
  });

  it("rejects a non-numeric timestamp", () => {
    const headers = signedHeaders(nowSeconds());
    headers["X-Veritasor-Timestamp"] = "not-a-number";

    expect(
      verifyWebhookSignature({ payload: payloadBody, headers, secret: SECRET })
    ).toBe(false);
  });

  it("rejects a signature produced with the wrong secret", () => {
    const headers = signedHeaders(nowSeconds(), "attacker-secret");
    expect(
      verifyWebhookSignature({ payload: payloadBody, headers, secret: SECRET })
    ).toBe(false);
  });

  it("rejects a tampered payload (signature covers the raw body)", () => {
    const headers = signedHeaders(nowSeconds());
    const tampered = JSON.stringify({ ...PAYLOAD, data: { id: 8 } });
    expect(
      verifyWebhookSignature({ payload: tampered, headers, secret: SECRET })
    ).toBe(false);
  });

  it("rejects a truncated or malformed signature", () => {
    const headers = signedHeaders(nowSeconds());
    headers["X-Veritasor-Signature"] = "deadbeef";

    expect(
      verifyWebhookSignature({ payload: payloadBody, headers, secret: SECRET })
    ).toBe(false);
  });

  it("reads the first value when headers are arrays (express-style)", () => {
    const headers = signedHeaders(nowSeconds());
    const arrayHeaders: Record<string, string | string[]> = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k, [v, "ignore-me"]])
    );

    expect(
      verifyWebhookSignature({
        payload: payloadBody,
        headers: arrayHeaders,
        secret: SECRET,
      })
    ).toBe(true);
  });

  it("matches lower-cased header names", () => {
    const headers = signedHeaders(nowSeconds());
    const lowerCased = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
    );

    expect(
      verifyWebhookSignature({
        payload: payloadBody,
        headers: lowerCased,
        secret: SECRET,
      })
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// sendWebhookDelivery — delivery result contract and failure paths
// ---------------------------------------------------------------------------

describe("sendWebhookDelivery", () => {
  it("returns the full result contract on a successful delivery", async () => {
    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(result.deliveryId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
    expect(result.attempt).toBe(1);
    expect(result.statusCode).toBe(200);
    expect(typeof result.latencyMs).toBe("number");
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    expect(result.signature).toMatch(/^[a-f0-9]{64}$/);
    expect(result.signatureVersion).toBe(1);
    expect(result.responseBody).toBe("OK");
  });

  it("posts the signed headers and JSON body to the subscription URL", async () => {
    await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];

    expect(url).toBe("https://example.com/hook");
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify(PAYLOAD));

    const headers = init.headers as Record<string, string>;
    expect(headers["X-Veritasor-Delivery-Id"]).toBeDefined();
    expect(headers["X-Veritasor-Attempt"]).toBe("1");
    expect(headers["X-Veritasor-Timestamp"]).toMatch(/^\d+$/);
    expect(headers["X-Veritasor-Signature"]).toMatch(/^[a-f0-9]{64}$/);
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("sends a verifiable signature matching the receipt", async () => {
    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;

    const expected = expectedSignature(
      headers["X-Veritasor-Delivery-Id"],
      1,
      headers["X-Veritasor-Timestamp"],
      JSON.stringify(PAYLOAD)
    );
    expect(result.signature).toBe(expected);
    expect(headers["X-Veritasor-Signature"]).toBe(expected);

    // And it round-trips through the verifier
    expect(
      verifyWebhookSignature({
        payload: JSON.stringify(PAYLOAD),
        headers,
        secret: SECRET,
      })
    ).toBe(true);
  });

  it("forwards the attempt number into headers, receipt and result", async () => {
    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
      attempt: 4,
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["X-Veritasor-Attempt"]).toBe("4");
    expect(result.attempt).toBe(4);
  });

  it("persists a delivery receipt with the delivery outcome", async () => {
    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(createDeliveryReceipt).toHaveBeenCalledExactlyOnceWith({
      deliveryId: result.deliveryId,
      attemptNumber: 1,
      subscriptionId: "sub-1",
      businessId: "biz-1",
      url: "https://example.com/hook",
      statusCode: 200,
      latencyMs: expect.any(Number),
      signatureVersion: 1,
      signature: result.signature,
      responseBody: "OK",
    });
  });

  it("records non-2xx HTTP statuses without throwing", async () => {
    mockFetchOk(500, "upstream exploded");

    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(result.statusCode).toBe(500);
    expect(result.responseBody).toBe("upstream exploded");
    expect(createDeliveryReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 500 })
    );
  });

  it("maps network failures to statusCode 0 with the error message", async () => {
    fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));

    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(result.statusCode).toBe(0);
    expect(result.responseBody).toBe("ECONNREFUSED");
    expect(createDeliveryReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 0, responseBody: "ECONNREFUSED" })
    );
  });

  it("uses a generic message for non-Error network rejections", async () => {
    fetchMock.mockRejectedValue("just a string");

    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(result.statusCode).toBe(0);
    expect(result.responseBody).toBe("Unknown networking error");
  });

  it("truncates large response bodies to 2048 characters", async () => {
    mockFetchOk(200, "x".repeat(3000));

    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(result.responseBody).toHaveLength(2048);
    expect(createDeliveryReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ responseBody: expect.any(String) })
    );
  });

  it("keeps response bodies of exactly 2048 characters intact", async () => {
    mockFetchOk(200, "y".repeat(2048));

    const result = await sendWebhookDelivery({
      subscription: makeSubscription(),
      payload: PAYLOAD,
    });

    expect(result.responseBody).toHaveLength(2048);
  });

  it("propagates WebhookPayloadTooLargeError without fetching or persisting", async () => {
    const sub = makeSubscription({ maxPayloadSize: 8 });

    await expect(
      sendWebhookDelivery({ subscription: sub, payload: PAYLOAD })
    ).rejects.toMatchObject({
      name: "WebhookPayloadTooLargeError",
      code: "PAYLOAD_TOO_LARGE",
      statusCode: 413,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(createDeliveryReceipt).not.toHaveBeenCalled();
  });
});
