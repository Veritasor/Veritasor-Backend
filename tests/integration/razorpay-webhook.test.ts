import crypto from "node:crypto";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "../../src/app.js";
import { resetProcessedRazorpayEvents } from "../../src/services/webhooks/razorpayHandler.js";
import { secretLoader } from "../../src/utils/secret-loader.js";

const WEBHOOK_PATH = "/api/webhooks/razorpay";
const WEBHOOK_SECRET = "test_webhook_secret";

function sign(rawBody: Buffer, secret = WEBHOOK_SECRET): string {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function rawEventBody(id = "evt_test_razorpay_webhook", event = "payment.captured"): Buffer {
  return Buffer.from(
    JSON.stringify({
      id,
      event,
      created_at: Math.floor(Date.now() / 1000),
      payload: {
        payment: {
          entity: {
            id: "pay_test_456",
            order_id: "order_test_789",
            status: "captured",
            amount: 1000,
            currency: "INR",
          },
        },
      },
    }),
  );
}

function sendRawJson(requestBuilder: request.Test, body: Buffer): request.Test {
  return requestBuilder
    .set("Content-Type", "application/json")
    .send(body.toString("utf8"));
}

describe("Razorpay webhook integration", () => {
  const originalSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

  beforeEach(() => {
    resetProcessedRazorpayEvents();
    process.env.RAZORPAY_WEBHOOK_SECRET = WEBHOOK_SECRET;
  });

  afterEach(() => {
    resetProcessedRazorpayEvents();
    vi.doUnmock("../../src/services/webhooks/razorpayHandler.js");

    if (originalSecret === undefined) {
      delete process.env.RAZORPAY_WEBHOOK_SECRET;
    } else {
      process.env.RAZORPAY_WEBHOOK_SECRET = originalSecret;
    }
  });

  it("accepts a valid signed raw JSON body and returns the handler result", async () => {
    const body = rawEventBody("evt_valid_signed_raw_body");

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body).toEqual({
      status: "ok",
      message: "Payment pay_test_456 captured successfully",
    });
  });

  it("uses an updated webhook secret after reload", async () => {
    process.env.RAZORPAY_WEBHOOK_SECRET = WEBHOOK_SECRET;
    await secretLoader.reload();

    const firstBody = rawEventBody("evt_reload_before");
    await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(firstBody))
      .use((req) => sendRawJson(req, firstBody))
      .expect(200);

    const newSecret = "updated_webhook_secret"
    process.env.RAZORPAY_WEBHOOK_SECRET = newSecret;
    await secretLoader.reload();

    const secondBody = rawEventBody("evt_reload_after");
    await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(secondBody, newSecret))
      .use((req) => sendRawJson(req, secondBody))
      .expect(200);

    await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(secondBody, WEBHOOK_SECRET))
      .use((req) => sendRawJson(req, secondBody))
      .expect(401);
  });

  it("rejects a tampered raw body signed for different bytes", async () => {
    const originalBody = rawEventBody("evt_tampered_original_body");
    const tamperedBody = Buffer.from(
      originalBody.toString("utf8").replace("pay_test_456", "pay_test_999"),
    );

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(originalBody))
      .use((req) => sendRawJson(req, tamperedBody))
      .expect(401);

    expect(response.body).toMatchObject({
      code: "invalid_signature",
      error: "Invalid signature",
    });
  });

  it("accepts a valid payment.failed event", async () => {
    const body = rawEventBody("evt_valid_payment_failed", "payment.failed");

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body).toEqual({
      status: "ok",
      message: "Payment pay_test_456 failed",
    });
  });

  it("accepts a valid order.paid event", async () => {
    const body = rawEventBody("evt_valid_order_paid", "order.paid");

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body).toEqual({
      status: "ok",
      message: "Order order_test_789 marked as paid",
    });
  });

  it("ignores signed events outside the handled Razorpay set", async () => {
    const body = rawEventBody("evt_unhandled_event_type", "refund.created");

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body).toEqual({
      status: "ignored",
      message: "Unhandled event type: refund.created",
    });
  });

  it("rejects requests when the webhook secret is not configured", async () => {
    delete process.env.RAZORPAY_WEBHOOK_SECRET;
    const body = rawEventBody("evt_secret_not_configured");

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(500);

    expect(response.body).toMatchObject({
      code: "secret_not_configured",
      error: "Webhook secret not configured",
    });
  });

  it("rejects a missing signature header before processing the body", async () => {
    const response = await request(app)
      .post(WEBHOOK_PATH)
      .use((req) => sendRawJson(req, rawEventBody("evt_missing_signature")))
      .expect(400);

    expect(response.body).toMatchObject({
      code: "missing_signature",
      error: "Missing Razorpay signature header",
    });
  });

  it("rejects an empty raw body even when the signature header is present", async () => {
    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(Buffer.alloc(0)))
      .use((req) => sendRawJson(req, Buffer.alloc(0)))
      .expect(400);

    expect(response.body).toMatchObject({
      code: "invalid_payload",
      error: "Invalid webhook payload",
    });
  });

  it("rejects signed malformed JSON after signature verification", async () => {
    const body = Buffer.from('{"id":"evt_malformed","event":"payment.captured",');

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(400);

    expect(response.body).toMatchObject({
      code: "invalid_payload",
      error: "Invalid webhook payload",
    });
  });

  it("rejects signed handled events with an invalid schema", async () => {
    const body = Buffer.from(
      JSON.stringify({
        id: "evt_invalid_schema",
        event: "payment.captured",
        payload: {},
      }),
    );

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(400);

    expect(response.body).toMatchObject({
      code: "invalid_event",
      error: "Invalid event structure",
    });
  });

  it("rejects signed events with timestamps beyond the future skew", async () => {
    const body = Buffer.from(
      JSON.stringify({
        id: "evt_future_timestamp",
        event: "payment.captured",
        created_at: Math.floor((Date.now() + 10 * 60 * 1000) / 1000),
        payload: {
          payment: {
            entity: {
              id: "pay_test_456",
              order_id: "order_test_789",
              status: "captured",
              amount: 1000,
              currency: "INR",
            },
          },
        },
      }),
    );

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(400);

    expect(response.body).toMatchObject({
      code: "invalid_timestamp",
      error: "Invalid webhook timestamp",
    });
  });

  it("handles replayed events idempotently without reprocessing", async () => {
    const body = rawEventBody("evt_replayed_signed_raw_body");
    const signature = sign(body);

    await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", signature)
      .use((req) => sendRawJson(req, body))
      .expect(200);

    const replay = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", signature)
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(replay.body).toEqual({
      status: "duplicate",
      message: "Event evt_replayed_signed_raw_body already processed",
    });
  });

  it("returns a generic 500 when verified processing fails unexpectedly", async () => {
    vi.resetModules();
    vi.doMock("../../src/services/webhooks/razorpayHandler.js", async (importOriginal) => {
      const actual =
        await importOriginal<typeof import("../../src/services/webhooks/razorpayHandler.js")>();

      return {
        ...actual,
        verifyRazorpaySignature: () => true,
        parseRazorpayEvent: () => ({
          id: "evt_unexpected_handler_failure",
          event: "payment.captured",
          payload: {
            payment: {
              entity: {
                id: "pay_test_456",
                order_id: "order_test_789",
                status: "captured",
                amount: 1000,
                currency: "INR",
              },
            },
          },
        }),
        handleRazorpayEvent: () => {
          throw new Error("database unavailable");
        },
      };
    });

    const [{ default: express }, { razorpayWebhookRouter }] = await Promise.all([
      import("express"),
      import("../../src/routes/webhooks-razorpay.js"),
    ]);
    const isolatedApp = express();
    const body = rawEventBody("evt_unexpected_handler_failure");

    isolatedApp.use(WEBHOOK_PATH, razorpayWebhookRouter);

    const response = await request(isolatedApp)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sign(body))
      .use((req) => sendRawJson(req, body))
      .expect(500);

    expect(response.body).toEqual({ error: "Internal Server Error" });

    vi.doUnmock("../../src/services/webhooks/razorpayHandler.js");
    vi.resetModules();
  });
});

// ─── Secret rotation tests ────────────────────────────────────────────────────

describe("Razorpay webhook — secret rotation", () => {
  const PRIMARY_SECRET = "primary_webhook_secret";
  const SECONDARY_SECRET = "secondary_webhook_secret";

  const originalPrimary = process.env.RAZORPAY_WEBHOOK_SECRET;
  const originalSecondary = process.env.RAZORPAY_WEBHOOK_SECRET_NEXT;

  beforeEach(() => {
    resetProcessedRazorpayEvents();
  });

  afterEach(() => {
    resetProcessedRazorpayEvents();

    if (originalPrimary === undefined) {
      delete process.env.RAZORPAY_WEBHOOK_SECRET;
    } else {
      process.env.RAZORPAY_WEBHOOK_SECRET = originalPrimary;
    }

    if (originalSecondary === undefined) {
      delete process.env.RAZORPAY_WEBHOOK_SECRET_NEXT;
    } else {
      process.env.RAZORPAY_WEBHOOK_SECRET_NEXT = originalSecondary;
    }
  });

  // ── only primary set ────────────────────────────────────────────────────────

  it("accepts a request signed with the primary secret when no secondary is set", async () => {
    process.env.RAZORPAY_WEBHOOK_SECRET = PRIMARY_SECRET;
    delete process.env.RAZORPAY_WEBHOOK_SECRET_NEXT;

    const body = rawEventBody("evt_rotation_primary_only");
    const sig = sign(body, PRIMARY_SECRET);

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sig)
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body.status).toBe("ok");
  });

  it("rejects a request signed with an unknown secret when only primary is set", async () => {
    process.env.RAZORPAY_WEBHOOK_SECRET = PRIMARY_SECRET;
    delete process.env.RAZORPAY_WEBHOOK_SECRET_NEXT;

    const body = rawEventBody("evt_rotation_primary_only_bad_sig");
    const sig = sign(body, "completely_wrong_secret");

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sig)
      .use((req) => sendRawJson(req, body))
      .expect(401);

    expect(response.body).toMatchObject({ code: "invalid_signature" });
  });

  // ── both set, primary wins ──────────────────────────────────────────────────

  it("accepts a request signed with the primary secret when both secrets are set", async () => {
    process.env.RAZORPAY_WEBHOOK_SECRET = PRIMARY_SECRET;
    process.env.RAZORPAY_WEBHOOK_SECRET_NEXT = SECONDARY_SECRET;

    const body = rawEventBody("evt_rotation_both_primary_wins");
    const sig = sign(body, PRIMARY_SECRET);

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sig)
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body.status).toBe("ok");
  });

  // ── both set, secondary wins ────────────────────────────────────────────────

  it("accepts a request signed with the secondary secret when both secrets are set", async () => {
    process.env.RAZORPAY_WEBHOOK_SECRET = PRIMARY_SECRET;
    process.env.RAZORPAY_WEBHOOK_SECRET_NEXT = SECONDARY_SECRET;

    const body = rawEventBody("evt_rotation_both_secondary_wins");
    const sig = sign(body, SECONDARY_SECRET);

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sig)
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body.status).toBe("ok");
  });

  // ── neither matches ─────────────────────────────────────────────────────────

  it("rejects a request when the signature matches neither primary nor secondary", async () => {
    process.env.RAZORPAY_WEBHOOK_SECRET = PRIMARY_SECRET;
    process.env.RAZORPAY_WEBHOOK_SECRET_NEXT = SECONDARY_SECRET;

    const body = rawEventBody("evt_rotation_neither_matches");
    const sig = sign(body, "completely_wrong_secret");

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sig)
      .use((req) => sendRawJson(req, body))
      .expect(401);

    expect(response.body).toMatchObject({ code: "invalid_signature" });
  });

  // ── post-rotation: secondary promoted to primary ────────────────────────────

  it("accepts a request after rotation completes (secondary promoted, old primary removed)", async () => {
    // Simulate the final rotation step: NEXT becomes the only secret
    process.env.RAZORPAY_WEBHOOK_SECRET = SECONDARY_SECRET;
    delete process.env.RAZORPAY_WEBHOOK_SECRET_NEXT;

    const body = rawEventBody("evt_rotation_post_rotation");
    const sig = sign(body, SECONDARY_SECRET);

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sig)
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body.status).toBe("ok");
  });

  // ── empty string secondary is treated as absent ─────────────────────────────

  it("treats an empty RAZORPAY_WEBHOOK_SECRET_NEXT as if it were unset", async () => {
    process.env.RAZORPAY_WEBHOOK_SECRET = PRIMARY_SECRET;
    process.env.RAZORPAY_WEBHOOK_SECRET_NEXT = "";

    const body = rawEventBody("evt_rotation_empty_secondary");
    const sig = sign(body, PRIMARY_SECRET);

    const response = await request(app)
      .post(WEBHOOK_PATH)
      .set("x-razorpay-signature", sig)
      .use((req) => sendRawJson(req, body))
      .expect(200);

    expect(response.body.status).toBe("ok");
  });
});
