import { beforeEach, describe, expect, it, vi } from "vitest";

const { query } = vi.hoisted(() => ({ query: vi.fn() }));

vi.mock("../db/client.js", () => ({
  db: { query },
}));

import {
  createDeliveryReceipt,
  getDeliveryReceiptsByDeliveryId,
  queryDeliveryReceipts,
} from "./deliveryReceiptRepository.js";
import type {
  CreateDeliveryReceiptInput,
  DeliveryReceipt,
  DeliveryReceiptQuery,
} from "./deliveryReceiptRepository.js";

const input: CreateDeliveryReceiptInput = {
  deliveryId: "delivery-1",
  attemptNumber: 2,
  subscriptionId: "subscription-1",
  businessId: "business-1",
  url: "https://example.com/webhook",
  statusCode: 503,
  latencyMs: 125,
  signatureVersion: 1,
  signature: "signature-value",
  responseBody: "temporarily unavailable",
};

function row(overrides: Record<string, unknown> = {}) {
  return {
    id: "receipt-1",
    delivery_id: "delivery-1",
    attempt_number: 2,
    subscription_id: "subscription-1",
    business_id: "business-1",
    url: "https://example.com/webhook",
    status_code: 503,
    latency_ms: 125,
    signature_version: 1,
    signature: "signature-value",
    response_body: "temporarily unavailable",
    created_at: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function expectedReceipt(overrides: Partial<DeliveryReceipt> = {}): DeliveryReceipt {
  return {
    id: "receipt-1",
    deliveryId: "delivery-1",
    attemptNumber: 2,
    subscriptionId: "subscription-1",
    businessId: "business-1",
    url: "https://example.com/webhook",
    statusCode: 503,
    latencyMs: 125,
    signatureVersion: 1,
    signature: "signature-value",
    responseBody: "temporarily unavailable",
    createdAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

beforeEach(() => {
  query.mockReset();
});

describe("delivery receipt repository", () => {
  it("creates and maps a DeliveryReceipt from a CreateDeliveryReceiptInput", async () => {
    query.mockResolvedValueOnce({ rows: [row()] });

    await expect(createDeliveryReceipt(input)).resolves.toEqual(expectedReceipt());

    const [sql, params] = query.mock.calls[0];
    expect(String(sql)).toContain("INSERT INTO delivery_receipts");
    expect(String(sql)).toContain("RETURNING *");
    expect(params).toEqual([
      input.deliveryId,
      input.attemptNumber,
      input.subscriptionId,
      input.businessId,
      input.url,
      input.statusCode,
      input.latencyMs,
      input.signatureVersion,
      input.signature,
      input.responseBody,
    ]);
  });

  it("stores an omitted response body as null and maps a null body to undefined", async () => {
    const { responseBody: _responseBody, ...inputWithoutBody } = input;
    query.mockResolvedValueOnce({ rows: [row({ response_body: null })] });

    await expect(createDeliveryReceipt(inputWithoutBody)).resolves.toEqual(
      expectedReceipt({ responseBody: undefined }),
    );
    expect(query.mock.calls[0][1]).toEqual([
      input.deliveryId,
      input.attemptNumber,
      input.subscriptionId,
      input.businessId,
      input.url,
      input.statusCode,
      input.latencyMs,
      input.signatureVersion,
      input.signature,
      null,
    ]);
  });

  it("propagates database failures when creating a receipt", async () => {
    const failure = new Error("database unavailable");
    query.mockRejectedValueOnce(failure);

    await expect(createDeliveryReceipt(input)).rejects.toBe(failure);
  });

  it("combines DeliveryReceiptQuery filters and returns the next page cursor", async () => {
    const filters: DeliveryReceiptQuery = {
      businessId: "business-1",
      deliveryId: "delivery-1",
      subscriptionId: "subscription-1",
      limit: 2,
    };
    query.mockResolvedValueOnce({
      rows: [row(), row({ id: "receipt-2", attempt_number: 3 })],
    });

    await expect(queryDeliveryReceipts(filters)).resolves.toEqual({
      data: [expectedReceipt(), expectedReceipt({ id: "receipt-2", attemptNumber: 3 })],
      nextCursor: "receipt-2",
    });

    const [sql, params] = query.mock.calls[0];
    expect(String(sql)).toContain(
      "WHERE business_id = $1 AND delivery_id = $2 AND subscription_id = $3",
    );
    expect(String(sql)).toContain("ORDER BY created_at DESC LIMIT $4");
    expect(params).toEqual(["business-1", "delivery-1", "subscription-1", 2]);
  });

  it("ignores empty filters and applies the default limit", async () => {
    const filters: DeliveryReceiptQuery = {
      businessId: "",
      deliveryId: "",
      subscriptionId: "",
    };
    query.mockResolvedValueOnce({ rows: [] });

    await expect(queryDeliveryReceipts(filters)).resolves.toEqual({ data: [], nextCursor: undefined });

    const [sql, params] = query.mock.calls[0];
    expect(String(sql)).not.toContain("WHERE");
    expect(params).toEqual([50]);
  });

  it("caps the page size at 100 and reports no cursor for a partial page", async () => {
    query.mockResolvedValueOnce({ rows: [row()] });

    await expect(queryDeliveryReceipts({ limit: 500 })).resolves.toEqual({
      data: [expectedReceipt()],
      nextCursor: undefined,
    });
    expect(query.mock.calls[0][1]).toEqual([100]);
  });

  it("returns an empty page without a cursor when the limit is zero", async () => {
    query.mockResolvedValueOnce({ rows: [] });

    await expect(queryDeliveryReceipts({ limit: 0 })).resolves.toEqual({ data: [], nextCursor: undefined });
    expect(query.mock.calls[0][1]).toEqual([0]);
  });

  it("propagates a database rejection for a negative limit", async () => {
    const failure = new Error("LIMIT must not be negative");
    query.mockRejectedValueOnce(failure);

    await expect(queryDeliveryReceipts({ limit: -1 })).rejects.toBe(failure);
    expect(query.mock.calls[0][1]).toEqual([-1]);
  });

  it("loads receipts for one delivery in ascending attempt order", async () => {
    query.mockResolvedValueOnce({
      rows: [row({ id: "receipt-1", attempt_number: 1 }), row({ id: "receipt-2", attempt_number: 2 })],
    });

    await expect(getDeliveryReceiptsByDeliveryId("delivery-1")).resolves.toEqual([
      expectedReceipt({ id: "receipt-1", attemptNumber: 1 }),
      expectedReceipt({ id: "receipt-2", attemptNumber: 2 }),
    ]);
    expect(String(query.mock.calls[0][0])).toContain(
      "WHERE delivery_id = $1 ORDER BY attempt_number ASC",
    );
    expect(query.mock.calls[0][1]).toEqual(["delivery-1"]);
  });

  it("returns an empty history when a delivery has no receipts", async () => {
    query.mockResolvedValueOnce({ rows: [] });

    await expect(getDeliveryReceiptsByDeliveryId("missing-delivery")).resolves.toEqual([]);
  });
});