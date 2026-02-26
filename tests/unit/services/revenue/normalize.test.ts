import { describe, it, expect } from "vitest";
import { normalizeRevenueEntry } from "../../../../src/services/revenue/normalize.js";

describe("revenue normalizer", () => {
  it("should produce the canonical shape", () => {
    const result = normalizeRevenueEntry({
      id: "txn_001",
      amount: 49.99,
      currency: "usd",
      date: "2025-11-15T10:30:00Z",
      source: "stripe",
    });

    expect(result).toEqual({
      id: "txn_001",
      amount: 49.99,
      currency: "USD",
      date: "2025-11-15T10:30:00.000Z",
      type: "payment",
      source: "stripe",
    });
  });

  it("should classify negative amounts as refund", () => {
    const result = normalizeRevenueEntry({
      id: "txn_002",
      amount: -20.0,
      currency: "EUR",
      date: "2025-12-01T00:00:00Z",
      source: "razorpay",
    });

    expect(result.type).toBe("refund");
    expect(result.amount).toBe(-20.0);
  });

  it("should classify positive amounts as payment", () => {
    const result = normalizeRevenueEntry({
      id: "txn_003",
      amount: 100,
      currency: "INR",
      date: "2025-06-01",
      source: "razorpay",
    });

    expect(result.type).toBe("payment");
  });

  it("should normalize currency to uppercase", () => {
    const result = normalizeRevenueEntry({
      id: "txn_004",
      amount: 10,
      currency: "gbp",
      date: "2025-01-01",
    });

    expect(result.currency).toBe("GBP");
  });

  it("should default currency to USD when missing", () => {
    const result = normalizeRevenueEntry({
      id: "txn_005",
      amount: 5,
      date: "2025-01-01",
    });

    expect(result.currency).toBe("USD");
  });

  it("should convert numeric date (Unix timestamp) to ISO string", () => {
    // 1700000000 = 2023-11-14T22:13:20.000Z
    const result = normalizeRevenueEntry({
      id: "txn_006",
      amount: 30,
      currency: "USD",
      date: 1700000000,
      source: "manual",
    });

    expect(result.date).toBe("2023-11-14T22:13:20.000Z");
  });

  it("should parse a string date into ISO format", () => {
    const result = normalizeRevenueEntry({
      id: "txn_007",
      amount: 15,
      currency: "USD",
      date: "2025-03-20",
      source: "stripe",
    });

    // Should be a valid ISO date string
    expect(result.date).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(new Date(result.date).toISOString()).toBe(result.date);
  });

  it("should default source to unknown when missing", () => {
    const result = normalizeRevenueEntry({
      id: "txn_008",
      amount: 25,
      date: "2025-01-01",
    });

    expect(result.source).toBe("unknown");
  });

  it("should handle zero amount as payment", () => {
    const result = normalizeRevenueEntry({
      id: "txn_009",
      amount: 0,
      currency: "USD",
      date: "2025-01-01",
      source: "test",
    });

    expect(result.type).toBe("payment");
    expect(result.amount).toBe(0);
  });
});
