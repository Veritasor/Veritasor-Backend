import { describe, it, expect } from "vitest";
import {
  getPagination,
  formatPaginatedResponse,
  encodeCursor,
  decodeCursor,
} from "../../../src/utils/pagination";

describe("getPagination", () => {
  it("returns default limit of 20 when no input is given", () => {
    const result = getPagination({});
    expect(result.limit).toBe(20);
  });

  it("parses numeric string inputs", () => {
    const result = getPagination({ page: "3", limit: "10" });
    expect(result.limit).toBe(10);
    expect(result.page).toBe(3);
  });

  it("clamps page=0 to the first page", () => {
    const result = getPagination({ page: "0" });
    expect(result.page).toBeGreaterThanOrEqual(1);
  });

  it("clamps negative pages to the first page", () => {
    const result = getPagination({ page: "-5" });
    expect(result.page).toBeGreaterThanOrEqual(1);
  });

  it("falls back to defaults for NaN and non-numeric values", () => {
    const result = getPagination({ page: "abc", limit: "NaN" });
    expect(Number.isNaN(result.page)).toBe(false);
    expect(Number.isNaN(result.limit)).toBe(false);
    expect(result.limit).toBe(20);
  });

  it("clamps limit above 100 down to 100", () => {
    const result = getPagination({ limit: "500" });
    expect(result.limit).toBe(100);
  });

  it("clamps limit below 1 up to 1", () => {
    const result = getPagination({ limit: "0" });
    expect(result.limit).toBe(1);
    const negative = getPagination({ limit: "-10" });
    expect(negative.limit).toBe(1);
  });
});

describe("formatPaginatedResponse", () => {
  it("handles limit = 0 without dividing by zero", () => {
    const result = formatPaginatedResponse([], 0, 1, 0);
    expect(Number.isFinite(result.totalPages as number)).toBe(true);
  });

  it("handles total 0 with zero items", () => {
    const result = formatPaginatedResponse([], 0, 1, 20);
    expect(result.data).toEqual([]);
    expect(result.total).toBe(0);
  });
});

describe("cursor helpers", () => {
  it("round-trips a cursor payload", () => {
    const payload = { id: "abc-123", createdAt: "2024-01-01T00:00:00.000Z" };
    const encoded = encodeCursor(payload);
    expect(typeof encoded).toBe("string");
    expect(decodeCursor(encoded)).toEqual(payload);
  });

  it("returns null for malformed base64", () => {
    expect(decodeCursor("%%%not-base64%%%")).toBeNull();
  });

  it("returns null when decoded JSON is not an object", () => {
    const encoded = Buffer.from(JSON.stringify("just a string")).toString("base64");
    expect(decodeCursor(encoded)).toBeNull();
  });

  it("returns null when fields have the wrong types", () => {
    const encoded = Buffer.from(JSON.stringify({ id: 42, createdAt: 99 })).toString("base64");
    expect(decodeCursor(encoded)).toBeNull();
  });

  it("returns null for an empty string cursor", () => {
    expect(decodeCursor("")).toBeNull();
  });

  it("returns null for a null cursor", () => {
    expect(decodeCursor(null as unknown as string)).toBeNull();
  });
});
