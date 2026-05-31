import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the pool so checkDatabase never touches a real DB
const mockQuery = vi.fn();
vi.mock("../../../src/db/client.js", () => ({
  pool: { query: mockQuery },
}));

// Import after mocks are set up
const { checkDatabase, sanitiseDbError } = await import(
  "../../../src/startup/readiness.js"
);

describe("checkDatabase", () => {
  beforeEach(() => {
    mockQuery.mockReset();
  });

  it("returns ready:true when pool.query resolves", async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ "?column?": 1 }] });
    const result = await checkDatabase();
    expect(result).toEqual({ dependency: "database", ready: true });
    expect(mockQuery).toHaveBeenCalledWith("SELECT 1");
  });

  it("returns ready:false with connection error reason on pool error", async () => {
    mockQuery.mockRejectedValueOnce(new Error("ECONNREFUSED 127.0.0.1:5432"));
    const result = await checkDatabase();
    expect(result.ready).toBe(false);
    expect(result.dependency).toBe("database");
    expect(result.reason).toMatch(/database connection failed/);
  });

  it("returns ready:false with timeout reason when query times out", async () => {
    // Simulate a query that never resolves so the internal timeout fires.
    // We override the timeout constant by making the query hang and relying
    // on the real withTimeout — but that would be slow. Instead, reject with
    // Error("timeout") to exercise the timeout branch directly.
    mockQuery.mockRejectedValueOnce(new Error("timeout"));
    const result = await checkDatabase();
    expect(result.ready).toBe(false);
    expect(result.reason).toMatch(/timed out after/);
  });

  it("sanitises connection string from error message", async () => {
    mockQuery.mockRejectedValueOnce(
      new Error("connect ECONNREFUSED postgresql://user:secret@host:5432/db"),
    );
    const result = await checkDatabase();
    expect(result.reason).not.toMatch(/secret/);
    expect(result.reason).toMatch(/\[redacted\]/);
  });
});

describe("sanitiseDbError", () => {
  it("redacts postgres:// URLs", () => {
    expect(sanitiseDbError("failed: postgres://user:pass@host/db")).toBe(
      "failed: [redacted]",
    );
  });

  it("redacts postgresql:// URLs", () => {
    expect(
      sanitiseDbError("error postgresql://user:pass@host:5432/db more"),
    ).toBe("error [redacted] more");
  });

  it("leaves messages without connection strings unchanged", () => {
    expect(sanitiseDbError("ECONNREFUSED 127.0.0.1:5432")).toBe(
      "ECONNREFUSED 127.0.0.1:5432",
    );
  });
});
