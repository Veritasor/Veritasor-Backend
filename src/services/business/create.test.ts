import { describe, it, expect, vi, beforeEach } from "vitest";
import { Request, Response } from "express";
import { createBusiness } from "./create.js";
import { businessRepository, type Business } from "../../repositories/business.js";
import { AppError } from "../../types/errors.js";

vi.mock("../../repositories/business.js", () => ({
  businessRepository: {
    getByUserId: vi.fn(),
    create: vi.fn(),
    clearAll: vi.fn(),
  },
}));

type MockRequest = Partial<Request> & {
  user?: { id: string; email?: string };
  body: Record<string, unknown>;
};

type MockStatusFn = ((code: number) => MockResponse) & {
  mock: { calls: unknown[][]; results: unknown[] };
};

type MockJsonFn = ((body: unknown) => MockResponse) & {
  mock: { calls: unknown[][]; results: unknown[] };
};

type MockResponse = Partial<Response> & {
  statusCode?: number;
  jsonResponse?: unknown;
  status: MockStatusFn;
  json: MockJsonFn;
};

function makeReq(overrides: Partial<MockRequest> = {}): MockRequest {
  return {
    user: { id: "user-uuid-0000", email: "user@example.com" },
    body: { name: "Acme Corp" },
    ...overrides,
  } as MockRequest;
}

function makeRes(): MockResponse {
  const statusFn = function (this: MockResponse, code: number) {
    this.statusCode = code;
    return this;
  } as MockStatusFn;
  statusFn.mock = { calls: [], results: [] };

  const jsonFn = function (this: MockResponse, body: unknown) {
    this.jsonResponse = body;
    return this;
  } as MockJsonFn;
  jsonFn.mock = { calls: [], results: [] };

  const res: MockResponse = {
    status: vi.fn(statusFn) as unknown as MockStatusFn,
    json: vi.fn(jsonFn) as unknown as MockJsonFn,
  };
  return res;
}

describe("src/services/business/create.ts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  describe("createBusiness — success path", () => {
    it("creates business with required name field only and returns 201", async () => {
      const userId = "user-uuid-1111";
      const expectedBusiness: Business = {
        id: "business-uuid-1111",
        userId,
        name: "Acme Corp",
        email: "user@example.com",
        industry: null,
        description: null,
        website: null,
        reportingPeriod: "monthly",
        reportingTimezone: "UTC",
        lastReminderSentAt: null,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      };

      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      vi.mocked(businessRepository.create).mockResolvedValueOnce(expectedBusiness);

      const req = makeReq({
        user: { id: userId, email: "user@example.com" },
        body: { name: "Acme Corp" },
      });
      const res = makeRes();

      const result = await createBusiness(req as Request, res as unknown as Response);

      expect(businessRepository.getByUserId).toHaveBeenCalledWith(userId);
      expect(businessRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId,
          name: "Acme Corp",
          email: "user@example.com",
          industry: null,
          description: null,
          website: null,
        }),
      );

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(expectedBusiness);
      expect((result as unknown as MockResponse)?.statusCode).toBe(201);
      expect((result as unknown as MockResponse)?.jsonResponse).toEqual(
        expectedBusiness,
      );
    });

    it("creates business with all optional fields and normalizes inputs", async () => {
      const userId = "user-uuid-2222";
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      vi.mocked(businessRepository.create).mockImplementationOnce(
        async (data) =>
          ({
            id: "biz-2222",
            userId: data.userId,
            name: data.name,
            email: data.email,
            industry: data.industry ?? null,
            description: data.description ?? null,
            website: data.website ?? null,
            reportingPeriod: "monthly",
            reportingTimezone: "UTC",
            lastReminderSentAt: null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          }) as Business,
      );

      const req = makeReq({
        user: { id: userId, email: "owner@example.com" },
        body: {
          name: "  Beta  Industries  ",
          industry: "  Software  ",
          description: "  We build things  \n\n  cool  ",
          website: "EXAMPLE.COM",
          countryCode: "us",
        },
      });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(businessRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId,
          name: "Beta Industries",
          email: "owner@example.com",
          industry: "Software",
          description: "We build things\n\ncool",
          website: "https://example.com",
        }),
      );
      expect(res.status).toHaveBeenCalledWith(201);
    });
  });

  describe("createBusiness — 401 unauthenticated", () => {
    it("returns 401 UNAUTHORIZED when req.user is undefined", async () => {
      const req = makeReq({ user: undefined });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "UNAUTHORIZED",
          message: "User authentication required",
        }),
      );
      expect(businessRepository.getByUserId).not.toHaveBeenCalled();
      expect(businessRepository.create).not.toHaveBeenCalled();
    });

    it("returns 401 UNAUTHORIZED when req.user.id is missing", async () => {
      const req = makeReq({ user: { email: "no-id@example.com" } as any });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "UNAUTHORIZED" }),
      );
      expect(businessRepository.getByUserId).not.toHaveBeenCalled();
    });
  });

  describe("createBusiness — 409 business already exists", () => {
    it("returns 409 BUSINESS_ALREADY_EXISTS when getByUserId returns existing", async () => {
      const userId = "user-uuid-3333";
      const existingBusiness: Business = {
        id: "biz-existing",
        userId,
        name: "Existing Co",
        email: "user@example.com",
        industry: null,
        description: null,
        website: null,
        reportingPeriod: "monthly",
        reportingTimezone: "UTC",
        lastReminderSentAt: null,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      };

      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(
        existingBusiness,
      );

      const req = makeReq({
        user: { id: userId, email: "user@example.com" },
        body: { name: "New Business" },
      });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(businessRepository.getByUserId).toHaveBeenCalledWith(userId);
      expect(businessRepository.create).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(409);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "BUSINESS_ALREADY_EXISTS",
          message: "A business already exists for this user",
        }),
      );
    });
  });

  describe("createBusiness — 400 validation error", () => {
    it("returns 400 VALIDATION_ERROR when name is missing", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);

      const req = makeReq({ body: {} });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "VALIDATION_ERROR",
          message: "Invalid input provided",
          details: expect.any(Array),
        }),
      );
      const details = (res.jsonResponse as any)?.details as unknown[];
      expect(
        details.some(
          (d: any) =>
            d?.message?.toLowerCase().includes("required") ||
            d?.message?.toLowerCase().includes("name"),
        ),
      ).toBe(true);
      expect(businessRepository.create).not.toHaveBeenCalled();
    });

    it("returns 400 with Zod issues for invalid website URL scheme", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);

      const req = makeReq({
        body: { name: "Acme Corp", website: "javascript:alert(1)" },
      });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(businessRepository.create).not.toHaveBeenCalled();
      const body = res.jsonResponse as any;
      expect(body?.error).toBe("VALIDATION_ERROR");
      expect(Array.isArray(body?.details)).toBe(true);
    });

    it("returns 400 when name contains control characters", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);

      const req = makeReq({
        body: { name: "Bad\u0000Name" },
      });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(businessRepository.create).not.toHaveBeenCalled();
    });

    it("returns 400 when name is too long (256 chars)", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      const longName = "A".repeat(256);

      const req = makeReq({ body: { name: longName } });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(businessRepository.create).not.toHaveBeenCalled();
    });

    it("returns 400 with string error when non-ZodError is thrown from parse", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);

      const schemasModule = await import("./schemas.js");
      const spy = vi
        .spyOn(schemasModule, "parseCreateBusinessInput")
        .mockRejectedValueOnce(new Error("custom parse failure"));

      const req = makeReq({ body: { name: "Test" } });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(400);
      expect((res.jsonResponse as any)?.error).toBe("VALIDATION_ERROR");
      expect((res.jsonResponse as any)?.details).toBe("custom parse failure");

      spy.mockRestore();
    });
  });

  describe("createBusiness — unique constraint race (AppError throw)", () => {
    it("throws AppError BUSINESS_ALREADY_EXISTS when postgres violates unique index", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      const pgError = Object.assign(new Error("duplicate key"), {
        code: "23505",
        constraint: "businesses_user_id_unique_idx",
      });
      vi.mocked(businessRepository.create).mockRejectedValueOnce(pgError);

      const req = makeReq({
        body: { name: "Race Condition Co" },
      });
      const res = makeRes();

      const promise = createBusiness(
        req as Request,
        res as unknown as Response,
      );

      await expect(promise).rejects.toThrow(AppError);
      await expect(promise).rejects.toHaveProperty(
        "message",
        "A business already exists for this user",
      );
      await expect(promise).rejects.toHaveProperty("status", 409);
      await expect(promise).rejects.toHaveProperty(
        "vrtCode",
        "BUSINESS_ALREADY_EXISTS",
      );
    });

    it("does NOT throw AppError for unrelated postgres error codes", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      const pgError = Object.assign(new Error("deadlock"), {
        code: "40P01",
        constraint: undefined,
      });
      vi.mocked(businessRepository.create).mockRejectedValueOnce(pgError);

      const req = makeReq({ body: { name: "X" } });
      const res = makeRes();

      const result = await createBusiness(
        req as Request,
        res as unknown as Response,
      );

      expect((result as unknown as MockResponse)?.statusCode).toBe(500);
      expect((result as unknown as MockResponse)?.jsonResponse).toEqual(
        expect.objectContaining({
          error: "INTERNAL_ERROR",
          message: "Failed to create business",
        }),
      );
    });

    it("does NOT throw AppError for non-object errors from repository", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      vi.mocked(businessRepository.create).mockRejectedValueOnce(
        "string-based failure",
      );

      const req = makeReq({ body: { name: "Y" } });
      const res = makeRes();

      const result = await createBusiness(
        req as Request,
        res as unknown as Response,
      );

      expect((result as unknown as MockResponse)?.statusCode).toBe(500);
    });
  });

  describe("createBusiness — 500 internal error", () => {
    it("returns 500 INTERNAL_ERROR when getByUserId rejects unexpectedly", async () => {
      vi.mocked(businessRepository.getByUserId).mockRejectedValueOnce(
        new Error("db connection lost"),
      );

      const req = makeReq({ body: { name: "Test Co" } });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "INTERNAL_ERROR",
          message: "Failed to create business",
        }),
      );
    });

    it("returns 500 when repository.create rejects", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      vi.mocked(businessRepository.create).mockRejectedValueOnce(
        new Error("INSERT failed"),
      );

      const req = makeReq({ body: { name: "Valid Name" } });
      const res = makeRes();

      await createBusiness(req as Request, res as unknown as Response);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(console.error).toHaveBeenCalled();
      const mockedConsole = console.error as unknown as {
        mock: { calls: unknown[][] };
      };
      const logArg = mockedConsole.mock.calls[0]?.[0];
      expect(typeof logArg).toBe("string");
      const parsed = JSON.parse(logArg);
      expect(parsed?.event).toBe("business.create.error");
      expect(parsed?.error).toContain("INSERT failed");
    });

    it("handles non-Error thrown values in outer catch block", async () => {
      vi.mocked(businessRepository.getByUserId).mockResolvedValueOnce(null);
      vi.mocked(businessRepository.create).mockRejectedValueOnce(
        42 as unknown as Error,
      );

      const req = makeReq({ body: { name: "Z" } });
      const res = makeRes();

      const result = await createBusiness(
        req as Request,
        res as unknown as Response,
      );

      expect((result as unknown as MockResponse)?.statusCode).toBe(500);
      expect((result as unknown as MockResponse)?.jsonResponse).toEqual(
        expect.objectContaining({ error: "INTERNAL_ERROR" }),
      );
    });
  });
});
