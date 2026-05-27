import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { attestationReminderJob } from "../../../src/jobs/attestationReminder.js";
import { businessRepository } from "../../../src/repositories/business.js";
import { attestationRepository } from "../../../src/repositories/attestation.js";
import { logger } from "../../../src/utils/logger.js";

// Mock repository modules cleanly
vi.mock("../../../src/repositories/business.js", () => ({
  businessRepository: {
    getAll: vi.fn(),
  },
}));

vi.mock("../../../src/repositories/attestation.js", () => ({
  attestationRepository: {
    listByBusiness: vi.fn(),
  },
}));

// Mock logger to avoid test stdout clutter
vi.mock("../../../src/utils/logger.js", () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe("attestationReminderJob", () => {
  beforeEach(() => {
    // Lock clock to fixed reference point (May 27, 2026) to stabilize "one-month" calculations
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-27T12:00:00.000Z"));
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("should log and return early if no businesses are present in the system", async () => {
    vi.mocked(businessRepository.getAll).mockResolvedValue([]);

    await attestationReminderJob();

    expect(businessRepository.getAll).toHaveBeenCalledOnce();
    expect(logger.info).toHaveBeenCalledWith("No businesses to remind.");
  });

  it("should skip businesses that have an attestation within the past month window", async () => {
    const mockBusiness = { id: "biz-1", name: "Active Corp" };
    vi.mocked(businessRepository.getAll).mockResolvedValue([mockBusiness]);
    
    // Attestation dated 10 days ago (well within 1-month threshold)
    vi.mocked(attestationRepository.listByBusiness).mockResolvedValue([
      { id: "att-1", businessId: "biz-1", attestedAt: "2026-05-17T00:00:00.000Z" },
    ]);

    await attestationReminderJob();

    expect(logger.info).toHaveBeenCalledWith("No businesses to remind.");
    expect(logger.info).not. some((call) => call[0]?.includes("Reminder would be sent"));
  });

  it("should trigger reminders for stale businesses with zero history or old history", async () => {
    const freshBiz = { id: "biz-fresh", name: "Fresh Corp" };
    const staleBiz = { id: "biz-stale", name: "Stale Corp" };
    
    vi.mocked(businessRepository.getAll).mockResolvedValue([freshBiz, staleBiz]);
    
    // Fresh business has a recent attestation
    vi.mocked(attestationRepository.listByBusiness).mockImplementation(async (id) => {
      if (id === "biz-fresh") {
        return [{ id: "a1", businessId: "biz-fresh", attestedAt: "2026-05-20T00:00:00.000Z" }];
      }
      // Stale business has an attestation older than one month
      return [{ id: "a2", businessId: "biz-stale", attestedAt: "2026-04-01T00:00:00.000Z" }];
    });

    await attestationReminderJob();

    expect(logger.info).toHaveBeenCalledWith("Found 1 businesses to remind.");
    expect(logger.info).toHaveBeenCalledWith("Reminder would be sent for business: Stale Corp");
  });

  it("should test the boundary condition: attestation exactly one month old is evaluated as a recent hit", async () => {
    const mockBusiness = { id: "biz-boundary", name: "Boundary Corp" };
    vi.mocked(businessRepository.getAll).mockResolvedValue([mockBusiness]);
    
    // Exactly 1 month ago relative to our fixed reference date (2026-05-27)
    vi.mocked(attestationRepository.listByBusiness).mockResolvedValue([
      { id: "att-b", businessId: "biz-boundary", attestedAt: "2026-04-27T12:00:00.000Z" },
    ]);

    await attestationReminderJob();

    // Because (attestationDate >= lastMonth) evaluates true exactly at boundary, it counts as recent
    expect(logger.info).toHaveBeenCalledWith("No businesses to remind.");
  });

  it("should test the boundary condition: attestation just 1 millisecond past one month is evaluated as stale", async () => {
    const mockBusiness = { id: "biz-stale-edge", name: "Stale Edge Corp" };
    vi.mocked(businessRepository.getAll).mockResolvedValue([mockBusiness]);
    
    // Just 1ms over the one-month cliff edge
    vi.mocked(attestationRepository.listByBusiness).mockResolvedValue([
      { id: "att-se", businessId: "biz-stale-edge", attestedAt: "2026-04-27T11:59:59.999Z" },
    ]);

    await attestationReminderJob();

    expect(logger.info).toHaveBeenCalledWith("Found 1 businesses to remind.");
    expect(logger.info).toHaveBeenCalledWith("Reminder would be sent for business: Stale Edge Corp");
  });

  it("should capture and log runtime internal repository errors gracefully", async () => {
    vi.mocked(businessRepository.getAll).mockRejectedValue(new Error("Database offline"));

    await attestationReminderJob();

    expect(logger.error).toHaveBeenCalledWith(
      "Error running attestation reminder job:",
      expect.any(Error)
    );
  });
});