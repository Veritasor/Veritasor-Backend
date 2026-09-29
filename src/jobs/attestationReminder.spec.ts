import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getAll: vi.fn(),
  setLastReminderSentAt: vi.fn(),
  info: vi.fn(),
  error: vi.fn(),
}));

vi.mock("../repositories/business.js", () => ({
  businessRepository: {
    getAll: mocks.getAll,
    setLastReminderSentAt: mocks.setLastReminderSentAt,
  },
}));

vi.mock("../utils/logger.js", () => ({
  logger: {
    info: mocks.info,
    error: mocks.error,
  },
}));

vi.mock("./jobRunner.js", async () => {
  const actual = await vi.importActual<typeof import("./jobRunner.js")>("./jobRunner.js");

  return {
    ...actual,
    runInstrumentedJob: async (
      _jobName: string,
      fn: () => Promise<{ itemsProcessed: number; success: boolean }>,
    ) => fn(),
  };
});

import {
  ATTESTATION_REMINDER_JOB_NAME,
  attestationReminderJob,
  nextPeriodBoundary,
  shouldSendReminder,
} from "./attestationReminder.js";

function makeBusiness(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "biz-1",
    userId: "user-1",
    name: "Acme",
    email: "owner@example.com",
    reportingPeriod: "weekly" as const,
    reportingTimezone: "UTC",
    lastReminderSentAt: null,
    createdAt: "2025-01-01T00:00:00.000Z",
    updatedAt: "2025-01-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("attestationReminder job behavior", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("exposes the stable job identifier", () => {
    expect(ATTESTATION_REMINDER_JOB_NAME).toBe("attestation_reminder");
  });

  it("computes the next weekly and monthly period boundaries in UTC", () => {
    expect(nextPeriodBoundary(new Date("2025-01-08T12:00:00.000Z"), "UTC", "weekly")).toEqual(
      new Date("2025-01-13T00:00:00.000Z"),
    );
    expect(nextPeriodBoundary(new Date("2025-01-31T12:00:00.000Z"), "UTC", "monthly")).toEqual(
      new Date("2025-02-01T00:00:00.000Z"),
    );
  });

  it("falls back to UTC for invalid timezone data instead of crashing", () => {
    const boundary = nextPeriodBoundary(new Date("2025-01-08T12:00:00.000Z"), "Not/AZone", "weekly");

    expect(boundary).toEqual(new Date("2025-01-13T00:00:00.000Z"));
  });

  it("detects reminder due windows and rejects malformed business state", () => {
    const business = makeBusiness({
      createdAt: "2025-01-01T00:00:00.000Z",
      lastReminderSentAt: null,
      reportingPeriod: "weekly",
      reportingTimezone: "UTC",
    });

    expect(shouldSendReminder(business, new Date("2025-01-03T12:00:00.000Z"))).toBe(false);
    expect(shouldSendReminder(business, new Date("2025-01-13T00:00:00.000Z"))).toBe(true);
    expect(
      shouldSendReminder(
        makeBusiness({
          createdAt: "not-a-date",
          lastReminderSentAt: "not-a-date",
          reportingTimezone: "Not/AZone",
        }),
        new Date("2025-01-13T00:00:00.000Z"),
      ),
    ).toBe(false);
  });

  it("sends one reminder per due business and suppresses repeats until the next boundary", async () => {
    const dueBusiness = makeBusiness({
      id: "biz-due",
      createdAt: "2025-01-01T00:00:00.000Z",
      lastReminderSentAt: null,
      reportingPeriod: "weekly",
    });
    const notDueBusiness = makeBusiness({
      id: "biz-not-due",
      createdAt: "2025-01-20T00:00:00.000Z",
      lastReminderSentAt: null,
      reportingPeriod: "weekly",
    });

    mocks.getAll.mockResolvedValue([dueBusiness, notDueBusiness]);

    await expect(attestationReminderJob(new Date("2025-01-13T12:00:00.000Z"))).resolves.toEqual({
      itemsProcessed: 1,
      success: true,
    });
    expect(mocks.setLastReminderSentAt).toHaveBeenCalledTimes(1);
    expect(mocks.setLastReminderSentAt).toHaveBeenCalledWith("biz-due", "2025-01-13T12:00:00.000Z");

    mocks.getAll.mockResolvedValue([
      makeBusiness({
        id: "biz-due",
        createdAt: "2025-01-01T00:00:00.000Z",
        lastReminderSentAt: "2025-01-13T12:00:00.000Z",
        reportingPeriod: "weekly",
      }),
    ]);

    await expect(attestationReminderJob(new Date("2025-01-14T12:00:00.000Z"))).resolves.toEqual({
      itemsProcessed: 0,
      success: true,
    });
    expect(mocks.setLastReminderSentAt).toHaveBeenCalledTimes(1);
  });
});
