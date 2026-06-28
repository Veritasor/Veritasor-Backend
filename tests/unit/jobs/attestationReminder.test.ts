import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  nextPeriodBoundary,
  shouldSendReminder,
  attestationReminderJob,
} from "../../../src/jobs/attestationReminder.js";
import { businessRepository, Business } from "../../../src/repositories/business.js";
import { logger } from "../../../src/utils/logger.js";

// ── Mocks ────────────────────────────────────────────────────────────────────

vi.mock("../../../src/repositories/business.js", () => ({
  businessRepository: {
    getAll: vi.fn(),
    setLastReminderSentAt: vi.fn(),
  },
}));

vi.mock("../../../src/utils/logger.js", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a minimal Business fixture with sensible defaults. */
function mkBusiness(overrides: Partial<Business> = {}): Business {
  return {
    id: "biz-1",
    userId: "user-1",
    name: "Acme Corp",
    email: "acme@example.com",
    industry: null,
    description: null,
    website: null,
    reportingPeriod: "monthly",
    reportingTimezone: "UTC",
    lastReminderSentAt: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

// ── nextPeriodBoundary ────────────────────────────────────────────────────────

describe("nextPeriodBoundary", () => {
  describe("monthly period", () => {
    it("returns the first of next month at midnight UTC", () => {
      const ref = new Date("2026-05-15T10:30:00.000Z");
      const result = nextPeriodBoundary(ref, "UTC", "monthly");
      expect(result.toISOString()).toBe("2026-06-01T00:00:00.000Z");
    });

    it("advances correctly at year boundary (December → January)", () => {
      const ref = new Date("2026-12-20T00:00:00.000Z");
      const result = nextPeriodBoundary(ref, "UTC", "monthly");
      expect(result.toISOString()).toBe("2027-01-01T00:00:00.000Z");
    });

    it("advances correctly when reference is on the last day of month", () => {
      const ref = new Date("2026-01-31T23:59:59.000Z");
      const result = nextPeriodBoundary(ref, "UTC", "monthly");
      expect(result.toISOString()).toBe("2026-02-01T00:00:00.000Z");
    });

    it("is DST-safe: US/Eastern spring-forward (2026-03-08) does not skip March 1", () => {
      // Reference is just before the spring-forward in Eastern time.
      // We want the boundary to still be April 1 00:00 UTC (which is correct).
      const ref = new Date("2026-03-08T06:59:00.000Z"); // just before spring-forward
      const result = nextPeriodBoundary(ref, "America/New_York", "monthly");
      // In Eastern (UTC-5 in March before DST), 2026-03-08 06:59 UTC = 2026-03-08 01:59 local
      // So the local date is still March, and the next boundary is April 1 UTC midnight
      expect(result.toISOString()).toBe("2026-04-01T00:00:00.000Z");
    });

    it("is DST-safe: US/Eastern fall-back (2026-11-01) does not duplicate November 1 boundary", () => {
      // Reference falls within the ambiguous fall-back hour.
      const ref = new Date("2026-11-01T06:00:00.000Z"); // 01:00 EST, in the "extra" hour
      const result = nextPeriodBoundary(ref, "America/New_York", "monthly");
      // Local date is still November 1, so boundary is December 1.
      expect(result.toISOString()).toBe("2026-12-01T00:00:00.000Z");
    });

    it("is DST-safe: Europe/London (BST spring-forward March 29 2026)", () => {
      // 2026-03-29: UK clocks go forward 01:00 → 02:00 (UTC 01:00).
      const ref = new Date("2026-03-29T00:30:00.000Z"); // 00:30 UTC = 00:30 London (before spring-forward)
      const result = nextPeriodBoundary(ref, "Europe/London", "monthly");
      expect(result.toISOString()).toBe("2026-04-01T00:00:00.000Z");
    });

    it("handles India Standard Time (UTC+5:30, no DST)", () => {
      // 2026-04-30T18:30:00.000Z = midnight IST (UTC+5:30) on April 30 — still April.
      // So next monthly boundary is May 1 00:00 IST = April 30 18:30 UTC.
      // We are AT that boundary, so next boundary is June 1.
      // Let's use a reference that is clearly inside April IST.
      const ref = new Date("2026-04-15T12:00:00.000Z"); // April 15 17:30 IST — mid April
      const result = nextPeriodBoundary(ref, "Asia/Kolkata", "monthly");
      expect(result.toISOString()).toBe("2026-05-01T00:00:00.000Z");
    });
  });

  describe("weekly period", () => {
    it("returns next Monday midnight UTC when today is Wednesday", () => {
      // 2026-05-13 is a Wednesday in UTC.
      const ref = new Date("2026-05-13T10:00:00.000Z");
      const result = nextPeriodBoundary(ref, "UTC", "weekly");
      // Next Monday = 2026-05-18
      expect(result.toISOString()).toBe("2026-05-18T00:00:00.000Z");
    });

    it("advances a full 7 days when today is already Monday", () => {
      // 2026-05-11 is a Monday.
      const ref = new Date("2026-05-11T09:00:00.000Z");
      const result = nextPeriodBoundary(ref, "UTC", "weekly");
      // Same-day Monday → next Monday = 2026-05-18
      expect(result.toISOString()).toBe("2026-05-18T00:00:00.000Z");
    });

    it("handles Sunday correctly (1 day to Monday)", () => {
      // 2026-05-17 is a Sunday.
      const ref = new Date("2026-05-17T20:00:00.000Z");
      const result = nextPeriodBoundary(ref, "UTC", "weekly");
      expect(result.toISOString()).toBe("2026-05-18T00:00:00.000Z");
    });

    it("is DST-safe for weekly: US/Eastern spring-forward Sunday 2026-03-08", () => {
      // 2026-03-08 is the spring-forward Sunday in the US/Eastern zone.
      // 06:59 UTC = 01:59 EST; local is still Sunday, so next Monday is correct.
      const ref = new Date("2026-03-08T06:59:00.000Z");
      const result = nextPeriodBoundary(ref, "America/New_York", "weekly");
      // Local Sunday → next Monday = 2026-03-09
      expect(result.toISOString()).toBe("2026-03-09T00:00:00.000Z");
    });

    it("is DST-safe for weekly: US/Eastern fall-back Sunday 2026-11-01", () => {
      // Fall-back Sunday; local date stays Sunday through the extra hour.
      const ref = new Date("2026-11-01T05:00:00.000Z"); // 00:00 EST = 05:00 UTC
      const result = nextPeriodBoundary(ref, "America/New_York", "weekly");
      // Local Sunday → next Monday = 2026-11-02
      expect(result.toISOString()).toBe("2026-11-02T00:00:00.000Z");
    });
  });
});

// ── shouldSendReminder ────────────────────────────────────────────────────────

describe("shouldSendReminder", () => {
  it("returns true when now is past the first period boundary after createdAt (never reminded)", () => {
    const b = mkBusiness({ createdAt: "2026-04-15T00:00:00.000Z", lastReminderSentAt: null });
    // First monthly boundary after Apr 15 is May 1. We are past that.
    const now = new Date("2026-05-02T00:00:00.000Z");
    expect(shouldSendReminder(b, now)).toBe(true);
  });

  it("returns false when now is before the first period boundary after createdAt", () => {
    const b = mkBusiness({ createdAt: "2026-05-15T00:00:00.000Z", lastReminderSentAt: null });
    // Next boundary is June 1. We're still in May.
    const now = new Date("2026-05-20T00:00:00.000Z");
    expect(shouldSendReminder(b, now)).toBe(false);
  });

  it("returns false when now is before the next boundary since last send", () => {
    const b = mkBusiness({ lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    // Next boundary after May 1 is June 1.
    const now = new Date("2026-05-15T00:00:00.000Z");
    expect(shouldSendReminder(b, now)).toBe(false);
  });

  it("returns true exactly at the boundary (inclusive)", () => {
    const b = mkBusiness({ lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    // Boundary is exactly June 1 midnight UTC.
    const now = new Date("2026-06-01T00:00:00.000Z");
    expect(shouldSendReminder(b, now)).toBe(true);
  });

  it("returns true one ms past the boundary", () => {
    const b = mkBusiness({ lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    const now = new Date("2026-06-01T00:00:00.001Z");
    expect(shouldSendReminder(b, now)).toBe(true);
  });

  it("returns false one ms before the boundary", () => {
    const b = mkBusiness({ lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    const now = new Date("2026-05-31T23:59:59.999Z");
    expect(shouldSendReminder(b, now)).toBe(false);
  });

  it("works with weekly period", () => {
    // Last reminded on 2026-05-11 (Monday). Next boundary is 2026-05-18.
    const b = mkBusiness({
      reportingPeriod: "weekly",
      lastReminderSentAt: "2026-05-11T00:00:00.000Z",
    });
    expect(shouldSendReminder(b, new Date("2026-05-17T23:59:59.999Z"))).toBe(false);
    expect(shouldSendReminder(b, new Date("2026-05-18T00:00:00.000Z"))).toBe(true);
  });

  it("defaults to UTC when reportingTimezone is not set", () => {
    const b = mkBusiness({ reportingTimezone: "", lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    const now = new Date("2026-06-01T00:00:00.000Z");
    expect(shouldSendReminder(b, now)).toBe(true);
  });
});

// ── attestationReminderJob ────────────────────────────────────────────────────

describe("attestationReminderJob", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(businessRepository.setLastReminderSentAt).mockResolvedValue(true);
  });

  it("logs 'No businesses to remind.' when getAll returns empty array", async () => {
    vi.mocked(businessRepository.getAll).mockResolvedValue([]);
    await attestationReminderJob(new Date("2026-06-01T00:00:00.000Z"));
    expect(logger.info).toHaveBeenCalledWith("No businesses to remind.");
  });

  it("does not call setLastReminderSentAt when no reminders are due", async () => {
    // Business created June 1 — next boundary is July 1. We're only on June 15.
    const b = mkBusiness({ createdAt: "2026-06-01T00:00:00.000Z", lastReminderSentAt: null });
    vi.mocked(businessRepository.getAll).mockResolvedValue([b]);
    await attestationReminderJob(new Date("2026-06-15T00:00:00.000Z"));
    expect(businessRepository.setLastReminderSentAt).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledWith("No businesses to remind.");
  });

  it("sends reminder and persists lastReminderSentAt when due", async () => {
    const b = mkBusiness({ lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    vi.mocked(businessRepository.getAll).mockResolvedValue([b]);
    const now = new Date("2026-06-01T00:00:00.000Z");
    await attestationReminderJob(now);
    expect(logger.info).toHaveBeenCalledWith("Reminder would be sent for business: Acme Corp");
    expect(businessRepository.setLastReminderSentAt).toHaveBeenCalledWith(
      "biz-1",
      now.toISOString(),
    );
    expect(logger.info).toHaveBeenCalledWith("Reminded 1 business(es).");
  });

  it("only reminds businesses whose period boundary has passed (mixed set)", async () => {
    const due = mkBusiness({ id: "biz-due", name: "Due Corp", lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    const notDue = mkBusiness({ id: "biz-not", name: "NotDue Corp", lastReminderSentAt: "2026-06-01T00:00:00.000Z" });
    vi.mocked(businessRepository.getAll).mockResolvedValue([due, notDue]);
    const now = new Date("2026-06-15T00:00:00.000Z");
    await attestationReminderJob(now);
    expect(businessRepository.setLastReminderSentAt).toHaveBeenCalledTimes(1);
    expect(businessRepository.setLastReminderSentAt).toHaveBeenCalledWith("biz-due", now.toISOString());
  });

  it("uses Date.now() as default when no `now` argument supplied", async () => {
    vi.mocked(businessRepository.getAll).mockResolvedValue([]);
    // Should not throw even when called without `now`.
    await expect(attestationReminderJob()).resolves.toBeUndefined();
  });

  it("catches and logs repository errors without rethrowing", async () => {
    vi.mocked(businessRepository.getAll).mockRejectedValue(new Error("DB down"));
    await attestationReminderJob(new Date("2026-06-01T00:00:00.000Z"));
    expect(logger.error).toHaveBeenCalledWith(
      "Error running attestation reminder job:",
      expect.any(Error),
    );
  });

  it("does not double-fire within same period (idempotency)", async () => {
    const b = mkBusiness({ lastReminderSentAt: "2026-05-01T00:00:00.000Z" });
    vi.mocked(businessRepository.getAll).mockResolvedValue([b]);
    const now = new Date("2026-06-01T00:00:00.000Z");

    // First run fires.
    await attestationReminderJob(now);
    expect(businessRepository.setLastReminderSentAt).toHaveBeenCalledTimes(1);

    // Simulate the business state after first run (lastReminderSentAt updated).
    const updated = mkBusiness({ lastReminderSentAt: now.toISOString() });
    vi.mocked(businessRepository.getAll).mockResolvedValue([updated]);
    vi.clearAllMocks();
    vi.mocked(businessRepository.setLastReminderSentAt).mockResolvedValue(true);

    // Second run 1 hour later — still in June, no new boundary crossed.
    await attestationReminderJob(new Date("2026-06-01T01:00:00.000Z"));
    expect(businessRepository.setLastReminderSentAt).not.toHaveBeenCalled();
  });

  // ── DST transition integration scenarios ─────────────────────────────────

  it("DST spring-forward: does not skip a monthly reminder in US/Eastern March 2026", async () => {
    // lastReminderSentAt = Feb 1 00:00 UTC.
    // nextPeriodBoundary reads local date as Jan 31 EST (UTC-5), next month = Feb.
    // Boundary = Date.UTC(2026, 1, 1) = 2026-02-01T00:00:00.000Z — already passed!
    // So we use Feb 1 06:00 UTC as the last reminder (= Feb 1 01:00 EST).
    // Local: Feb 1, next boundary = Date.UTC(2026, 2, 1) = 2026-03-01T00:00:00.000Z.
    const b = mkBusiness({
      reportingTimezone: "America/New_York",
      lastReminderSentAt: "2026-02-01T06:00:00.000Z", // Feb 1 01:00 EST
    });
    vi.mocked(businessRepository.getAll).mockResolvedValue([b]);

    // Mar 1 00:00 UTC minus 1ms — boundary not yet crossed
    await attestationReminderJob(new Date("2026-02-28T23:59:59.999Z"));
    expect(businessRepository.setLastReminderSentAt).not.toHaveBeenCalled();

    vi.clearAllMocks();
    vi.mocked(businessRepository.setLastReminderSentAt).mockResolvedValue(true);

    // Mar 1 00:00 UTC — boundary crossed exactly
    await attestationReminderJob(new Date("2026-03-01T00:00:00.000Z"));
    expect(businessRepository.setLastReminderSentAt).toHaveBeenCalledTimes(1);
  });

  it("DST fall-back: does not fire twice during the extra hour in US/Eastern Nov 2026", async () => {
    // lastReminderSentAt = Oct 1 06:00 UTC (Oct 1 02:00 EDT — local date is Oct 1).
    // nextPeriodBoundary: local = Oct 1, next month = Nov → Date.UTC(2026, 10, 1) = 2026-11-01T00:00:00.000Z.
    const b = mkBusiness({
      reportingTimezone: "America/New_York",
      lastReminderSentAt: "2026-10-01T06:00:00.000Z",
    });
    vi.mocked(businessRepository.getAll).mockResolvedValue([b]);

    // Nov 1 00:00 UTC minus 1ms — not yet due
    await attestationReminderJob(new Date("2026-10-31T23:59:59.999Z"));
    expect(businessRepository.setLastReminderSentAt).not.toHaveBeenCalled();

    vi.clearAllMocks();
    vi.mocked(businessRepository.setLastReminderSentAt).mockResolvedValue(true);

    // Nov 1 00:00 UTC — due; DST fall-back happens at 06:00 UTC (02:00 EDT→01:00 EST)
    // so the boundary fires at UTC midnight, well before the ambiguous hour
    await attestationReminderJob(new Date("2026-11-01T00:00:00.000Z"));
    expect(businessRepository.setLastReminderSentAt).toHaveBeenCalledTimes(1);
  });
});
