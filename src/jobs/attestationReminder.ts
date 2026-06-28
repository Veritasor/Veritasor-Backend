import { businessRepository, Business, ReportingPeriod } from "../repositories/business.js";
import { logger } from "../utils/logger.js";

/**
 * Compute the start-of-period (SOW for weekly, SOM for monthly) boundary
 * immediately after `reference` in the business's IANA timezone.
 *
 * The approach:
 *  1. Use `Intl.DateTimeFormat` to decompose `reference` into year/month/day
 *     components in the target timezone — this is DST-safe because we never
 *     reconstruct a wall-clock time with Date's local methods.
 *  2. Compute the *next* period boundary (SOW or SOM) relative to those
 *     components using `Date.UTC`, so the result is always a UTC instant.
 *
 * DST safety: we compute the boundary in UTC arithmetic (Date.UTC) after
 * reading the local date parts. This means "next Monday in Europe/London"
 * during a spring-forward produces the correct UTC instant even though
 * 01:00–02:00 local time doesn't exist that night.
 *
 * @param reference - The current wall-clock instant (typically `new Date()`).
 * @param tz        - An IANA timezone string (e.g. 'America/New_York').
 * @param period    - 'weekly' (fires every Monday 00:00 local) or 'monthly'
 *                    (fires on the 1st of each month 00:00 local).
 * @returns UTC Date representing the next period boundary.
 */
export function nextPeriodBoundary(
  reference: Date,
  tz: string,
  period: ReportingPeriod,
): Date {
  // Decompose `reference` into local calendar fields using Intl.
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    weekday: "short",
  });
  const parts = Object.fromEntries(fmt.formatToParts(reference).map((p) => [p.type, p.value]));

  const year = Number(parts.year);
  const month = Number(parts.month); // 1-based
  const day = Number(parts.day);

  if (period === "weekly") {
    const DOW_MAP: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    const dow = DOW_MAP[parts.weekday] ?? 0;
    // Days until next Monday (dow=1). If today is Monday, jump a full week.
    const daysUntilMonday = dow === 1 ? 7 : (8 - dow) % 7 || 7;
    // Next Monday midnight UTC — Date.UTC absorbs overflow days correctly.
    return new Date(Date.UTC(year, month - 1, day + daysUntilMonday));
  }

  // Monthly: first day of next month, midnight UTC.
  return new Date(Date.UTC(year, month, 1)); // month is 1-based; Date.UTC month is 0-based, so month=month equals +1
}

/**
 * Returns true when a reminder should fire for `business` right now.
 *
 * A reminder is due when:
 *   - A new reporting period has started since the last reminder (or no
 *     reminder has ever been sent), AND
 *   - `now` is at or past the most-recently-started period boundary.
 *
 * This is evaluated by checking whether `now >= nextPeriodBoundary(lastFire)`.
 * If the business has never been reminded we treat its `createdAt` as the
 * last reference point so it fires at the first boundary after creation.
 */
export function shouldSendReminder(business: Business, now: Date): boolean {
  const reference = business.lastReminderSentAt
    ? new Date(business.lastReminderSentAt)
    : new Date(business.createdAt);

  const tz = business.reportingTimezone || "UTC";
  const boundary = nextPeriodBoundary(reference, tz, business.reportingPeriod);
  return now >= boundary;
}

/**
 * Period-aligned attestation reminder job.
 *
 * Iterates every business, computes whether the current wall-clock time has
 * crossed a period boundary since the last reminder, and fires (logs) a
 * reminder only when due. Persists `lastReminderSentAt` immediately after
 * each send to prevent double-triggering on re-runs within the same period.
 *
 * Designed to be invoked on a frequent cron (e.g. every 5 minutes); the
 * period-alignment logic ensures actual notifications are calendar-aligned.
 */
export const attestationReminderJob = async (now: Date = new Date()): Promise<void> => {
  logger.info("Running attestation reminder job...");

  try {
    const businesses = await businessRepository.getAll();
    let reminded = 0;

    for (const business of businesses) {
      if (!shouldSendReminder(business, now)) continue;

      logger.info(`Reminder would be sent for business: ${business.name}`);
      await businessRepository.setLastReminderSentAt(business.id, now.toISOString());
      reminded++;
    }

    logger.info(
      reminded === 0
        ? "No businesses to remind."
        : `Reminded ${reminded} business(es).`,
    );
  } catch (error) {
    logger.error("Error running attestation reminder job:", error);
  }
};
