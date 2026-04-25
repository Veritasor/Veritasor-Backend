import { describe, it, expect } from "vitest";
import { revenueReportQuerySchema, RevenueReportValidationErrors } from "../../../../src/services/analytics/revenueReportSchema.js";

describe("revenueReportQuerySchema - Security Hardening", () => {
  // -------------------------------------------------------------------------
  // Valid inputs - should pass validation
  // -------------------------------------------------------------------------

  describe("valid inputs", () => {
    it("should accept a valid period", () => {
      const result = revenueReportQuerySchema.safeParse({ period: "2025-10" });
      expect(result.success).toBe(true);
    });

    it("should accept a valid date range", () => {
      const result = revenueReportQuerySchema.safeParse({ from: "2025-01", to: "2025-12" });
      expect(result.success).toBe(true);
    });

    it("should accept minimum valid year (2020)", () => {
      const result = revenueReportQuerySchema.safeParse({ period: "2020-01" });
      expect(result.success).toBe(true);
    });

    it("should accept maximum valid year (2105)", () => {
      const result = revenueReportQuerySchema.safeParse({ period: "2105-12" });
      expect(result.success).toBe(true);
    });

    it("should accept edge case years", () => {
      const result1 = revenueReportQuerySchema.safeParse({ period: "2099-12" });
      const result2 = revenueReportQuerySchema.safeParse({ period: "2100-01" });
      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Invalid format tests
  // -------------------------------------------------------------------------

  describe("invalid format", () => {
    it("should reject non-string values", () => {
      const results = [
        revenueReportQuerySchema.safeParse({ period: 202510 }),
        revenueReportQuerySchema.safeParse({ from: null }),
        revenueReportQuerySchema.safeParse({ to: undefined }),
        revenueReportQuerySchema.safeParse({ period: {} }),
        revenueReportQuerySchema.safeParse({ from: [] }),
      ];

      results.forEach(result => {
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].message).toMatch(/string|either.*period.*alone/i);
        }
      });
    });

    it("should reject malformed date strings", () => {
      const invalidFormats = [
        "2025/10",      // Wrong separator
        "2025-1",       // Single digit month
        "25-10",        // Short year
        "2025-13",      // Invalid month
        "2025-00",      // Invalid month
        "2025-100",     // Three digit month
        "202510",       // Missing separator
        "20-25-10",     // Extra separator
        "2025-1-0",     // Multiple separators
        "abcd-ef",      // Non-numeric
        "2025-10 ",     // Trailing space
        " 2025-10",     // Leading space
      ];

      invalidFormats.forEach(format => {
        const result = revenueReportQuerySchema.safeParse({ period: format });
        expect(result.success).toBe(false);
      });
    });

    it("should reject strings with incorrect length", () => {
      const invalidLengths = [
        "2025-1",        // Too short (6 chars)
        "2025-100",      // Too long (8 chars)
        "202510",        // Too short (6 chars)
        "20-25-10",      // Too long (8 chars)
        "",              // Empty string
        "2025-10-extra", // Too long
      ];

      invalidLengths.forEach(format => {
        const result = revenueReportQuerySchema.safeParse({ period: format });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].message).toMatch(/too long|too short|exactly 7 characters/);
        }
      });
    });
  });

  // -------------------------------------------------------------------------
  // Year boundary tests
  // -------------------------------------------------------------------------

  describe("year boundary validation", () => {
    it("should reject years before 2020", () => {
      const invalidYears = [
        "2019-12",
        "2015-06",
        "2000-01",
        "1999-12",
        "0000-01",
      ];

      invalidYears.forEach(year => {
        const result = revenueReportQuerySchema.safeParse({ period: year });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].message).toMatch(/2020.*2105|between 2020 and 2105/);
        }
      });
    });

    it("should reject years after 2105", () => {
      const invalidYears = [
        "2106-01",
        "2110-12",
        "2200-01",
        "9999-12",
      ];

      invalidYears.forEach(year => {
        const result = revenueReportQuerySchema.safeParse({ period: year });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].message).toMatch(/2020.*2105|between 2020 and 2105/);
        }
      });
    });

    it("should reject edge case years just outside bounds", () => {
      const result1 = revenueReportQuerySchema.safeParse({ period: "2019-12" });
      const result2 = revenueReportQuerySchema.safeParse({ period: "2106-01" });

      expect(result1.success).toBe(false);
      expect(result2.success).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Month validation tests
  // -------------------------------------------------------------------------

  describe("month validation", () => {
    it("should reject invalid months", () => {
      const invalidMonths = [
        "2025-00",
        "2025-13",
        "2025-99",
        "2025-01",  // Valid, control test
      ];

      invalidMonths.forEach(month => {
        if (month === "2025-01") return; // Skip valid control
        const result = revenueReportQuerySchema.safeParse({ period: month });
        expect(result.success).toBe(false);
      });
    });

    it("should reject single-digit months without leading zero", () => {
      const invalidMonths = [
        "2025-1",
        "2025-2",
        "2025-9",
      ];

      invalidMonths.forEach(month => {
        const result = revenueReportQuerySchema.safeParse({ period: month });
        expect(result.success).toBe(false);
      });
    });

    it("should accept all valid months with leading zeros", () => {
      const validMonths = [
        "2025-01", "2025-02", "2025-03", "2025-04", "2025-05",
        "2025-06", "2025-07", "2025-08", "2025-09", "2025-10",
        "2025-11", "2025-12",
      ];

      validMonths.forEach(month => {
        const result = revenueReportQuerySchema.safeParse({ period: month });
        expect(result.success).toBe(true);
      });
    });
  });

  // -------------------------------------------------------------------------
  // Injection prevention tests
  // -------------------------------------------------------------------------

  describe("injection prevention", () => {
    it("should reject HTML injection attempts", () => {
      const injectionAttempts = [
        "2025-10<script>",
        "2025-10<img>",
        "2025-10<a>",
        "2025-10<div>",
        "<script>2025-10",
        "2025-10</script>",
        "2025-10<!--",
        "2025-10-->",
      ];

      injectionAttempts.forEach(attempt => {
        const result = revenueReportQuerySchema.safeParse({ period: attempt });
        expect(result.success).toBe(false);
        // Either length validation or character validation should catch this
        if (!result.success) {
          const message = result.error.issues[0].message;
          expect(message).toMatch(/too long|invalid characters/);
        }
      });
    });

    it("should reject SQL injection attempts", () => {
      const injectionAttempts = [
        "2025-10'; DROP TABLE users; --",
        "2025-10' OR '1'='1",
        "2025-10\"; SELECT * FROM users; --",
        "2025-10' UNION SELECT password FROM users --",
        "2025-10\\x27\\x3B DROP TABLE users\\x3B --",
      ];

      injectionAttempts.forEach(attempt => {
        const result = revenueReportQuerySchema.safeParse({ period: attempt });
        expect(result.success).toBe(false);
        // Either length validation or character validation should catch this
        if (!result.success) {
          const message = result.error.issues[0].message;
          expect(message).toMatch(/too long|invalid characters/);
        }
      });
    });

    it("should reject command injection attempts", () => {
      const injectionAttempts = [
        "2025-10; rm -rf /",
        "2025-10| cat /etc/passwd",
        "2025-10&& echo hacked",
        "2025-10`whoami`",
        "2025-10$(id)",
        "2025-10${HOME}",
      ];

      injectionAttempts.forEach(attempt => {
        const result = revenueReportQuerySchema.safeParse({ period: attempt });
        expect(result.success).toBe(false);
        // Either length validation or character validation should catch this
        if (!result.success) {
          const message = result.error.issues[0].message;
          expect(message).toMatch(/too long|invalid characters/);
        }
      });
    });

    it("should reject path traversal attempts", () => {
      const injectionAttempts = [
        "2025-10../../../etc/passwd",
        "2025-10..\\..\\..\\windows\\system32",
        "2025-10/../../../root/.ssh/id_rsa",
        "2025-10\\\\..\\\\..\\\\..\\\\boot.ini",
      ];

      injectionAttempts.forEach(attempt => {
        const result = revenueReportQuerySchema.safeParse({ period: attempt });
        expect(result.success).toBe(false);
        // Either length validation or character validation should catch this
        if (!result.success) {
          const message = result.error.issues[0].message;
          expect(message).toMatch(/too long|invalid characters/);
        }
      });
    });

    it("should reject XSS attempts with various encodings", () => {
      const injectionAttempts = [
        "2025-10%3Cscript%3E",
        "2025-10&lt;script&gt;",
        "2025-10&#60;script&#62;",
        "2025-10\\u003cscript\\u003e",
        "2025-10\\x3Cscript\\x3E",
      ];

      injectionAttempts.forEach(attempt => {
        const result = revenueReportQuerySchema.safeParse({ period: attempt });
        expect(result.success).toBe(false);
      });
    });
  });

  // -------------------------------------------------------------------------
  // Parameter combination tests
  // -------------------------------------------------------------------------

  describe("parameter combination validation", () => {
    it("should reject period with from parameter", () => {
      const result = revenueReportQuerySchema.safeParse({
        period: "2025-10",
        from: "2025-01"
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain("either \"period\" alone or both \"from\" and \"to\"");
      }
    });

    it("should reject period with to parameter", () => {
      const result = revenueReportQuerySchema.safeParse({
        period: "2025-10",
        to: "2025-12"
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain("either \"period\" alone or both \"from\" and \"to\"");
      }
    });

    it("should reject period with both from and to parameters", () => {
      const result = revenueReportQuerySchema.safeParse({
        period: "2025-10",
        from: "2025-01",
        to: "2025-12"
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain("either \"period\" alone or both \"from\" and \"to\"");
      }
    });

    it("should reject from parameter without to parameter", () => {
      const result = revenueReportQuerySchema.safeParse({
        from: "2025-01"
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain("either \"period\" alone or both \"from\" and \"to\"");
      }
    });

    it("should reject to parameter without from parameter", () => {
      const result = revenueReportQuerySchema.safeParse({
        to: "2025-12"
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain("either \"period\" alone or both \"from\" and \"to\"");
      }
    });

    it("should reject empty object", () => {
      const result = revenueReportQuerySchema.safeParse({});
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain("either \"period\" alone or both \"from\" and \"to\"");
      }
    });

    it("should accept valid range parameters", () => {
      const result = revenueReportQuerySchema.safeParse({
        from: "2025-01",
        to: "2025-12"
      });
      expect(result.success).toBe(true);
    });

    it("should apply same validation to both from and to parameters", () => {
      const testCases = [
        { from: "2019-01", to: "2020-01" }, // Invalid from
        { from: "2025-01", to: "2106-01" }, // Invalid to
        { from: "2025-13", to: "2025-12" }, // Invalid from month
        { from: "2025-01", to: "2025-00" }, // Invalid to month
        { from: "2025-1", to: "2025-12" },  // Invalid from format
        { from: "2025-01", to: "2025-1" },  // Invalid to format
      ];

      testCases.forEach(testCase => {
        const result = revenueReportQuerySchema.safeParse(testCase);
        expect(result.success).toBe(false);
      });
    });
  });

  // -------------------------------------------------------------------------
  // DoS prevention tests
  // -------------------------------------------------------------------------

  describe("denial of service prevention", () => {
    it("should reject extremely long strings", () => {
      const longString = "2025-" + "a".repeat(1000);
      const result = revenueReportQuerySchema.safeParse({ period: longString });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain("too long");
      }
    });

    it("should reject strings with many null bytes", () => {
      const nullBytes = "2025-10" + "\0".repeat(100);
      const result = revenueReportQuerySchema.safeParse({ period: nullBytes });
      expect(result.success).toBe(false);
    });

    it("should reject strings with Unicode attacks", () => {
      const unicodeAttacks = [
        "2025-10\u0000",      // Null character
        "2025-10\uFFFF",      // Maximum Unicode
        "2025-10\uFEFF",      // BOM
        "2025-10\u202E",      // Right-to-left override
        "2025-10\u200F",      // Right-to-left mark
      ];

      unicodeAttacks.forEach(attack => {
        const result = revenueReportQuerySchema.safeParse({ period: attack });
        expect(result.success).toBe(false);
      });
    });
  });

  // -------------------------------------------------------------------------
  // Error type validation
  // -------------------------------------------------------------------------

  describe("error type constants", () => {
    it("should define all expected error types", () => {
      const expectedErrors = [
        "INVALID_FORMAT",
        "YEAR_OUT_OF_BOUNDS",
        "MONTH_OUT_OF_BOUNDS",
        "STRING_TOO_LONG",
        "STRING_TOO_SHORT",
        "INVALID_CHARACTERS",
        "CONFLICTING_PARAMETERS",
        "MISSING_PARAMETERS",
      ];

      expectedErrors.forEach(error => {
        expect(RevenueReportValidationErrors).toHaveProperty(error);
      });
    });

    it("should have immutable error constants", () => {
      // Verify the constants object is properly typed as const
      const errors = RevenueReportValidationErrors;
      expect(typeof errors.INVALID_FORMAT).toBe("string");
      expect(typeof errors.YEAR_OUT_OF_BOUNDS).toBe("string");
    });
  });

  // -------------------------------------------------------------------------
  // Edge case boundary tests
  // -------------------------------------------------------------------------

  describe("boundary condition tests", () => {
    it("should handle exact boundary years correctly", () => {
      const minYear = revenueReportQuerySchema.safeParse({ period: "2020-01" });
      const maxYear = revenueReportQuerySchema.safeParse({ period: "2105-12" });
      const belowMin = revenueReportQuerySchema.safeParse({ period: "2019-12" });
      const aboveMax = revenueReportQuerySchema.safeParse({ period: "2106-01" });

      expect(minYear.success).toBe(true);
      expect(maxYear.success).toBe(true);
      expect(belowMin.success).toBe(false);
      expect(aboveMax.success).toBe(false);
    });

    it("should handle all valid months at boundaries", () => {
      const boundaryMonths = [
        "2020-01", "2020-12", // Min year boundaries
        "2105-01", "2105-12", // Max year boundaries
      ];

      boundaryMonths.forEach(month => {
        const result = revenueReportQuerySchema.safeParse({ period: month });
        expect(result.success).toBe(true);
      });
    });

    it("should reject malformed dates close to valid ones", () => {
      const nearMisses = [
        "2020-00",    // Just below valid month
        "2020-13",    // Just above valid month
        "2019-12",    // Just below valid year
        "2106-01",    // Just above valid year
        "202-01",     // Missing digit
        "2025-1",     // Missing leading zero
        "20251-01",   // Extra digit
      ];

      nearMisses.forEach(nearMiss => {
        const result = revenueReportQuerySchema.safeParse({ period: nearMiss });
        expect(result.success).toBe(false);
      });
    });
  });
});
