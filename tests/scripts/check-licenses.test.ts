import { describe, it, expect, vi, beforeEach } from "vitest";
import { checkLicenses } from "../../scripts/check-licenses";

vi.mock("license-checker", () => ({
  default: {
    init: vi.fn((opts, callback) => {
      // Mock packages based on the start path for different test cases
      if (opts.start === "pass") {
        callback(null, {
          "package-a@1.0.0": { licenses: "MIT" },
          "package-b@2.0.0": { licenses: ["Apache-2.0"] },
        });
      } else if (opts.start === "fail") {
        callback(null, {
          "package-c@1.0.0": { licenses: "GPL-3.0" },
        });
      } else if (opts.start === "exception") {
        callback(null, {
          "package-d@1.0.0": { licenses: "GPL-3.0" },
        });
      } else if (opts.start === "multi") {
        callback(null, {
          "package-e@1.0.0": { licenses: "(MIT OR GPL-3.0)" },
        });
      } else {
        callback(new Error("Unknown start path"), null);
      }
    }),
  },
}));

describe("checkLicenses", () => {
  const allowList = {
    allowedLicenses: ["MIT", "Apache-2.0"],
    exceptions: [{ package: "package-d@1.0.0", reason: "test", approvedBy: "test" }],
  };

  const allowListJson = JSON.stringify(allowList);

  it("passes when all licenses are allowed", async () => {
    const result = await checkLicenses("pass", allowListJson);
    expect(result.passed).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it("fails when a license is disallowed", async () => {
    const result = await checkLicenses("fail", allowListJson);
    expect(result.passed).toBe(false);
    expect(result.issues).toContain("Package package-c@1.0.0 has disallowed license(s): GPL-3.0");
  });

  it("passes when a disallowed license is in exceptions", async () => {
    const result = await checkLicenses("exception", allowListJson);
    expect(result.passed).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it("handles multi-license and passes if one is allowed", async () => {
    const result = await checkLicenses("multi", allowListJson);
    expect(result.passed).toBe(true);
    expect(result.issues).toHaveLength(0);
  });
});
