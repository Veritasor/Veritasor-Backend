import { describe, it, expect, vi } from "vitest";

// A valid X509Certificate always yields a Date-parseable `validTo`, so the
// unparseable-expiry branch is defensive and unreachable through real certs.
// Force it by mocking node:crypto's X509Certificate to expose an invalid date.
vi.mock("node:crypto", async () => {
  const actual =
    await vi.importActual<typeof import("node:crypto")>("node:crypto");
  class UnparseableExpiryCertificate {
    validTo = "not-a-parseable-date";
  }
  return {
    ...actual,
    X509Certificate:
      UnparseableExpiryCertificate as unknown as typeof actual.X509Certificate,
  };
});

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  responseToTlsMaterial,
  SpiffeMaterialError,
} from "../../../src/spiffe/svidProvider.js";
import type { WorkloadX509Response } from "../../../src/spiffe/types.js";

const fixtureDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../fixtures/spiffe",
);
const TEST_CERT = readFileSync(join(fixtureDir, "spiffe-test-cert.pem"));
const TEST_KEY = readFileSync(join(fixtureDir, "spiffe-test-key.pem"));
const TRUST_DOMAIN = "example.org";

describe("responseToTlsMaterial unparseable expiry", () => {
  it("throws SpiffeMaterialError when the certificate validTo is not a date", () => {
    const response: WorkloadX509Response = {
      svids: [
        {
          x509Svid: TEST_CERT,
          privateKey: TEST_KEY,
          spiffeId: `spiffe://${TRUST_DOMAIN}/backend`,
        },
      ],
      bundles: new Map([[TRUST_DOMAIN, { authorities: [TEST_CERT] }]]),
    };

    let caught: unknown;
    try {
      responseToTlsMaterial(response, TRUST_DOMAIN);
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(SpiffeMaterialError);
    const error = caught as SpiffeMaterialError;
    expect(error.name).toBe("SpiffeMaterialError");
    expect(error.message).toBe("Unable to parse SVID certificate expiry");
  });
});
