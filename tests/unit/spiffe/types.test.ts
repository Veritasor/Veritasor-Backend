import { describe, expect, it } from "vitest";
import type {
  WorkloadX509Response,
  X509BundleRecord,
  X509SvidRecord,
} from "../../../src/spiffe/types.js";

const CERT = Buffer.from("certificate");
const KEY = Buffer.from("private-key");
const CA = Buffer.from("authority");
const SPIFFE_ID = "spiffe://example.org/backend";
const TRUST_DOMAIN = "example.org";

function createSvid(spiffeId = SPIFFE_ID): X509SvidRecord {
  return {
    x509Svid: CERT,
    privateKey: KEY,
    spiffeId,
  };
}

function createBundle(): X509BundleRecord {
  return {
    authorities: [CA],
  };
}

function createResponse(
  svids: X509SvidRecord[] = [],
  bundles: Map<string, X509BundleRecord> = new Map(),
): WorkloadX509Response {
  return { svids, bundles };
}

describe("SPIFFE record type contracts", () => {
  it("represents a complete X509SvidRecord", () => {
    const record = createSvid();

    expect(record).toEqual({
      x509Svid: CERT,
      privateKey: KEY,
      spiffeId: SPIFFE_ID,
    });
    expect(Buffer.isBuffer(record.x509Svid)).toBe(true);
    expect(Buffer.isBuffer(record.privateKey)).toBe(true);
  });

  it("supports an empty authority boundary and multiple authorities in X509BundleRecord", () => {
    const emptyBundle: X509BundleRecord = { authorities: [] };
    const populatedBundle: X509BundleRecord = {
      authorities: [CA, Buffer.from("second-authority")],
    };

    expect(emptyBundle.authorities).toHaveLength(0);
    expect(populatedBundle.authorities).toHaveLength(2);
    expect(populatedBundle.authorities[0]).toBe(CA);
  });

  it("represents an empty WorkloadX509Response boundary", () => {
    const response = createResponse();

    expect(response.svids).toEqual([]);
    expect(response.bundles).toBeInstanceOf(Map);
    expect(response.bundles.size).toBe(0);
  });

  it("models the response transition from empty to issued material", () => {
    let response = createResponse();

    response = createResponse(
      [createSvid()],
      new Map([[TRUST_DOMAIN, createBundle()]]),
    );

    expect(response.svids).toHaveLength(1);
    expect(response.svids[0]?.spiffeId).toBe(SPIFFE_ID);
    expect(response.bundles.get(TRUST_DOMAIN)?.authorities).toEqual([CA]);
  });

  it("models a deterministic SVID rotation while preserving the trust bundle", () => {
    let response = createResponse(
      [createSvid()],
      new Map([[TRUST_DOMAIN, createBundle()]]),
    );

    const rotatedId = `${SPIFFE_ID}/rotated`;
    response = createResponse(
      [createSvid(rotatedId)],
      response.bundles,
    );

    expect(response.svids).toHaveLength(1);
    expect(response.svids[0]?.spiffeId).toBe(rotatedId);
    expect(response.bundles.get(TRUST_DOMAIN)?.authorities).toEqual([CA]);
  });

  it("rejects representative invalid record shapes at compile time", () => {
    const invalidSvid: X509SvidRecord = {
      /* @ts-expect-error x509Svid must be a Buffer */
      x509Svid: "certificate",
      privateKey: KEY,
      spiffeId: SPIFFE_ID,
    };

    const invalidBundle: X509BundleRecord = {
      /* @ts-expect-error authorities must be an array of Buffers */
      authorities: ["authority"],
    };

    const invalidResponse: WorkloadX509Response = {
      svids: [createSvid()],
      /* @ts-expect-error bundles must be a Map keyed by trust domain */
      bundles: {},
    };

    expect(invalidSvid).toBeDefined();
    expect(invalidBundle).toBeDefined();
    expect(invalidResponse).toBeDefined();
  });
});
