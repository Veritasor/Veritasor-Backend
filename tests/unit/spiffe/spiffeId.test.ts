import { describe, it, expect } from "vitest";
import {
  extractSpiffeIdFromCert,
  isSpiffeIdInTrustDomain,
  parseSpiffeIdAllowlist,
} from "../../../src/spiffe/spiffeId.js";

describe("spiffeId helpers", () => {
  it("validates SPIFFE IDs against a trust domain", () => {
    expect(isSpiffeIdInTrustDomain("spiffe://example.org/api", "example.org")).toBe(true);
    expect(isSpiffeIdInTrustDomain("spiffe://other.org/api", "example.org")).toBe(false);
    expect(isSpiffeIdInTrustDomain("spiffe://example.org/api", "")).toBe(false);
  });

  it("extracts a matching SPIFFE ID from certificate SAN entries", () => {
    const cert = {
      subjectaltname:
        "DNS:legacy.example.org, URI:spiffe://example.org/backend/api, URI:spiffe://other.org/ignored",
    } as import("node:tls").PeerCertificate;

    expect(extractSpiffeIdFromCert(cert, "example.org")).toBe(
      "spiffe://example.org/backend/api",
    );
  });

  it("returns undefined when no SPIFFE ID matches the trust domain", () => {
    const cert = {
      subjectaltname: "URI:spiffe://other.org/service",
    } as import("node:tls").PeerCertificate;

    expect(extractSpiffeIdFromCert(cert, "example.org")).toBeUndefined();
  });

  it("parses comma-separated SPIFFE ID allowlists", () => {
    expect(parseSpiffeIdAllowlist(" spiffe://example.org/a , spiffe://example.org/b "))
      .toEqual(["spiffe://example.org/a", "spiffe://example.org/b"]);
    expect(parseSpiffeIdAllowlist(undefined)).toEqual([]);
  });

  it("returns undefined when the certificate has no SAN entries", () => {
    const cert = {} as import("node:tls").PeerCertificate;
    expect(extractSpiffeIdFromCert(cert, "example.org")).toBeUndefined();
  });
});
