import { describe, it, expect, vi } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  convertCyclonedxToSpdx,
  computeSha256,
  parseCliArgs,
} from "../../scripts/generate-spdx";

const MINIMAL_CDX = JSON.stringify({
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  version: 1,
  metadata: {
    component: { name: "my-app", version: "1.0.0", licenses: [{ license: { id: "MIT" } }] },
    timestamp: "2024-01-01T00:00:00Z",
  },
  components: [
    {
      type: "library",
      name: "express",
      version: "4.18.2",
      purl: "pkg:npm/express@4.18.2",
      hashes: [{ alg: "SHA-512", value: "abc123" }],
      licenses: [{ license: { id: "MIT" } }],
      supplier: { name: "OpenJS Foundation" },
    },
    {
      type: "library",
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
      licenses: [{ license: { id: "MIT" } }],
    },
  ],
});

const CDX_NO_LICENSE = JSON.stringify({
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  version: 1,
  metadata: { component: { name: "no-license-app", version: "0.1.0" } },
  components: [],
});

const CDX_MULTI_LICENSE = JSON.stringify({
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  version: 1,
  metadata: { component: { name: "multi", version: "1.0" } },
  components: [
    {
      type: "library",
      name: "dual-licensed-pkg",
      version: "2.0.0",
      licenses: [
        { license: { id: "MIT" } },
        { license: { id: "Apache-2.0" } },
      ],
    },
  ],
});

const CDX_NO_COMPONENTS = JSON.stringify({
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  version: 1,
  metadata: { component: { name: "empty", version: "0.0.0", licenses: [{ license: { id: "MIT" } }] } },
});

// ─── convertCyclonedxToSpdx ───────────────────────────────────────────────────

describe("convertCyclonedxToSpdx", () => {
  it("produces valid SPDX JSON with the correct structure", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(MINIMAL_CDX));
    expect(result.spdxVersion).toBe("SPDX-2.3");
    expect(result.dataLicense).toBe("CC0-1.0");
    expect(result.SPDXID).toBe("SPDXRef-DOCUMENT");
    expect(result.name).toBe("my-app 1.0.0");
    expect(result.creationInfo.creators).toEqual(["Tool: veritasor-generate-spdx"]);
    expect(result.creationInfo.created).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it("maps the root package correctly", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(MINIMAL_CDX));
    const root = result.packages.find((p: { SPDXID: string }) => p.SPDXID === "SPDXRef-my-app");
    expect(root).toBeDefined();
    expect(root.name).toBe("my-app");
    expect(root.versionInfo).toBe("1.0.0");
    expect(root.filesAnalyzed).toBe(false);
    expect(root.licenseConcluded).toBe("MIT");
    expect(root.downloadLocation).toBe("NOASSERTION");
  });

  it("maps dependency packages with checksums and external refs", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(MINIMAL_CDX));
    const express = result.packages.find((p: { name: string }) => p.name === "express");
    expect(express).toBeDefined();
    expect(express.versionInfo).toBe("4.18.2");
    expect(express.checksums).toEqual([{ algorithm: "SHA512", value: "abc123" }]);
    expect(express.externalRefs).toEqual([
      { referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:npm/express@4.18.2" },
    ]);
    expect(express.supplier).toBe("OpenJS Foundation");
  });

  it("creates DEPENDS_ON and DESCRIBES relationships", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(MINIMAL_CDX));
    const describes = result.relationships.find(
      (r: { relationshipType: string }) => r.relationshipType === "DESCRIBES"
    );
    expect(describes).toBeDefined();
    expect(describes.spdxElementId).toBe("SPDXRef-DOCUMENT");
    expect(describes.relatedSpdxElement).toBe("SPDXRef-my-app");

    const dependsOn = result.relationships.filter(
      (r: { relationshipType: string }) => r.relationshipType === "DEPENDS_ON"
    );
    expect(dependsOn.length).toBe(2);
    expect(dependsOn[0].spdxElementId).toBe("SPDXRef-my-app");
  });

  it("sets NOASSERTION when no license info is present", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(CDX_NO_LICENSE));
    const root = result.packages.find((p: { SPDXID: string }) => p.SPDXID === "SPDXRef-no-license-app");
    expect(root.licenseConcluded).toBe("NOASSERTION");
    expect(root.licenseDeclared).toBe("NOASSERTION");
  });

  it("handles AND compound licenses", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(CDX_MULTI_LICENSE));
    const pkg = result.packages.find((p: { name: string }) => p.name === "dual-licensed-pkg");
    expect(pkg.licenseConcluded).toBe("(MIT AND Apache-2.0)");
  });

  it("works with no components array", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(CDX_NO_COMPONENTS));
    expect(result.packages).toHaveLength(1);
    expect(result.relationships).toHaveLength(1);
    expect(result.relationships[0].relationshipType).toBe("DESCRIBES");
  });

  it("generates unique SPDXIDs for different packages", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(MINIMAL_CDX));
    const ids = result.packages.map((p: { SPDXID: string }) => p.SPDXID);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("handles components without hashes gracefully", () => {
    const result = JSON.parse(convertCyclonedxToSpdx(MINIMAL_CDX));
    const lodash = result.packages.find((p: { name: string }) => p.name === "lodash");
    expect(lodash.checksums).toBeUndefined();
  });

  it("rejects invalid JSON input", () => {
    expect(() => convertCyclonedxToSpdx("not-json")).toThrow();
  });
});

// ─── computeSha256 ────────────────────────────────────────────────────────────

describe("computeSha256", () => {
  it("computes the well-known digest of an empty string", () => {
    expect(computeSha256("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("is deterministic for the same input", () => {
    expect(computeSha256("hello")).toBe(computeSha256("hello"));
  });

  it("produces different hashes for different inputs", () => {
    expect(computeSha256("a")).not.toBe(computeSha256("b"));
  });
});

// ─── parseCliArgs ─────────────────────────────────────────────────────────────

describe("parseCliArgs", () => {
  it("parses --input and --output", () => {
    expect(parseCliArgs(["--input", "in.json", "--output", "out.json"])).toEqual({
      input: "in.json",
      output: "out.json",
    });
  });

  it("returns empty object when no args given", () => {
    expect(parseCliArgs([])).toEqual({});
  });

  it("throws on unknown flags", () => {
    expect(() => parseCliArgs(["--unknown", "x"])).toThrow(/Unknown argument/);
  });
});
