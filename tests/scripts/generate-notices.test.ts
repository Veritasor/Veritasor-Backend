import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseCliArgs,
  normalizePackages,
  renderNotices,
  generateNotices,
  type PackageNotice,
} from "../../scripts/generate-notices";

// ---------------------------------------------------------------------------
// parseCliArgs
// ---------------------------------------------------------------------------
describe("parseCliArgs", () => {
  it("returns defaults when no args given", () => {
    expect(parseCliArgs([])).toEqual({ output: "docs/legal/NOTICES.md", check: false });
  });

  it("parses --output", () => {
    expect(parseCliArgs(["--output", "out/NOTICES.md"])).toMatchObject({ output: "out/NOTICES.md" });
  });

  it("parses --check", () => {
    expect(parseCliArgs(["--check"])).toMatchObject({ check: true });
  });

  it("parses --output and --check together", () => {
    expect(parseCliArgs(["--output", "x.md", "--check"])).toEqual({ output: "x.md", check: true });
  });

  it("throws on --output without value", () => {
    expect(() => parseCliArgs(["--output"])).toThrow("--output requires a file path");
  });

  it("throws on --output followed by another flag", () => {
    expect(() => parseCliArgs(["--output", "--check"])).toThrow("--output requires a file path");
  });

  it("throws on unknown argument", () => {
    expect(() => parseCliArgs(["--unknown"])).toThrow("Unknown argument: --unknown");
  });
});

// ---------------------------------------------------------------------------
// normalizePackages
// ---------------------------------------------------------------------------
describe("normalizePackages", () => {
  it("splits name and version correctly", () => {
    const result = normalizePackages({ "express@4.18.0": { licenses: "MIT" } as any });
    expect(result[0]).toMatchObject({ name: "express", version: "4.18.0", license: "MIT" });
  });

  it("handles scoped packages (@scope/pkg@version)", () => {
    const result = normalizePackages({ "@scope/pkg@1.0.0": { licenses: "Apache-2.0" } as any });
    expect(result[0]).toMatchObject({ name: "@scope/pkg", version: "1.0.0", license: "Apache-2.0" });
  });

  it("joins array licenses with comma", () => {
    const result = normalizePackages({ "dual@1.0.0": { licenses: ["MIT", "BSD-2-Clause"] } as any });
    expect(result[0].license).toBe("MIT, BSD-2-Clause");
  });

  it("falls back to UNKNOWN when licenses is missing", () => {
    const result = normalizePackages({ "nolic@1.0.0": {} as any });
    expect(result[0].license).toBe("UNKNOWN");
  });

  it("extracts repository string", () => {
    const result = normalizePackages({
      "pkg@1.0.0": { licenses: "MIT", repository: "https://github.com/org/pkg" } as any,
    });
    expect(result[0].repository).toBe("https://github.com/org/pkg");
  });

  it("sets repository to null when not a string", () => {
    const result = normalizePackages({ "pkg@1.0.0": { licenses: "MIT", repository: { url: "x" } } as any });
    expect(result[0].repository).toBeNull();
  });

  it("sorts packages alphabetically by name", () => {
    const result = normalizePackages({
      "zlib@1.0.0": { licenses: "MIT" } as any,
      "alib@1.0.0": { licenses: "MIT" } as any,
    });
    expect(result[0].name).toBe("alib");
    expect(result[1].name).toBe("zlib");
  });

  it("handles empty input", () => {
    expect(normalizePackages({})).toEqual([]);
  });

  it("sets licenseText to null (filled later by collectNotices)", () => {
    const result = normalizePackages({ "pkg@1.0.0": { licenses: "MIT" } as any });
    expect(result[0].licenseText).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// renderNotices
// ---------------------------------------------------------------------------
describe("renderNotices", () => {
  const ts = "2025-01-01T00:00:00.000Z";

  it("includes the header and timestamp", () => {
    const out = renderNotices([], ts);
    expect(out).toContain("# Third-Party Notices");
    expect(out).toContain(`Generated: ${ts}`);
    expect(out).toContain("auto-generated");
  });

  it("renders a package entry with license text", () => {
    const notices: PackageNotice[] = [
      {
        name: "express",
        version: "4.18.0",
        license: "MIT",
        licenseText: "MIT License\n...",
        repository: "https://github.com/expressjs/express",
      },
    ];
    const out = renderNotices(notices, ts);
    expect(out).toContain("## express @ 4.18.0");
    expect(out).toContain("License: MIT");
    expect(out).toContain("Repository: https://github.com/expressjs/express");
    expect(out).toContain("MIT License");
    expect(out).toContain("```");
  });

  it("renders fallback text when licenseText is null", () => {
    const notices: PackageNotice[] = [
      { name: "pkg", version: "1.0.0", license: "ISC", licenseText: null, repository: null },
    ];
    const out = renderNotices(notices, ts);
    expect(out).toContain("*License text not available");
    expect(out).not.toContain("Repository:");
  });

  it("omits repository line when repository is null", () => {
    const notices: PackageNotice[] = [
      { name: "pkg", version: "1.0.0", license: "MIT", licenseText: "text", repository: null },
    ];
    const out = renderNotices(notices, ts);
    expect(out).not.toContain("Repository:");
  });

  it("renders multiple packages separated by ---", () => {
    const notices: PackageNotice[] = [
      { name: "a", version: "1.0.0", license: "MIT", licenseText: null, repository: null },
      { name: "b", version: "2.0.0", license: "Apache-2.0", licenseText: null, repository: null },
    ];
    const out = renderNotices(notices, ts);
    expect(out).toContain("## a @ 1.0.0");
    expect(out).toContain("## b @ 2.0.0");
    expect((out.match(/^---$/gm) ?? []).length).toBeGreaterThanOrEqual(2);
  });

  it("renders empty package list without package entries", () => {
    const out = renderNotices([], ts);
    expect(out).toContain("# Third-Party Notices");
    expect(out).not.toContain("##");
  });

  it("trims license text before rendering", () => {
    const notices: PackageNotice[] = [
      { name: "pkg", version: "1.0.0", license: "MIT", licenseText: "  MIT text  \n", repository: null },
    ];
    const out = renderNotices(notices, ts);
    expect(out).toContain("MIT text");
    // Should not have leading/trailing whitespace inside the code block
    expect(out).not.toMatch(/```\n\s+MIT text/);
  });
});

// ---------------------------------------------------------------------------
// generateNotices (integration-style with mocked checker, real FS via tmpdir)
// ---------------------------------------------------------------------------
describe("generateNotices", () => {
  const makeChecker = (packages: Record<string, any>) =>
    vi.fn().mockResolvedValue(packages);

  it("writes NOTICES.md to the specified output path", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = makeChecker({ "express@4.18.0": { licenses: "MIT" } });
    const result = await generateNotices({ output: "docs/legal/NOTICES.md", cwd }, checker);
    expect(result.output).toContain("NOTICES.md");
    expect(result.content).toContain("## express @ 4.18.0");
    const written = await readFile(result.output, "utf8");
    expect(written).toBe(result.content);
  });

  it("creates parent directories if they do not exist", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = makeChecker({});
    const result = await generateNotices({ output: "deep/nested/NOTICES.md", cwd }, checker);
    const written = await readFile(result.output, "utf8");
    expect(written).toContain("# Third-Party Notices");
  });

  it("returns stale=true in check mode when file is missing", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = makeChecker({ "pkg@1.0.0": { licenses: "MIT" } });
    const result = await generateNotices({ output: "docs/legal/NOTICES.md", check: true, cwd }, checker);
    expect(result.stale).toBe(true);
  });

  it("returns stale=false in check mode when content matches (ignoring timestamp)", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const packages = { "pkg@1.0.0": { licenses: "MIT" } };

    // Write first
    await generateNotices({ output: "docs/legal/NOTICES.md", cwd }, makeChecker(packages));

    // Check — should be up-to-date
    const result = await generateNotices(
      { output: "docs/legal/NOTICES.md", check: true, cwd },
      makeChecker(packages),
    );
    expect(result.stale).toBe(false);
  });

  it("returns stale=true in check mode when packages changed", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));

    await generateNotices(
      { output: "docs/legal/NOTICES.md", cwd },
      makeChecker({ "pkg@1.0.0": { licenses: "MIT" } }),
    );

    const result = await generateNotices(
      { output: "docs/legal/NOTICES.md", check: true, cwd },
      makeChecker({ "other@2.0.0": { licenses: "Apache-2.0" } }),
    );
    expect(result.stale).toBe(true);
  });

  it("includes license text when licenseFile exists on disk", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const licenseFile = join(cwd, "LICENSE");
    await writeFile(licenseFile, "MIT License text here");

    const checker = makeChecker({ "pkg@1.0.0": { licenses: "MIT", licenseFile } });
    const result = await generateNotices({ output: "NOTICES.md", cwd }, checker);
    expect(result.content).toContain("MIT License text here");
  });

  it("handles packages with no license gracefully", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = makeChecker({ "nolic@1.0.0": {} });
    const result = await generateNotices({ output: "NOTICES.md", cwd }, checker);
    expect(result.content).toContain("UNKNOWN");
    expect(result.content).toContain("*License text not available");
  });

  it("handles empty package list", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = makeChecker({});
    const result = await generateNotices({ output: "NOTICES.md", cwd }, checker);
    expect(result.content).toContain("# Third-Party Notices");
    expect(result.content).not.toContain("##");
  });

  it("propagates checker errors", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = vi.fn().mockRejectedValue(new Error("checker failed"));
    await expect(generateNotices({ output: "NOTICES.md", cwd }, checker)).rejects.toThrow("checker failed");
  });

  it("handles missing licenseFile path gracefully (null text)", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    // licenseFile points to a non-existent path
    const checker = makeChecker({
      "pkg@1.0.0": { licenses: "MIT", licenseFile: join(cwd, "nonexistent-LICENSE") },
    });
    const result = await generateNotices({ output: "NOTICES.md", cwd }, checker);
    expect(result.content).toContain("*License text not available");
  });

  it("does not write file in check mode", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = makeChecker({ "pkg@1.0.0": { licenses: "MIT" } });
    await generateNotices({ output: "NOTICES.md", check: true, cwd }, checker);
    // File should not exist since we only checked
    await expect(readFile(join(cwd, "NOTICES.md"), "utf8")).rejects.toThrow();
  });

  it("sorts packages alphabetically in output", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "notices-test-"));
    const checker = makeChecker({
      "zpackage@1.0.0": { licenses: "MIT" },
      "apackage@1.0.0": { licenses: "MIT" },
    });
    const result = await generateNotices({ output: "NOTICES.md", cwd }, checker);
    const aIdx = result.content.indexOf("## apackage");
    const zIdx = result.content.indexOf("## zpackage");
    expect(aIdx).toBeLessThan(zIdx);
  });
});
