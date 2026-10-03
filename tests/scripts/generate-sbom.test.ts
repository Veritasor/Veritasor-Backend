import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { DEFAULT_OUTPUT, generateSbom, parseCliArgs, sha256, validateCycloneDxBom } from "../../scripts/generate-sbom";

const VALID_BOM = Buffer.from(JSON.stringify({ bomFormat: "CycloneDX", metadata: { component: { name: "veritasor-backend", version: "0.1.0" } }, components: [] }));

describe("generate-sbom", () => {
  it("uses the locked CycloneDX generator and writes a matching checksum", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "sbom-test-"));
    const runner = vi.fn(async (_command: string, args: string[]) => {
      await writeFile(args[args.indexOf("--output-file") + 1]!, VALID_BOM);
      return { stdout: "", stderr: "" };
    });
    const generated = await generateSbom({ output: "artifacts/bom.json", cwd }, runner);
    expect(runner).toHaveBeenCalledWith("npx", expect.arrayContaining(["--no-install", "@cyclonedx/cyclonedx-npm", "--output-reproducible"]), expect.objectContaining({ cwd, windowsHide: true }));
    expect(generated.sha256).toBe(sha256(VALID_BOM));
    expect(await readFile(`${generated.output}.sha256`, "utf8")).toBe(`${generated.sha256}  bom.json\n`);
  });
  it("rejects missing root metadata", () => {
    expect(() => validateCycloneDxBom(Buffer.from('{"bomFormat":"CycloneDX","components":[]}'))).toThrow(/root component metadata/);
    expect(() => validateCycloneDxBom(Buffer.from('{"bomFormat":"CycloneDX","metadata":{"component":{"name":"app"}},"components":[]}'))).toThrow(/incomplete root component metadata/);
  });
  it("rejects malformed or incomplete generator output", () => {
    expect(() => validateCycloneDxBom(Buffer.from("not-json"))).toThrow(/invalid JSON/);
    expect(() => validateCycloneDxBom(Buffer.from('{"bomFormat":"CycloneDX","metadata":{"component":{}}}'))).toThrow(/dependency components/);
  });
  it("parses the output option and rejects invalid flags", () => {
    expect(parseCliArgs([])).toEqual({ output: DEFAULT_OUTPUT });
    expect(parseCliArgs(["--output", "release/bom.json"])).toEqual({ output: "release/bom.json" });
    expect(() => parseCliArgs(["--output"])).toThrow(/requires a file path/);
    expect(() => parseCliArgs(["--unexpected"])).toThrow(/Unknown argument/);
  });
});
