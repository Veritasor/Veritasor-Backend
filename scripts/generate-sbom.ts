/** Generate a CycloneDX JSON SBOM for the complete npm dependency graph. */
import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
export const DEFAULT_OUTPUT = "sbom/cyclonedx-sbom.json";

export interface GenerateSbomOptions { output: string; cwd?: string; }
export interface GeneratedSbom { output: string; sha256: string; }
interface CycloneDxBom { bomFormat?: unknown; components?: unknown; metadata?: { component?: unknown }; }

export function parseCliArgs(argv: string[]): GenerateSbomOptions {
  let output = DEFAULT_OUTPUT;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== "--output") throw new Error(`Unknown argument: ${argv[index]}`);
    const value = argv[++index];
    if (!value || value.startsWith("--")) throw new Error("--output requires a file path");
    output = value;
  }
  return { output };
}

export function sha256(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

export function validateCycloneDxBom(content: Buffer): void {
  let bom: CycloneDxBom;
  try { bom = JSON.parse(content.toString("utf8")) as CycloneDxBom; }
  catch { throw new Error("CycloneDX generator produced invalid JSON"); }
  if (bom.bomFormat !== "CycloneDX") throw new Error("CycloneDX generator output is missing bomFormat: CycloneDX");
  if (!bom.metadata?.component || typeof bom.metadata.component !== "object") {
    throw new Error("CycloneDX generator output is missing the root component metadata");
  }
  const component = bom.metadata.component as { name?: unknown; version?: unknown };
  if (typeof component.name !== "string" || component.name.length === 0 ||
      typeof component.version !== "string" || component.version.length === 0) {
    throw new Error("CycloneDX generator output has incomplete root component metadata");
  }
  if (!Array.isArray(bom.components)) throw new Error("CycloneDX generator output is missing dependency components");
}

export async function generateSbom(options: GenerateSbomOptions, run = execFile): Promise<GeneratedSbom> {
  const cwd = options.cwd ?? process.cwd();
  const output = resolve(cwd, options.output);
  await mkdir(dirname(output), { recursive: true });
  await run("npx", ["--no-install", "@cyclonedx/cyclonedx-npm", "--output-format", "JSON", "--output-reproducible", "--output-file", output], { cwd, windowsHide: true });
  const content = await readFile(output);
  validateCycloneDxBom(content);
  const digest = sha256(content);
  await writeFile(`${output}.sha256`, `${digest}  ${output.split(/[\\/]/).pop()}\n`, "utf8");
  return { output, sha256: digest };
}

export async function runGenerateSbomCli(argv: string[]): Promise<GeneratedSbom> {
  const generated = await generateSbom(parseCliArgs(argv));
  process.stdout.write(`${generated.sha256}  ${generated.output}\n`);
  return generated;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  runGenerateSbomCli(process.argv.slice(2)).catch((error: unknown) => {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}
