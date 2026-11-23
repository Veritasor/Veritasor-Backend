/**
 * Generate an aggregated third-party NOTICES bundle from installed npm packages.
 *
 * Usage:
 *   tsx scripts/generate-notices.ts [--output <path>] [--check]
 *
 * --output  Path to write the bundle (default: docs/legal/NOTICES.md)
 * --check   Exit 1 if the on-disk file differs from the freshly generated content
 *           (used in CI to detect stale bundles).
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const DEFAULT_OUTPUT = "docs/legal/NOTICES.md";

export interface PackageNotice {
  name: string;
  version: string;
  license: string;
  licenseText: string | null;
  repository: string | null;
}

export interface GenerateNoticesOptions {
  output: string;
  check?: boolean;
  cwd?: string;
}

export interface CliArgs {
  output: string;
  check: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function parseCliArgs(argv: string[]): CliArgs {
  let output = DEFAULT_OUTPUT;
  let check = false;
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--output": {
        const val = argv[++i];
        if (!val || val.startsWith("--")) throw new Error("--output requires a file path");
        output = val;
        break;
      }
      case "--check":
        check = true;
        break;
      default:
        throw new Error(`Unknown argument: ${argv[i]}`);
    }
  }
  return { output, check };
}

export async function runChecker(startPath: string): Promise<Record<string, any>> {
  // Dynamic import keeps license-checker (CJS) out of the module graph at load
  // time, so tests that don't exercise this path can import the module cleanly.
  const checker = (await import("license-checker")).default;
  return new Promise((res, rej) => {
    checker.init(
      { start: startPath, production: true, excludePrivatePackages: true },
      (err: Error | null, packages: Record<string, any>) =>
        err ? rej(err) : res(packages),
    );
  });
}

export async function readLicenseText(licenseFile: string | undefined): Promise<string | null> {
  if (!licenseFile || !existsSync(licenseFile)) return null;
  try {
    return await readFile(licenseFile, "utf8");
  } catch {
    return null;
  }
}

export function normalizePackages(raw: Record<string, any>): PackageNotice[] {
  const notices: PackageNotice[] = [];
  for (const [nameVersion, info] of Object.entries(raw)) {
    const atIdx = nameVersion.lastIndexOf("@");
    const name = atIdx > 0 ? nameVersion.slice(0, atIdx) : nameVersion;
    const version = atIdx > 0 ? nameVersion.slice(atIdx + 1) : "unknown";
    const license =
      typeof info.licenses === "string"
        ? info.licenses
        : Array.isArray(info.licenses)
          ? (info.licenses as string[]).join(", ")
          : "UNKNOWN";
    notices.push({
      name,
      version,
      license,
      licenseText: null,
      repository: typeof info.repository === "string" ? info.repository : null,
    });
  }
  return notices.sort((a, b) => a.name.localeCompare(b.name));
}

export async function collectNotices(raw: Record<string, any>): Promise<PackageNotice[]> {
  const base = normalizePackages(raw);
  return Promise.all(
    base.map(async (pkg) => {
      const key = Object.keys(raw).find((k) => {
        const atIdx = k.lastIndexOf("@");
        return (
          (atIdx > 0 ? k.slice(0, atIdx) : k) === pkg.name &&
          (atIdx > 0 ? k.slice(atIdx + 1) : "unknown") === pkg.version
        );
      });
      const licenseFile = key ? raw[key]?.licenseFile : undefined;
      return { ...pkg, licenseText: await readLicenseText(licenseFile) };
    }),
  );
}

export function renderNotices(notices: PackageNotice[], generatedAt: string): string {
  const lines: string[] = [
    "# Third-Party Notices",
    "",
    "This file is auto-generated. Do not edit manually.",
    `Generated: ${generatedAt}`,
    "",
    "This product includes software developed by third parties.",
    "The following packages are used under the terms of their respective licenses.",
    "",
    "---",
    "",
  ];

  for (const pkg of notices) {
    lines.push(`## ${pkg.name} @ ${pkg.version}`);
    lines.push("");
    lines.push(`License: ${pkg.license}`);
    if (pkg.repository) lines.push(`Repository: ${pkg.repository}`);
    lines.push("");
    if (pkg.licenseText) {
      lines.push("```");
      lines.push(pkg.licenseText.trim());
      lines.push("```");
    } else {
      lines.push("*License text not available. See package repository for details.*");
    }
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

export async function generateNotices(
  options: GenerateNoticesOptions,
  _runChecker = runChecker,
): Promise<{ output: string; content: string; stale?: boolean }> {
  const cwd = options.cwd ?? process.cwd();
  const outputPath = resolve(cwd, options.output);

  const raw = await _runChecker(cwd);
  const notices = await collectNotices(raw);
  const content = renderNotices(notices, new Date().toISOString());

  if (options.check) {
    let existing: string | null = null;
    try {
      existing = await readFile(outputPath, "utf8");
    } catch {
      // file missing → stale
    }
    const strip = (s: string) => s.replace(/^Generated: .+$/m, "Generated: <timestamp>");
    const stale = existing === null || strip(existing) !== strip(content);
    return { output: outputPath, content, stale };
  }

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, content, "utf8");
  return { output: outputPath, content };
}

async function main(): Promise<void> {
  const args = parseCliArgs(process.argv.slice(2));
  const result = await generateNotices({ output: args.output, check: args.check });

  if (args.check) {
    if (result.stale) {
      console.error(
        `NOTICES bundle is stale. Run \`npm run notices:generate\` and commit the result.\n` +
          `Expected file: ${result.output}`,
      );
      process.exitCode = 1;
    } else {
      console.log("NOTICES bundle is up-to-date.");
    }
    return;
  }

  console.log(`NOTICES bundle written to ${result.output}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err: unknown) => {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  });
}
