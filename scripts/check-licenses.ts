import { readFile } from "fs/promises";
import { resolve } from "path";
import { pathToFileURL } from "url";
import { z } from "zod";

const PolicyModeSchema = z.enum(["denylist", "allowlist"]);
const OnUnlicensedSchema = z.enum(["fail", "warn", "ignore"]);

const ExceptionSchema = z.object({
  package: z.string(),
  versionRange: z.string().optional(),
  reason: z.string(),
  approvedBy: z.string(),
  expires: z.string().nullable(),
});

const PolicySchema = z.object({
  disallowed: z.array(z.string()),
  allowed: z.array(z.string()),
  exceptions: z.array(ExceptionSchema),
  mode: PolicyModeSchema,
  onUnlicensed: OnUnlicensedSchema,
});

type Policy = z.infer<typeof PolicySchema>;
type Exception = z.infer<typeof ExceptionSchema>;

const SPDXPackageSchema = z.object({
  name: z.string(),
  versionInfo: z.string().optional(),
  licenseConcluded: z.string().optional(),
  licenseDeclared: z.string().optional(),
});

const SPDXSchema = z.object({
  packages: z.array(SPDXPackageSchema),
});

type SPDXPackage = z.infer<typeof SPDXPackageSchema>;

const POLICY_PATH = new URL("../ops/license-policy.json", import.meta.url);

function tokenizeSpdxExpression(expr: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let depth = 0;

  for (const char of expr) {
    if (char === "(") {
      if (current.trim()) tokens.push(current.trim());
      current = "";
      tokens.push("(");
      depth++;
    } else if (char === ")") {
      if (current.trim()) tokens.push(current.trim());
      current = "";
      tokens.push(")");
      depth--;
    } else if ([" ", "\t", "\n"].includes(char)) {
      if (current.trim()) {
        tokens.push(current.trim());
        current = "";
      }
    } else {
      current += char;
    }
  }
  if (current.trim()) tokens.push(current.trim());
  return tokens;
}

function parseSpdxExpression(tokens: string[], start: number): { value: string | boolean | null; end: number } {
  const results: (string | boolean | null)[] = [];
  let op: "OR" | "AND" | null = null;
  let i = start;

  while (i < tokens.length) {
    const token = tokens[i];
    if (token === "(") {
      const sub = parseSpdxExpression(tokens, i + 1);
      results.push(sub.value);
      i = sub.end;
    } else if (token === ")") {
      i++;
      break;
    } else if (token === "OR" || token === "AND") {
      op = token;
      i++;
    } else {
      results.push(token);
      i++;
    }
  }

  if (results.length === 1) {
    return { value: results[0], end: i };
  } else if (op) {
    let result: string | boolean | null = results[0];
    for (let j = 1; j < results.length; j++) {
      if (op === "OR") {
        result = Boolean(result) || Boolean(results[j]);
      } else if (op === "AND") {
        result = Boolean(result) && Boolean(results[j]);
      }
    }
    return { value: result, end: i };
  }
  return { value: null, end: i };
}

function evaluateSpdxExpression(
  expr: string,
  policy: Policy,
  isAllowed: (license: string) => boolean,
  isDisallowed: (license: string) => boolean
): { allowed: boolean; disallowed: boolean; licenses: string[] } {
  const normalized = expr.trim();
  if (!normalized || normalized === "NOASSERTION" || normalized === "NONE") {
    return { allowed: false, disallowed: false, licenses: [] };
  }

  const tokens = tokenizeSpdxExpression(normalized);
  const { value } = parseSpdxExpression(tokens, 0);

  const licenses: string[] = [];
  for (const t of tokens) {
    if (t !== "(" && t !== ")" && t !== "OR" && t !== "AND") {
      licenses.push(t);
    }
  }

  const anyAllowed = licenses.some(isAllowed);
  const anyDisallowed = licenses.some(isDisallowed);

  if (policy.mode === "denylist") {
    return { allowed: !anyDisallowed, disallowed: anyDisallowed, licenses };
  } else {
    return { allowed: anyAllowed, disallowed: !anyAllowed, licenses };
  }
}

function getPackageLicenses(pkg: SPDXPackage): string[] {
  const licenses: string[] = [];
  if (pkg.licenseConcluded && pkg.licenseConcluded !== "NOASSERTION" && pkg.licenseConcluded !== "NONE") {
    licenses.push(pkg.licenseConcluded);
  }
  if (pkg.licenseDeclared && pkg.licenseDeclared !== "NOASSERTION" && pkg.licenseDeclared !== "NONE") {
    if (!licenses.includes(pkg.licenseDeclared)) {
      licenses.push(pkg.licenseDeclared);
    }
  }
  return licenses;
}

function isPackageExceptioned(pkg: SPDXPackage, exceptions: Exception[], now: Date): boolean {
  return exceptions.some((ex) => {
    if (ex.package !== pkg.name) return false;
    if (ex.expires) {
      const expiresDate = new Date(ex.expires);
      if (Number.isNaN(expiresDate.getTime())) return false;
      if (expiresDate < now) return false;
    }
    return true;
  });
}

function formatIssue(pkg: SPDXPackage, reason: string): string {
  return `- ${pkg.name}${pkg.versionInfo ? `@${pkg.versionInfo}` : ""}: ${reason}`;
}

async function readStdin(): Promise<string> {
  return new Promise((resolveStdin, reject) => {
    let stdin = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      stdin += chunk;
    });
    process.stdin.on("end", () => resolveStdin(stdin));
    process.stdin.on("error", reject);
  });
}

export async function checkLicenses(spdxJson: string, policy: Policy, now: Date = new Date()): Promise<{ issues: string[]; passed: boolean }> {
  const spdx = SPDXSchema.parse(JSON.parse(spdxJson));
  const issues: string[] = [];

  const isAllowed = (license: string) => policy.allowed.includes(license);
  const isDisallowed = (license: string) => policy.disallowed.includes(license);

  for (const pkg of spdx.packages) {
    if (isPackageExceptioned(pkg, policy.exceptions, now)) {
      continue;
    }

    const licenses = getPackageLicenses(pkg);
    if (licenses.length === 0) {
      if (policy.onUnlicensed === "fail") {
        issues.push(formatIssue(pkg, "no license information found"));
      }
      continue;
    }

    for (const licenseExpr of licenses) {
      const evaluation = evaluateSpdxExpression(licenseExpr, policy, isAllowed, isDisallowed);
      if (!evaluation.allowed) {
        issues.push(
          formatIssue(pkg, `license "${licenseExpr}" is disallowed (licenses evaluated: ${evaluation.licenses.join(", ")})`)
        );
      }
    }
  }

  return { issues, passed: issues.length === 0 };
}

async function main(): Promise<void> {
  const spdxJson = process.argv[2]
    ? await readFile(pathToFileURL(resolve(process.cwd(), process.argv[2])).pathname, "utf8")
    : await readStdin();

  const policyRaw = JSON.parse(await readFile(POLICY_PATH, "utf8"));
  const policy = PolicySchema.parse(policyRaw);
  const now = new Date();

  const { issues, passed } = await checkLicenses(spdxJson, policy, now);

  if (passed) {
    console.log("All dependencies have allowed licenses!");
    process.exit(0);
  } else {
    console.error("Detected license policy violations:\n");
    for (const issue of issues) {
      console.error(issue);
    }
    console.error(
      "\nTo resolve, either swap the dependency for an alternative with an allowed license, or add an exception to ops/license-policy.json (expiration date required unless permanent)."
    );
    process.exit(1);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`Error checking licenses: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
