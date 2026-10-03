import { readFile } from "fs/promises";
import { resolve } from "path";
import { pathToFileURL } from "url";

type AllowlistSeverity = "low" | "moderate" | "high" | "critical";

interface AllowlistEntry {
  id: string;
  package: string;
  severity: AllowlistSeverity;
  reason: string;
  expires: string;
}

interface Advisory {
  id: string;
  package: string;
  severity: AllowlistSeverity;
  title?: string;
  url?: string;
}

const ALLOWLIST_PATH = new URL("../.audit-allowlist.json", import.meta.url);

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

function normalizeSeverity(value: unknown): AllowlistSeverity {
  const normalized = String(value).trim().toLowerCase();
  if (!["low", "moderate", "high", "critical"].includes(normalized)) {
    throw new Error(`Invalid severity value: ${String(value)}`);
  }
  return normalized as AllowlistSeverity;
}

function parseAllowlist(rawAllowlist: unknown): AllowlistEntry[] {
  if (!Array.isArray(rawAllowlist)) {
    throw new Error("Allowlist file must contain a JSON array.");
  }

  return rawAllowlist.map((entry, index) => {
    if (entry == null || typeof entry !== "object") {
      throw new Error(`Allowlist entry ${index} must be an object.`);
    }

    const id = String((entry as any).id ?? "").trim();
    const packageName = String((entry as any).package ?? "").trim();
    const severity = normalizeSeverity((entry as any).severity);
    const reason = String((entry as any).reason ?? "").trim();
    const expires = String((entry as any).expires ?? "").trim();

    if (!id) {
      throw new Error(`Allowlist entry ${index} is missing required field "id".`);
    }
    if (!packageName) {
      throw new Error(`Allowlist entry ${index} is missing required field "package".`);
    }
    if (!reason) {
      throw new Error(`Allowlist entry ${index} is missing required field "reason".`);
    }
    if (!expires) {
      throw new Error(`Allowlist entry ${index} is missing required field "expires".`);
    }

    const expiresDate = new Date(expires);
    if (Number.isNaN(expiresDate.getTime())) {
      throw new Error(`Allowlist entry ${index} has invalid ISO expiration date: ${expires}`);
    }

    return {
      id,
      package: packageName,
      severity,
      reason,
      expires,
    };
  });
}

function fromAuditAdvisories(rawReport: any): Advisory[] {
  if (rawReport?.advisories && typeof rawReport.advisories === "object") {
    return Object.values(rawReport.advisories).map((advisory) => {
      const id = String(advisory.id ?? advisory.module_name ?? "");
      const packageName = String(advisory.module_name ?? advisory.package ?? "");
      const severity = normalizeSeverity(advisory.severity ?? "");
      return {
        id,
        package: packageName,
        severity,
        title: advisory.title,
        url: advisory.url,
      };
    });
  }

  if (rawReport?.vulnerabilities && typeof rawReport.vulnerabilities === "object") {
    const vulnerabilities = rawReport.vulnerabilities as Record<string, any>;
    return Object.entries(vulnerabilities).flatMap(([packageName, details]) => {
      if (!details || typeof details !== "object" || !Array.isArray(details.via)) {
        return [];
      }

      return details.via
        .filter((via) => via && typeof via === "object" && typeof via.id !== "undefined")
        .map((via) => ({
          id: String(via.id),
          package: String(via.module_name ?? via.package ?? packageName),
          severity: normalizeSeverity(via.severity ?? ""),
          title: via.title,
          url: via.url,
        }));
    });
  }

  return [];
}

function allowlistMatches(advisory: Advisory, allowlist: AllowlistEntry[], now: Date): boolean {
  return allowlist.some((entry) => {
    const expiresDate = new Date(entry.expires);
    if (Number.isNaN(expiresDate.getTime())) {
      return false;
    }

    if (expiresDate < now) {
      return false;
    }

    return (
      entry.id === advisory.id &&
      entry.package === advisory.package &&
      entry.severity === advisory.severity
    );
  });
}

function formatAdvisory(advisory: Advisory): string {
  return `- [${advisory.severity.toUpperCase()}] ${advisory.package} (advisory ${advisory.id})${advisory.title ? `: ${advisory.title}` : ""}`;
}

async function main(): Promise<void> {
  const input = process.argv[2]
    ? await readFile(pathToFileURL(resolve(process.cwd(), process.argv[2])).pathname, "utf8")
    : await readStdin();

  if (!input.trim()) {
    throw new Error("No audit JSON input was provided to scripts/check-audit.ts.");
  }

  const rawReport = JSON.parse(input);
  const advisories = fromAuditAdvisories(rawReport);
  const allowlist = parseAllowlist(JSON.parse(await readFile(ALLOWLIST_PATH, "utf8")));
  const now = new Date();

  const highCritical = advisories.filter((advisory) => ["high", "critical"].includes(advisory.severity));
  const unapproved = highCritical.filter((advisory) => !allowlistMatches(advisory, allowlist, now));

  if (unapproved.length === 0) {
    return;
  }

  console.error("Detected non-allowlisted high/critical npm advisories:\n");
  for (const advisory of unapproved) {
    console.error(formatAdvisory(advisory));
  }

  console.error(
    "\nAdd an allowlist entry to .audit-allowlist.json or update an existing entry with an ISO 8601 expiration date. Expired entries are rejected."
  );
  process.exit(1);
}

main().catch((error) => {
  console.error(`Error validating audit report: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});