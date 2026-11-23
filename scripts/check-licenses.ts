import checker from "license-checker";
import { readFile } from "fs/promises";
import { resolve } from "path";
import { pathToFileURL } from "url";

export interface AllowList {
  allowedLicenses: string[];
  exceptions: Array<{ package: string; reason: string; approvedBy: string }>;
}

export function runChecker(startPath: string): Promise<Record<string, any>> {
  return new Promise((resolve, reject) => {
    checker.init({ start: startPath, production: true }, (err: Error, packages: any) => {
      if (err) {
        reject(err);
      } else {
        resolve(packages);
      }
    });
  });
}

export async function checkLicenses(startDir: string, allowListJson: string): Promise<{ issues: string[]; passed: boolean }> {
  const allowList: AllowList = JSON.parse(allowListJson);
  const packages = await runChecker(startDir);
  const issues: string[] = [];

  for (const [pkgNameVersion, info] of Object.entries(packages)) {
    let licenses: string[] = [];
    if (typeof info.licenses === "string") {
      licenses = [info.licenses];
    } else if (Array.isArray(info.licenses)) {
      licenses = info.licenses as string[];
    } else {
      issues.push(`Package ${pkgNameVersion} has no license information.`);
      continue;
    }

    let isAllowed = false;
    for (const allowed of allowList.allowedLicenses) {
      if (licenses.some(l => l.includes(allowed))) {
        isAllowed = true;
        break;
      }
    }

    const isException = allowList.exceptions.some(
      e => e.package === pkgNameVersion || pkgNameVersion.startsWith(e.package + "@")
    );

    if (!isAllowed && !isException) {
      issues.push(`Package ${pkgNameVersion} has disallowed license(s): ${licenses.join(", ")}`);
    }
  }

  return { issues, passed: issues.length === 0 };
}

async function main(): Promise<void> {
  const allowListPath = resolve(process.cwd(), "allow-list.json");
  const allowListJson = await readFile(allowListPath, "utf8");

  const { issues, passed } = await checkLicenses(process.cwd(), allowListJson);

  if (passed) {
    console.log("All dependencies have allowed licenses!");
    process.exit(0);
  } else {
    console.error("Detected license policy violations:\n");
    for (const issue of issues) {
      console.error(issue);
    }
    console.error(
      "\nTo resolve, either swap the dependency for an alternative with an allowed license, or add an exception to allow-list.json."
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
