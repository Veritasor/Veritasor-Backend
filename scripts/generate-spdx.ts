import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

interface CycloneDxComponent {
  type?: string;
  name: string;
  version?: string;
  "bom-ref"?: string;
  purl?: string;
  hashes?: { alg: string; value: string }[];
  licenses?: { license?: { id?: string; name?: string } }[];
  supplier?: { name?: string };
  description?: string;
}

interface CycloneDxMetadata {
  component?: CycloneDxComponent;
  timestamp?: string;
}

interface CycloneDxBom {
  bomFormat: string;
  specVersion: string;
  version: number;
  metadata?: CycloneDxMetadata;
  components?: CycloneDxComponent[];
}

interface SpdxCreationInfo {
  created: string;
  creators: string[];
  licenseListVersion?: string;
}

interface SpdxChecksum {
  algorithm: string;
  value: string;
}

interface SpdxExternalRef {
  referenceCategory: string;
  referenceType: string;
  referenceLocator: string;
}

interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo: string;
  filesAnalyzed: boolean;
  licenseConcluded: string;
  licenseDeclared: string;
  downloadLocation: string;
  checksums?: SpdxChecksum[];
  externalRefs?: SpdxExternalRef[];
  supplier?: string;
}

interface SpdxRelationship {
  spdxElementId: string;
  relatedSpdxElement: string;
  relationshipType: string;
}

interface SpdxDocument {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  creationInfo: SpdxCreationInfo;
  packages: SpdxPackage[];
  relationships: SpdxRelationship[];
}

function hashComponentName(name: string, version: string): string {
  const raw = `${name}@${version}`;
  return `SPDXRef-${createHash("sha256").update(raw).digest("hex").slice(0, 12)}`;
}

function toSpdxChecksum(hashes: { alg: string; value: string }[]): SpdxChecksum[] {
  const algMap: Record<string, string> = {
    "SHA-1": "SHA1",
    "SHA-256": "SHA256",
    "SHA-384": "SHA384",
    "SHA-512": "SHA512",
    "MD5": "MD5",
  };
  return hashes
    .filter((h) => algMap[h.alg])
    .map((h) => ({ algorithm: algMap[h.alg], value: h.value }));
}

function extractLicense(licenses?: { license?: { id?: string; name?: string } }[]): string {
  if (!licenses || licenses.length === 0) return "NOASSERTION";
  const ids = licenses
    .map((l) => l.license?.id || l.license?.name)
    .filter(Boolean);
  if (ids.length === 0) return "NOASSERTION";
  if (ids.length === 1) return ids[0]!;
  return `(${ids.join(" AND ")})`;
}

function toSpdxId(value: string): string {
  return `SPDXRef-${value.replace(/[^a-zA-Z0-9.-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "")}`;
}

export function convertCyclonedxToSpdx(cdxJson: string): string {
  const bom: CycloneDxBom = JSON.parse(cdxJson);

  const rootComponent = bom.metadata?.component;
  const components = bom.components ?? [];
  const rootName = rootComponent?.name ?? "unknown";
  const rootVersion = rootComponent?.version ?? "0.0.0";
  const documentName = `${rootName} ${rootVersion}`;
  const now = new Date().toISOString().replace(/\.\d+Z$/, "Z");

  const packages: SpdxPackage[] = [];
  const relationships: SpdxRelationship[] = [];

  const rootSpdxId = toSpdxId(rootName);
  packages.push({
    SPDXID: rootSpdxId,
    name: rootName,
    versionInfo: rootVersion,
    filesAnalyzed: false,
    licenseConcluded: rootComponent ? extractLicense(rootComponent.licenses) : "NOASSERTION",
    licenseDeclared: rootComponent ? extractLicense(rootComponent.licenses) : "NOASSERTION",
    downloadLocation: "NOASSERTION",
  });

  for (const comp of components) {
    const name = comp.name;
    const version = comp.version ?? "0.0.0";
    const spdxId = hashComponentName(name, version);

    packages.push({
      SPDXID: spdxId,
      name,
      versionInfo: version,
      filesAnalyzed: false,
      licenseConcluded: extractLicense(comp.licenses),
      licenseDeclared: extractLicense(comp.licenses),
      downloadLocation: "NOASSERTION",
      checksums: comp.hashes ? toSpdxChecksum(comp.hashes) : undefined,
      externalRefs: comp.purl
        ? [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: comp.purl }]
        : undefined,
      supplier: comp.supplier?.name,
    });

    relationships.push({
      spdxElementId: rootSpdxId,
      relatedSpdxElement: spdxId,
      relationshipType: "DEPENDS_ON",
    });
  }

  relationships.unshift({
    spdxElementId: "SPDXRef-DOCUMENT",
    relatedSpdxElement: rootSpdxId,
    relationshipType: "DESCRIBES",
  });

  const document: SpdxDocument = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: documentName,
    creationInfo: {
      created: now,
      creators: ["Tool: veritasor-generate-spdx"],
    },
    packages,
    relationships,
  };

  return JSON.stringify(document, null, 2);
}

export function computeSha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

interface CliArgs {
  input?: string;
  output?: string;
}

export function parseCliArgs(argv: string[]): CliArgs {
  const args: CliArgs = {};
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--input":
        args.input = argv[++i];
        break;
      case "--output":
        args.output = argv[++i];
        break;
      default:
        throw new Error(`Unknown argument: ${argv[i]}`);
    }
  }
  return args;
}

async function runGenerateSpdxCli(argv: string[]): Promise<void> {
  const args = parseCliArgs(argv);
  let input: string;
  if (args.input) {
    input = await readFile(resolve(args.input), "utf8");
  } else {
    input = await new Promise<string>((resolveStdin) => {
      let data = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => { data += chunk; });
      process.stdin.on("end", () => resolveStdin(data));
    });
  }

  const spdxJson = convertCyclonedxToSpdx(input);

  if (args.output) {
    await writeFile(resolve(args.output), spdxJson, "utf8");
  } else {
    process.stdout.write(spdxJson);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  runGenerateSpdxCli(process.argv.slice(2)).catch((err) => {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
