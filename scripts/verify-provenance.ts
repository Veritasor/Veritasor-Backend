/**
 * SLSA provenance verification gate (issue #565).
 *
 * Verifies that a SLSA v1 provenance attestation (in-toto DSSE envelope, as
 * produced by slsa-framework/slsa-github-generator) matches a release
 * artifact:
 *   - the envelope is well-formed and carries at least one signature,
 *   - the in-toto statement type and SLSA v1 predicate type are correct,
 *   - the artifact's SHA-256 digest is bound to a subject of the statement,
 *   - the builder identity is the expected slsa-github-generator workflow,
 *   - the provenance was built from the expected source repository.
 *
 * Scope: this script performs structural and digest-binding verification and
 * is used both in CI (defense-in-depth alongside slsa-verifier / cosign,
 * which perform the cryptographic signature + Rekor transparency-log checks)
 * and in unit tests. It intentionally does NOT re-implement Sigstore
 * signature verification.
 *
 * Usage:
 *   tsx scripts/verify-provenance.ts \
 *     --provenance dist-artifacts/app.intoto.jsonl \
 *     --artifact dist-artifacts/app.tgz \
 *     --source-repo github.com/aburex12345/Veritasor-Backend
 *
 * Exit codes: 0 verified, 1 verification failure or bad invocation.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";

// ─── constants ───────────────────────────────────────────────────────────────

export const IN_TOTO_STATEMENT_TYPES = new Set([
  "https://in-toto.io/Statement/v1",
  "https://in-toto.io/Statement/v0.1",
]);

export const SLSA_V1_PREDICATE_TYPE = "https://slsa.dev/provenance/v1";

export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";

/**
 * Trusted builder: the generic SLSA3 generator reusable workflow, pinned by
 * tag. Verification accepts any tagged release of this exact workflow path.
 */
export const EXPECTED_BUILDER_ID_PREFIX =
  "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/";

// ─── types ───────────────────────────────────────────────────────────────────

export type VerificationFailureCode =
  | "MALFORMED_ENVELOPE"
  | "UNSIGNED_ENVELOPE"
  | "BAD_PAYLOAD_TYPE"
  | "MALFORMED_STATEMENT"
  | "BAD_STATEMENT_TYPE"
  | "BAD_PREDICATE_TYPE"
  | "NO_SUBJECTS"
  | "SUBJECT_DIGEST_MISMATCH"
  | "BUILDER_MISMATCH"
  | "SOURCE_REPO_MISMATCH";

export class ProvenanceVerificationError extends Error {
  readonly code: VerificationFailureCode;

  constructor(code: VerificationFailureCode, message: string) {
    super(message);
    this.name = "ProvenanceVerificationError";
    this.code = code;
  }
}

export interface DsseEnvelope {
  payload: string;
  payloadType: string;
  signatures: Array<{ sig: string; keyid?: string }>;
}

export interface InTotoSubject {
  name: string;
  digest: Record<string, string>;
}

export interface InTotoStatement {
  _type: string;
  subject: InTotoSubject[];
  predicateType: string;
  predicate: {
    buildDefinition?: {
      externalParameters?: { workflow?: { repository?: string } };
    };
    runDetails?: { builder?: { id?: string } };
  };
}

export interface VerifyOptions {
  /** Raw contents of the .intoto.jsonl provenance file. */
  provenanceRaw: string;
  /** SHA-256 hex digest of the artifact under verification. */
  artifactSha256: string;
  /** Basename the subject should carry; skipped when omitted. */
  artifactName?: string;
  /** e.g. "github.com/aburex12345/Veritasor-Backend"; skipped when omitted. */
  expectedSourceRepo?: string;
  /** Overrides the trusted builder prefix; defaults to the generic generator. */
  expectedBuilderIdPrefix?: string;
}

export interface VerificationReport {
  subjectName: string;
  sha256: string;
  builderId: string;
  sourceRepo?: string;
  predicateType: string;
}

// ─── parsing ─────────────────────────────────────────────────────────────────

/**
 * Parse the first DSSE envelope from a .intoto.jsonl document and validate
 * its shape. The generic generator emits exactly one envelope per file.
 */
export function parseDsseEnvelope(raw: string): DsseEnvelope {
  const firstLine = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length > 0);

  if (!firstLine) {
    throw new ProvenanceVerificationError(
      "MALFORMED_ENVELOPE",
      "Provenance file is empty."
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(firstLine);
  } catch {
    throw new ProvenanceVerificationError(
      "MALFORMED_ENVELOPE",
      "Provenance file is not valid JSON (expected a DSSE envelope per line)."
    );
  }

  const envelope = parsed as Partial<DsseEnvelope> | null;
  if (
    envelope == null ||
    typeof envelope !== "object" ||
    typeof envelope.payload !== "string" ||
    typeof envelope.payloadType !== "string"
  ) {
    throw new ProvenanceVerificationError(
      "MALFORMED_ENVELOPE",
      "DSSE envelope must contain string `payload` and `payloadType` fields."
    );
  }

  if (envelope.payloadType !== DSSE_PAYLOAD_TYPE) {
    throw new ProvenanceVerificationError(
      "BAD_PAYLOAD_TYPE",
      `Unexpected DSSE payloadType "${envelope.payloadType}"; expected "${DSSE_PAYLOAD_TYPE}".`
    );
  }

  if (
    !Array.isArray(envelope.signatures) ||
    envelope.signatures.length === 0 ||
    envelope.signatures.some((s) => typeof s?.sig !== "string" || s.sig.length === 0)
  ) {
    throw new ProvenanceVerificationError(
      "UNSIGNED_ENVELOPE",
      "DSSE envelope carries no signatures; refusing unsigned provenance."
    );
  }

  return envelope as DsseEnvelope;
}

/** Decode and validate the in-toto statement inside a DSSE envelope. */
export function decodeStatement(envelope: DsseEnvelope): InTotoStatement {
  let statement: unknown;
  try {
    statement = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
  } catch {
    throw new ProvenanceVerificationError(
      "MALFORMED_STATEMENT",
      "DSSE payload is not base64-encoded JSON."
    );
  }

  const stmt = statement as Partial<InTotoStatement> | null;
  if (stmt == null || typeof stmt !== "object" || typeof stmt._type !== "string") {
    throw new ProvenanceVerificationError(
      "MALFORMED_STATEMENT",
      "Decoded payload is not an in-toto statement."
    );
  }

  if (!IN_TOTO_STATEMENT_TYPES.has(stmt._type)) {
    throw new ProvenanceVerificationError(
      "BAD_STATEMENT_TYPE",
      `Unexpected statement _type "${stmt._type}".`
    );
  }

  if (stmt.predicateType !== SLSA_V1_PREDICATE_TYPE) {
    throw new ProvenanceVerificationError(
      "BAD_PREDICATE_TYPE",
      `Unexpected predicateType "${String(stmt.predicateType)}"; expected SLSA v1 ("${SLSA_V1_PREDICATE_TYPE}").`
    );
  }

  if (!Array.isArray(stmt.subject) || stmt.subject.length === 0) {
    throw new ProvenanceVerificationError(
      "NO_SUBJECTS",
      "Provenance statement contains no subjects."
    );
  }

  return stmt as InTotoStatement;
}

// ─── verification ────────────────────────────────────────────────────────────

/** SHA-256 hex digest of a buffer. */
export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Locate the statement subject matching the artifact digest (and name, when
 * provided). Digest binding is the security-relevant check; the name check
 * catches accidental subject/asset mix-ups.
 */
export function findMatchingSubject(
  statement: InTotoStatement,
  artifactSha256: string,
  artifactName?: string
): InTotoSubject {
  const normalized = artifactSha256.toLowerCase();

  const byDigest = statement.subject.filter(
    (s) => s.digest?.sha256?.toLowerCase() === normalized
  );

  if (byDigest.length === 0) {
    const known = statement.subject
      .map((s) => `${s.name}=${s.digest?.sha256 ?? "<none>"}`)
      .join(", ");
    throw new ProvenanceVerificationError(
      "SUBJECT_DIGEST_MISMATCH",
      `Artifact sha256 ${normalized} is not attested by any provenance subject (subjects: ${known}).`
    );
  }

  if (artifactName) {
    const byName = byDigest.find((s) => basename(s.name) === basename(artifactName));
    if (!byName) {
      throw new ProvenanceVerificationError(
        "SUBJECT_DIGEST_MISMATCH",
        `Digest matches but no subject is named "${artifactName}" (matched: ${byDigest
          .map((s) => s.name)
          .join(", ")}).`
      );
    }
    return byName;
  }

  return byDigest[0];
}

/** Enforce the trusted builder identity and source repository. */
export function verifyBuilderIdentity(
  statement: InTotoStatement,
  expectedBuilderIdPrefix: string = EXPECTED_BUILDER_ID_PREFIX,
  expectedSourceRepo?: string
): { builderId: string; sourceRepo?: string } {
  const builderId = statement.predicate?.runDetails?.builder?.id ?? "";
  if (!builderId.startsWith(expectedBuilderIdPrefix)) {
    throw new ProvenanceVerificationError(
      "BUILDER_MISMATCH",
      `Untrusted builder id "${builderId}"; expected prefix "${expectedBuilderIdPrefix}".`
    );
  }

  const sourceRepo =
    statement.predicate?.buildDefinition?.externalParameters?.workflow?.repository;

  if (expectedSourceRepo) {
    const normalize = (repo: string): string =>
      repo.replace(/^https?:\/\//, "").replace(/\.git$/, "").replace(/\/+$/, "").toLowerCase();

    if (!sourceRepo || normalize(sourceRepo) !== normalize(expectedSourceRepo)) {
      throw new ProvenanceVerificationError(
        "SOURCE_REPO_MISMATCH",
        `Provenance source repository "${String(sourceRepo)}" does not match expected "${expectedSourceRepo}".`
      );
    }
  }

  return { builderId, sourceRepo };
}

/** Full structural verification of one artifact against one provenance file. */
export function verifyProvenance(options: VerifyOptions): VerificationReport {
  const envelope = parseDsseEnvelope(options.provenanceRaw);
  const statement = decodeStatement(envelope);

  const subject = findMatchingSubject(
    statement,
    options.artifactSha256,
    options.artifactName
  );

  const { builderId, sourceRepo } = verifyBuilderIdentity(
    statement,
    options.expectedBuilderIdPrefix,
    options.expectedSourceRepo
  );

  return {
    subjectName: subject.name,
    sha256: options.artifactSha256.toLowerCase(),
    builderId,
    sourceRepo,
    predicateType: statement.predicateType,
  };
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

export interface CliArgs {
  provenance: string;
  artifact: string;
  sourceRepo?: string;
  builderIdPrefix?: string;
}

export function parseCliArgs(argv: string[]): CliArgs {
  const args: Partial<CliArgs> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    switch (flag) {
      case "--provenance":
        args.provenance = value;
        i += 1;
        break;
      case "--artifact":
        args.artifact = value;
        i += 1;
        break;
      case "--source-repo":
        args.sourceRepo = value;
        i += 1;
        break;
      case "--builder-id-prefix":
        args.builderIdPrefix = value;
        i += 1;
        break;
      default:
        throw new Error(`Unknown argument: ${flag}`);
    }
  }

  if (!args.provenance || !args.artifact) {
    throw new Error(
      "Usage: verify-provenance --provenance <file.intoto.jsonl> --artifact <file> [--source-repo github.com/owner/repo] [--builder-id-prefix <url>]"
    );
  }

  return args as CliArgs;
}

export async function runVerifyProvenanceCli(
  argv: string[] = process.argv.slice(2)
): Promise<VerificationReport> {
  const cli = parseCliArgs(argv);

  const [provenanceRaw, artifactData] = await Promise.all([
    readFile(cli.provenance, "utf8"),
    readFile(cli.artifact),
  ]);

  const report = verifyProvenance({
    provenanceRaw,
    artifactSha256: sha256Hex(artifactData),
    artifactName: basename(cli.artifact),
    expectedSourceRepo: cli.sourceRepo,
    expectedBuilderIdPrefix: cli.builderIdPrefix,
  });

  console.log(
    `PASS: ${report.subjectName} (sha256:${report.sha256}) attested by ${report.builderId}`
  );
  return report;
}

/** True when this module is the process entrypoint (not imported by tests). */
export function isVerifyProvenanceCliEntrypoint(
  argv1: string | undefined,
  moduleUrl: string
): boolean {
  return Boolean(argv1 && fileURLToPath(moduleUrl) === argv1);
}

export function handleVerifyProvenanceCliFailure(
  err: unknown,
  exitFn: (code: number) => never = ((code) => process.exit(code)) as (code: number) => never
): never {
  const code = err instanceof ProvenanceVerificationError ? ` [${err.code}]` : "";
  console.error(`FAIL${code}: ${err instanceof Error ? err.message : String(err)}`);
  exitFn(1);
}

if (isVerifyProvenanceCliEntrypoint(process.argv[1], import.meta.url)) {
  runVerifyProvenanceCli().catch((err) => handleVerifyProvenanceCliFailure(err));
}
