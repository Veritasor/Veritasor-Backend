/**
 * Audit-Log Signed Export Job  (issue #580)
 *
 * Regulators require signed audit exports. This module:
 *
 *  1. Fetches all audit logs via the existing `getAllAuditLogs()` repository.
 *  2. Builds a gzip-compressed tarball containing:
 *       - `audit-logs.json`    – newline-delimited JSON of every log entry
 *       - `manifest.json`      – export metadata (record count, SHA-256 of logs file)
 *  3. Signs the manifest text with a detached PGP signature using a private key
 *     sourced from the secret loader (`AUDIT_EXPORT_PGP_PRIVATE_KEY`).
 *  4. Returns the tarball buffer + armored detached signature so the caller can
 *     upload them to an encrypted bucket or attach them to a regulated report.
 *
 * Key rotation safety:
 *   The signing step fetches the key fresh on every run, so a key rotation that
 *   updates the secret loader's backing store takes effect on the next export
 *   without any deployment. A `passphrase` may optionally be supplied via the
 *   `AUDIT_EXPORT_PGP_PASSPHRASE` secret.
 *
 * The job follows the `runInstrumentedJob` pattern used across all other jobs
 * in this codebase so metrics (duration, item count, outcome) are emitted to
 * Pushgateway automatically.
 */

import { createGzip } from "node:zlib";
import { pipeline } from "node:stream/promises";
import { Writable, PassThrough } from "node:stream";
import { createHash } from "node:crypto";
import * as openpgp from "openpgp";
import { pack as tarPack } from "tar-stream";
import { getAllAuditLogs, type AuditLog } from "../repositories/auditLogRepository.js";
import { createSecretLoader } from "../utils/secret-loader.js";
import { logger } from "../utils/logger.js";
import { runInstrumentedJob, type JobOutcome } from "./jobRunner.js";

export const AUDIT_EXPORT_JOB_NAME = "audit_signed_export";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditExportManifest {
  /** Export format version for consumers. */
  exportVersion: number;
  /** ISO-8601 timestamp when the export was generated. */
  exportedAt: string;
  /** Total number of audit log records included. */
  recordCount: number;
  /** Hex SHA-256 digest of the `audit-logs.json` file contents. */
  logsFileSha256: string;
  /** Fingerprint of the PGP key used to sign this manifest. */
  signingKeyFingerprint: string;
}

export interface AuditExportResult {
  /** Gzip-compressed tarball containing audit-logs.json + manifest.json. */
  tarballBuffer: Buffer;
  /** Armored PGP detached signature over the manifest JSON string. */
  manifestSignature: string;
  /** The manifest that was signed – consumers use this to verify. */
  manifest: AuditExportManifest;
  /** Number of audit log records exported. */
  recordCount: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Serialise audit logs as newline-delimited JSON (NDJSON).
 * Each line is one JSON-encoded log record.
 */
export function serialiseLogsAsNdjson(logs: AuditLog[]): string {
  return logs.map((l) => JSON.stringify(l)).join("\n");
}

/**
 * Compute SHA-256 of a UTF-8 string and return a lowercase hex digest.
 */
export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Build a gzip-compressed tarball from the provided files.
 *
 * @param files  - Map of filename → UTF-8 content.
 * @returns Buffer containing the `.tar.gz` bytes.
 */
export async function buildTarball(
  files: Map<string, string>
): Promise<Buffer> {
  const tar = tarPack();
  const gzip = createGzip();

  const chunks: Buffer[] = [];
  const collector = new Writable({
    write(chunk: Buffer, _enc: string, cb: () => void) {
      chunks.push(chunk);
      cb();
    },
  });

  // We need to pipe tar → gzip → collector and simultaneously feed files
  // into the tar stream. Use a PassThrough so pipeline can join them.
  const pipelinePromise = pipeline(tar, gzip, collector);

  for (const [name, content] of files) {
    const contentBuffer = Buffer.from(content, "utf8");
    await new Promise<void>((resolve, reject) => {
      const entry = tar.entry(
        { name, size: contentBuffer.length },
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
      entry.end(contentBuffer);
    });
  }

  tar.finalize();
  await pipelinePromise;

  return Buffer.concat(chunks);
}

/**
 * Load the PGP private key from the secret loader.
 *
 * The secret loader key is `AUDIT_EXPORT_PGP_PRIVATE_KEY` (armored).
 * An optional passphrase can be supplied via `AUDIT_EXPORT_PGP_PASSPHRASE`.
 */
export async function loadSigningKey(): Promise<openpgp.PrivateKey> {
  const loader = createSecretLoader();

  let armoredKey: string;
  try {
    armoredKey = await loader.get("AUDIT_EXPORT_PGP_PRIVATE_KEY");
  } catch {
    // Fall back to env var for local development
    const envKey = process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];
    if (!envKey) {
      throw new Error(
        "AUDIT_EXPORT_PGP_PRIVATE_KEY secret is not configured. " +
          "Set it in the secret store or as an environment variable."
      );
    }
    armoredKey = envKey;
  }

  let passphrase: string | undefined;
  try {
    passphrase = await loader.get("AUDIT_EXPORT_PGP_PASSPHRASE");
  } catch {
    passphrase = process.env["AUDIT_EXPORT_PGP_PASSPHRASE"];
  }

  const privateKey = await openpgp.readPrivateKey({ armoredKey });

  if (passphrase) {
    return openpgp.decryptKey({ privateKey, passphrase });
  }

  return privateKey;
}

/**
 * Sign `text` with a detached PGP signature using the provided private key.
 *
 * @returns Armored PGP signature string.
 */
export async function signManifest(
  text: string,
  privateKey: openpgp.PrivateKey
): Promise<string> {
  const message = await openpgp.createMessage({ text });
  const detachedSignature = await openpgp.sign({
    message,
    signingKeys: privateKey,
    detached: true,
  });
  return detachedSignature as string;
}

/**
 * Verify that a detached PGP signature over `text` is valid.
 *
 * @param text          - The original signed text.
 * @param armoredSig    - Armored detached PGP signature.
 * @param publicKey     - The public key to verify against.
 * @returns `true` if at least one valid signature is found.
 */
export async function verifyExportSignature(
  text: string,
  armoredSig: string,
  publicKey: openpgp.PublicKey
): Promise<boolean> {
  try {
    const message = await openpgp.createMessage({ text });
    const signature = await openpgp.readSignature({ armoredSignature: armoredSig });
    const result = await openpgp.verify({
      message,
      signature,
      verificationKeys: publicKey,
    });
    const { verified } = result.signatures[0];
    await verified;
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Core export function
// ---------------------------------------------------------------------------

/**
 * Generate a signed audit-log export.
 *
 * Fetches all audit logs, builds a tarball, signs the manifest, and returns
 * the complete export result.  Throws on configuration or signing errors so
 * `runInstrumentedJob` can record the failure metric.
 *
 * @param now - Injectable clock (defaults to `new Date()`).
 */
export async function generateSignedAuditExport(
  now: Date = new Date()
): Promise<AuditExportResult> {
  // 1. Fetch logs
  const logs = await getAllAuditLogs();
  const ndjson = serialiseLogsAsNdjson(logs);
  const logsHash = sha256Hex(ndjson);

  // 2. Load signing key
  const privateKey = await loadSigningKey();
  const fingerprint = privateKey.getFingerprint();

  // 3. Build manifest
  const manifest: AuditExportManifest = {
    exportVersion: 1,
    exportedAt: now.toISOString(),
    recordCount: logs.length,
    logsFileSha256: logsHash,
    signingKeyFingerprint: fingerprint,
  };
  const manifestJson = JSON.stringify(manifest, null, 2);

  // 4. Build tarball
  const files = new Map<string, string>([
    ["audit-logs.json", ndjson],
    ["manifest.json", manifestJson],
  ]);
  const tarballBuffer = await buildTarball(files);

  // 5. Sign the manifest
  const manifestSignature = await signManifest(manifestJson, privateKey);

  return {
    tarballBuffer,
    manifestSignature,
    manifest,
    recordCount: logs.length,
  };
}

// ---------------------------------------------------------------------------
// Job entry point
// ---------------------------------------------------------------------------

/**
 * Scheduled audit-log signed export job.
 *
 * Intended to run nightly (or on-demand via admin trigger). Generates a signed
 * export and logs the result.  In production the caller should upload
 * `tarballBuffer` and `manifestSignature` to the encrypted S3/GCS bucket.
 *
 * @param now - Injectable clock for deterministic testing.
 */
export const auditSignedExportJob = async (
  now: Date = new Date()
): Promise<JobOutcome> => {
  return runInstrumentedJob(AUDIT_EXPORT_JOB_NAME, async () => {
    logger.info("Running audit signed export job…");

    try {
      const result = await generateSignedAuditExport(now);

      logger.info(
        {
          recordCount: result.recordCount,
          tarballBytes: result.tarballBuffer.length,
          exportedAt: result.manifest.exportedAt,
          signingKeyFingerprint: result.manifest.signingKeyFingerprint,
        },
        "Audit export generated. Upload tarball + signature to encrypted bucket."
      );

      return { itemsProcessed: result.recordCount, success: true };
    } catch (error) {
      logger.error("Audit signed export job failed", error);
      return { itemsProcessed: 0, success: false };
    }
  });
};
