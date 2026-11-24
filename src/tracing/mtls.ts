/**
 * gRPC mTLS credential management for the OTLP exporter.
 *
 * Credentials are loaded either from the secret loader (preferred) or from
 * filesystem paths. File-backed credentials are watched so that certificate
 * rotation takes effect without a process restart.
 */

import { watch } from "node:fs";
import { readFile as readFileAsync } from "node:fs/promises";
import { logger } from "../utils/logger.js";
import { isGrpcMtlsEnabled } from "./protocol.js";

/** PEM-encoded CA, client certificate, and private key. */
export type GrpcMtlsCredentials = {
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
};

let grpcMtlsCredentials: GrpcMtlsCredentials | undefined;

/**
 * Whether mTLS creds were loaded from file paths (true) or secret loader (false).
 * Files are watched for rotation; secret-loader creds rotate via reload().
 */
let grpcMtlsFromFiles = false;

/** Active file watchers for gRPC mTLS cert files. Cleared on SDK shutdown. */
const grpcMtlsWatchers: Array<ReturnType<typeof watch>> = [];

/** Debounce timer for file-watch-driven SDK reinitialization. */
let grpcMtlsDebounceTimer: ReturnType<typeof setTimeout> | undefined;

/** Currently loaded gRPC mTLS credentials, if any. */
export function getGrpcMtlsCredentials(): GrpcMtlsCredentials | undefined {
  return grpcMtlsCredentials;
}

/** Clear cached credentials and remember that they did not come from files. */
export function clearGrpcMtlsCredentials(): void {
  grpcMtlsCredentials = undefined;
  grpcMtlsFromFiles = false;
}

/**
 * Attempt to load PEM credential material from the secret loader.
 *
 * Keys tried: `OTEL_MTLS_CA`, `OTEL_MTLS_CERT`, `OTEL_MTLS_KEY`.
 * When all three resolve, the PEM strings are returned as Buffers.
 * When any key is missing the function returns `undefined` so the
 * caller can fall back to file-path loading.
 */
async function loadGrpcMtlsFromSecretLoader(): Promise<GrpcMtlsCredentials | undefined> {
  try {
    // Loaded lazily so tracing can be imported without initializing the
    // secret backend (which may pull in cloud SDKs) when mTLS is unused.
    const { secretLoader } = await import("../utils/secret-loader.js");
    const [ca, cert, key] = await Promise.all([
      secretLoader.get("OTEL_MTLS_CA"),
      secretLoader.get("OTEL_MTLS_CERT"),
      secretLoader.get("OTEL_MTLS_KEY"),
    ]);
    if (!ca || !cert || !key) return undefined;
    return {
      ca: Buffer.from(ca, "utf-8"),
      cert: Buffer.from(cert, "utf-8"),
      key: Buffer.from(key, "utf-8"),
    };
  } catch {
    // SecretNotLoadedError or SecretNotFoundError → fall back to files
    return undefined;
  }
}

/**
 * Load gRPC mTLS credentials.
 *
 * Prefers the secret loader (keys `OTEL_MTLS_CA`, `OTEL_MTLS_CERT`,
 * `OTEL_MTLS_KEY`) so operators can store PEM material in Vault, env,
 * or a file backend. Falls back to reading from filesystem paths
 * (`OTEL_MTLS_CA_PATH`, …) when the secret loader returns nothing.
 *
 * Returns `undefined` when mTLS is not enabled. Throws when mTLS is
 * enabled but neither backend provides all three PEM values.
 */
export async function loadGrpcMtlsCredentials(): Promise<GrpcMtlsCredentials | undefined> {
  if (!isGrpcMtlsEnabled()) {
    clearGrpcMtlsCredentials();
    return undefined;
  }

  // 1. Try secret loader (supports Vault, env, file backends)
  const fromSecrets = await loadGrpcMtlsFromSecretLoader();
  if (fromSecrets) {
    grpcMtlsFromFiles = false;
    grpcMtlsCredentials = fromSecrets;
    return fromSecrets;
  }

  // 2. Fall back to file paths
  const caPath = process.env.OTEL_MTLS_CA_PATH?.trim();
  const certPath = process.env.OTEL_MTLS_CERT_PATH?.trim();
  const keyPath = process.env.OTEL_MTLS_KEY_PATH?.trim();

  if (!caPath || !certPath || !keyPath) {
    throw new Error(
      "OTEL_GRPC_MTLS_ENABLED=true but neither secret-loader keys " +
        "(OTEL_MTLS_CA/CERT/KEY) nor file paths " +
        "(OTEL_MTLS_CA_PATH/CERT_PATH/KEY_PATH) are fully configured.",
    );
  }

  const [ca, cert, key] = await Promise.all([
    readFileAsync(caPath),
    readFileAsync(certPath),
    readFileAsync(keyPath),
  ]);

  grpcMtlsFromFiles = true;
  grpcMtlsCredentials = { ca, cert, key };
  return grpcMtlsCredentials;
}

/**
 * Start file watchers on the gRPC mTLS certificate paths.
 *
 * Only active when credentials were loaded from files (not the secret
 * loader). When any watched file changes, `onRotate` is invoked so that
 * rotated certificates take effect without a process restart. A short
 * debounce prevents storms when a certificate manager atomically replaces
 * multiple files in quick succession.
 *
 * @param onRotate - Callback that reinitializes the SDK with fresh credentials.
 */
export function startGrpcMtlsFileWatchers(onRotate: () => Promise<void>): void {
  if (!grpcMtlsFromFiles) return;

  const paths = [
    process.env.OTEL_MTLS_CA_PATH?.trim(),
    process.env.OTEL_MTLS_CERT_PATH?.trim(),
    process.env.OTEL_MTLS_KEY_PATH?.trim(),
  ].filter((p): p is string => Boolean(p));

  for (const filePath of paths) {
    try {
      const watcher = watch(filePath, (eventType) => {
        if (eventType !== "change") return;
        if (grpcMtlsDebounceTimer) clearTimeout(grpcMtlsDebounceTimer);
        grpcMtlsDebounceTimer = setTimeout(() => {
          logger.info({
            event: "otel_grpc_mtls_cert_changed",
            path: filePath,
          });
          onRotate().catch((err) => {
            logger.error({
              event: "otel_grpc_mtls_reinit_failed",
              error: err instanceof Error ? err.message : String(err),
            });
          });
        }, 500);
      });
      grpcMtlsWatchers.push(watcher);
    } catch {
      logger.debug({
        event: "otel_grpc_mtls_watcher_failed",
        path: filePath,
      });
    }
  }
}

/**
 * Stop all gRPC mTLS file watchers and cancel any pending debounce timer.
 */
export function stopGrpcMtlsFileWatchers(): void {
  if (grpcMtlsDebounceTimer) {
    clearTimeout(grpcMtlsDebounceTimer);
    grpcMtlsDebounceTimer = undefined;
  }
  for (const watcher of grpcMtlsWatchers) {
    try {
      watcher.close();
    } catch {
      /* best-effort */
    }
  }
  grpcMtlsWatchers.length = 0;
}
