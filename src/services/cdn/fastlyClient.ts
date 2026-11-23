// src/services/cdn/fastlyClient.ts

import { CdnClient } from "./cdnClientAdapter.js";
import http from "node:http";
import https from "node:https";
import { logger } from "../../utils/logger.js";

// ---------------------------------------------------------------------------
// Typed error class — replaces the (err as any).transient hack
// ---------------------------------------------------------------------------

/**
 * Thrown by {@link FastlyClient.purge} when a request fails.
 *
 * `transient` is `true` for errors that may succeed on retry (5xx, 429,
 * connection-level errors like ECONNRESET). It is `false` for permanent
 * failures (4xx other than 429).
 */
export class FastlyPurgeError extends Error {
  public readonly transient: boolean;

  constructor(message: string, transient: boolean) {
    super(message);
    this.name = "FastlyPurgeError";
    this.transient = transient;
  }
}

/** Node.js network error codes that should be retried. */
const RETRYABLE_CODES = new Set(["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EPIPE", "ENOTCONN"]);

/**
 * Typed error thrown when a Fastly purge request fails with a non-2xx HTTP status.
 */
export class FastlyPurgeError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly transient = false,
  ) {
    super(message);
    this.name = "FastlyPurgeError";
  }
}

/**
 * Fastly CDN client implementation.
 * Purges URLs via Fastly API using an API key header.
 */
export class FastlyClient implements CdnClient {
  private apiKey: string;
  private serviceId: string;
  private baseUrl: string;

  constructor(apiKey?: string, serviceId?: string, baseUrl?: string) {
    this.apiKey = apiKey ?? process.env.FASTLY_API_KEY ?? "";
    this.serviceId = serviceId ?? process.env.FASTLY_SERVICE_ID ?? "";
    this.baseUrl = baseUrl ?? process.env.FASTLY_API_BASE_URL ?? "https://api.fastly.com";
    if (!this.apiKey || !this.serviceId) {
      throw new Error("Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID");
    }
  }

  async purge(urls: string[]): Promise<void> {
    const parsed = new URL(this.baseUrl);
    const useHttps = parsed.protocol === "https:";
    const transport = useHttps ? https : http;
    const defaultPort = useHttps ? 443 : 80;
    const port = parsed.port ? Number(parsed.port) : defaultPort;

    const path = `/service/${this.serviceId}/purge`; // Fastly bulk purge endpoint
    const payload = JSON.stringify({ urls });
    const options: http.RequestOptions = {
      method: "POST",
      hostname: parsed.hostname,
      port,
      path,
      headers: {
        "Fastly-Key": this.apiKey,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload).toString(),
      },
      // 10-second socket timeout; the request is destroyed on expiry.
      timeout: 10_000,
    };

    const maxAttempts = 5;
    let attempt = 0;
    // Jittered exponential backoff: base delay doubled each attempt, capped at
    // 16 s, with up to 1 s of uniform random jitter added.
    const backoff = (n: number) => Math.min(1000 * 2 ** n, 16_000) + Math.random() * 1000;

    while (attempt < maxAttempts) {
      attempt++;
      try {
        await new Promise<void>((resolve, reject) => {
          const req = transport.request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
              const status = res.statusCode ?? 0;
              if (status >= 200 && status < 300) {
                resolve();
              } else {
                const isTransient = Boolean(res.statusCode && res.statusCode >= 500);
                reject(
                  new FastlyPurgeError(
                    `Fastly purge failed with status ${res.statusCode}: ${data}`,
                    res.statusCode,
                    isTransient,
                // 429 Too Many Requests is transient; all other 4xx are not.
                const transient = status >= 500 || status === 429;
                reject(
                  new FastlyPurgeError(
                    `Fastly purge failed with status ${status}: ${data}`,
                    transient,
                  ),
                );
              }
            });
          });

          req.on("timeout", () => {
            req.destroy(new FastlyPurgeError("Fastly purge request timed out", true));
          });

          req.on("error", (err: NodeJS.ErrnoException) => {
            // Network-level errors (socket resets, refusals, pipe breaks) are
            // transient and should be retried.
            const transient = RETRYABLE_CODES.has(err.code ?? "");
            reject(new FastlyPurgeError(err.message, transient));
          });

          req.write(payload);
          req.end();
        });
        // Success — exit retry loop.
        return;
      } catch (err) {
        const isTransient = err instanceof FastlyPurgeError ? err.transient : false;
        const message = err instanceof Error ? err.message : String(err);
        logger.error(`Fastly purge attempt ${attempt} failed: ${message}`);
        if (!isTransient || attempt >= maxAttempts) {
          throw err;
        const purgeErr = err instanceof FastlyPurgeError
          ? err
          : new FastlyPurgeError((err as Error).message, false);

        logger.error(`Fastly purge attempt ${attempt} failed: ${purgeErr.message}`);

        if (!purgeErr.transient || attempt >= maxAttempts) {
          throw purgeErr;
        }
        await new Promise((r) => setTimeout(r, backoff(attempt)));
      }
    }
  }
}

// Export a singleton instance for injection
let _instance: FastlyClient | undefined;

export function resetFastlyClient(): void {
  _instance = undefined;
}

export const fastlyClient: FastlyClient = new Proxy<FastlyClient>(
  Object.create(FastlyClient.prototype) as FastlyClient,
  {
    get(_target: FastlyClient, prop: string | symbol, receiver: unknown): unknown {
      if (prop === "purge") {
        return async (
          ...args: Parameters<FastlyClient["purge"]>
        ): ReturnType<FastlyClient["purge"]> => {
          if (!_instance) {
            _instance = new FastlyClient();
          }
          return _instance.purge(...args);
        };
      }
      if (!_instance) {
        _instance = new FastlyClient();
      }
      const val: unknown = Reflect.get(_instance, prop, receiver);
      return typeof val === "function" ? val.bind(_instance) : val;
    },
  },
);
