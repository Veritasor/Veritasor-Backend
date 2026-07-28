// src/services/cdn/fastlyClient.ts

import { CdnClient } from "./cdnClientAdapter.js";
import https from "node:https";
import { logger } from "../utils/logger.js";

/**
 * Fastly CDN client implementation.
 * Purges URLs via Fastly API using an API key header.
 */
export class FastlyClient implements CdnClient {
  private apiKey: string;
  private serviceId: string;
  private baseUrl: string;

  constructor() {
    this.apiKey = process.env.FASTLY_API_KEY ?? "";
    this.serviceId = process.env.FASTLY_SERVICE_ID ?? "";
    this.baseUrl = process.env.FASTLY_API_BASE_URL ?? "https://api.fastly.com";
    if (!this.apiKey || !this.serviceId) {
      throw new Error("Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID");
    }
  }

  async purge(urls: string[]): Promise<void> {
    const path = `/service/${this.serviceId}/purge`; // Fastly bulk purge endpoint
    const payload = JSON.stringify({ urls });
    const options = {
      method: "POST",
      hostname: new URL(this.baseUrl).hostname,
      path,
      headers: {
        "Fastly-Key": this.apiKey,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload).toString(),
      },
    };

    const maxAttempts = 5;
    let attempt = 0;
    const backoff = (attempt: number) => Math.min(1000 * 2 ** attempt, 16000);

    while (attempt < maxAttempts) {
      attempt++;
      try {
        await new Promise<void>((resolve, reject) => {
          const req = https.request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
              if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                resolve();
              } else {
                const err = new Error(`Fastly purge failed with status ${res.statusCode}: ${data}`);
                (err as any).transient = res.statusCode && res.statusCode >= 500;
                reject(err);
              }
            });
          });
          req.on("error", reject);
          req.write(payload);
          req.end();
        });
        // Success, exit loop
        return;
      } catch (err) {
        const isTransient = (err as any).transient ?? false;
        logger.error(`Fastly purge attempt ${attempt} failed: ${(err as Error).message}`);
        if (!isTransient || attempt >= maxAttempts) {
          throw err;
        }
        // wait backoff
        await new Promise((r) => setTimeout(r, backoff(attempt)));
      }
    }
  }
}

// Export a singleton instance for injection
export const fastlyClient = new FastlyClient();
