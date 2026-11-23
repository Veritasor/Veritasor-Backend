import { X509Certificate } from "node:crypto";
import type {
  TlsIdentityMaterial,
  WorkloadApiClient,
  WorkloadX509Response,
  X509SvidRecord,
} from "./types.js";

export class SpiffeMaterialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpiffeMaterialError";
  }
}

export interface SvidProviderOptions {
  trustDomain: string;
  client: WorkloadApiClient;
  /** Fraction of SVID lifetime after which a refresh timer is scheduled (0–1). */
  refreshRatio?: number;
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
  now?: () => Date;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
  onRotate?: (material: TlsIdentityMaterial) => void;
}

const DEFAULT_REFRESH_RATIO = 0.7;
const DEFAULT_RECONNECT_BASE_MS = 500;
const DEFAULT_RECONNECT_MAX_MS = 30_000;

export function responseToTlsMaterial(
  response: WorkloadX509Response,
  trustDomain: string,
): TlsIdentityMaterial {
  const svid = pickSvidForTrustDomain(response.svids, trustDomain);
  if (!svid) {
    throw new SpiffeMaterialError(
      `Workload API returned no SVID for trust domain ${trustDomain}`,
    );
  }

  const bundle = response.bundles.get(trustDomain);
  if (!bundle || bundle.authorities.length === 0) {
    throw new SpiffeMaterialError(
      `Workload API returned no trust bundle for domain ${trustDomain}`,
    );
  }

  const certPem = svid.x509Svid.toString("utf8");
  const expiresAt = parseCertificateExpiry(certPem);

  return {
    ca: Buffer.from(
      bundle.authorities
        .map((authority) => authority.toString("utf8").trim())
        .join("\n"),
    ),
    cert: svid.x509Svid,
    key: svid.privateKey,
    spiffeId: svid.spiffeId,
    expiresAt,
  };
}

function pickSvidForTrustDomain(
  svids: X509SvidRecord[],
  trustDomain: string,
): X509SvidRecord | undefined {
  const prefix = `spiffe://${trustDomain}/`;
  return svids.find((svid) => svid.spiffeId.startsWith(prefix));
}

function parseCertificateExpiry(certPem: string): Date {
  const x509 = new X509Certificate(certPem);
  const expiresAt = new Date(x509.validTo);
  if (Number.isNaN(expiresAt.getTime())) {
    throw new SpiffeMaterialError("Unable to parse SVID certificate expiry");
  }
  return expiresAt;
}

export class SvidProvider {
  private readonly trustDomain: string;
  private readonly client: WorkloadApiClient;
  private readonly refreshRatio: number;
  private readonly reconnectBaseMs: number;
  private readonly reconnectMaxMs: number;
  private readonly now: () => Date;
  private readonly setTimeoutFn: typeof setTimeout;
  private readonly clearTimeoutFn: typeof clearTimeout;
  private readonly onRotate?: (material: TlsIdentityMaterial) => void;

  private material: TlsIdentityMaterial | undefined;
  private refreshTimer: ReturnType<typeof setTimeout> | undefined;
  private stopWatch: (() => void) | undefined;
  private reconnectAttempts = 0;
  private stopped = false;

  constructor(options: SvidProviderOptions) {
    this.trustDomain = options.trustDomain;
    this.client = options.client;
    this.refreshRatio = options.refreshRatio ?? DEFAULT_REFRESH_RATIO;
    this.reconnectBaseMs = options.reconnectBaseMs ?? DEFAULT_RECONNECT_BASE_MS;
    this.reconnectMaxMs = options.reconnectMaxMs ?? DEFAULT_RECONNECT_MAX_MS;
    this.now = options.now ?? (() => new Date());
    this.setTimeoutFn = options.setTimeoutFn ?? setTimeout;
    this.clearTimeoutFn = options.clearTimeoutFn ?? clearTimeout;
    this.onRotate = options.onRotate;
  }

  async start(): Promise<void> {
    const initial = await this.client.fetchX509Svid();
    this.applyMaterial(initial);
    this.stopWatch = this.client.watchX509Svid(
      (response) => {
        this.reconnectAttempts = 0;
        this.applyMaterial(response);
      },
      (error) => this.handleWatchError(error),
    );
  }

  stop(): void {
    this.stopped = true;
    this.clearRefreshTimer();
    this.stopWatch?.();
    this.stopWatch = undefined;
  }

  getTlsMaterial(): TlsIdentityMaterial {
    if (!this.material) {
      throw new SpiffeMaterialError("SVID material is not loaded yet");
    }
    return this.material;
  }

  getSecondsUntilExpiry(): number | undefined {
    if (!this.material) {
      return undefined;
    }
    const msRemaining = this.material.expiresAt.getTime() - this.now().getTime();
    return Math.max(0, Math.floor(msRemaining / 1000));
  }

  private applyMaterial(response: WorkloadX509Response): void {
    const next = responseToTlsMaterial(response, this.trustDomain);
    const rotated = this.material !== undefined;
    this.material = next;
    this.scheduleRefresh(next.expiresAt);
    if (rotated) {
      this.onRotate?.(next);
    }
  }

  private scheduleRefresh(expiresAt: Date): void {
    this.clearRefreshTimer();
    const ttlMs = expiresAt.getTime() - this.now().getTime();
    if (ttlMs <= 0) {
      return;
    }

    const delayMs = Math.max(
      1_000,
      Math.floor(ttlMs * this.refreshRatio),
    );

    this.refreshTimer = this.setTimeoutFn(() => {
      void this.refreshFromFetch();
    }, delayMs);
    if (typeof this.refreshTimer === "object" && "unref" in this.refreshTimer) {
      this.refreshTimer.unref();
    }
  }

  private async refreshFromFetch(): Promise<void> {
    if (this.stopped) {
      return;
    }

    try {
      const response = await this.client.fetchX509Svid();
      this.applyMaterial(response);
    } catch (error) {
      this.handleWatchError(
        error instanceof Error ? error : new Error(String(error)),
      );
    }
  }

  private handleWatchError(error: Error): void {
    if (this.stopped) {
      return;
    }

    this.clearRefreshTimer();
    const delayMs = Math.min(
      this.reconnectMaxMs,
      this.reconnectBaseMs * 2 ** this.reconnectAttempts,
    );
    this.reconnectAttempts += 1;

    this.refreshTimer = this.setTimeoutFn(() => {
      void this.reconnectAfterApiRestart();
    }, delayMs);
    if (typeof this.refreshTimer === "object" && "unref" in this.refreshTimer) {
      this.refreshTimer.unref();
    }
  }

  private async reconnectAfterApiRestart(): Promise<void> {
    if (this.stopped) {
      return;
    }

    try {
      const response = await this.client.fetchX509Svid();
      this.reconnectAttempts = 0;
      this.applyMaterial(response);
      this.stopWatch?.();
      this.stopWatch = this.client.watchX509Svid(
        (next) => {
          this.reconnectAttempts = 0;
          this.applyMaterial(next);
        },
        (error) => this.handleWatchError(error),
      );
    } catch (error) {
      this.handleWatchError(
        error instanceof Error ? error : new Error(String(error)),
      );
    }
  }

  private clearRefreshTimer(): void {
    if (this.refreshTimer !== undefined) {
      this.clearTimeoutFn(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }
}

export function createSvidProvider(options: SvidProviderOptions): SvidProvider {
  return new SvidProvider(options);
}
