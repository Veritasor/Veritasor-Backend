import { BaseSecretAdapter, SecretLoadError } from './base.js'

/** A Vault dynamic-secret lease, tracked so it can be renewed before expiry. */
export interface VaultLease {
  leaseId: string
  leaseDurationSeconds: number
  renewable: boolean
}

export interface VaultAdapterOptions {
  /** Injected for tests. Defaults to the global timer functions. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setTimeoutFn?: (cb: () => void, ms: number) => any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  clearTimeoutFn?: (handle: any) => void
  /** Injected for tests to make jitter deterministic. Defaults to `Math.random`. */
  randomFn?: () => number
}

export class VaultAdapter extends BaseSecretAdapter {
  private lease: VaultLease | undefined
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private renewalTimer: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly setTimeoutFn: (cb: () => void, ms: number) => any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly clearTimeoutFn: (handle: any) => void
  private readonly randomFn: () => number

  constructor(
    private readonly baseUrl: string,
    private readonly secretPath: string,
    private readonly token?: string,
    options: VaultAdapterOptions = {},
  ) {
    super()
    this.setTimeoutFn = options.setTimeoutFn ?? setTimeout
    this.clearTimeoutFn = options.clearTimeoutFn ?? clearTimeout
    this.randomFn = options.randomFn ?? Math.random
  }

  /**
   * Fetches secrets from Vault and, if the response carries a renewable
   * lease, schedules automatic renewal. Cancels any previously-scheduled
   * renewal first, so calling `reload()` externally never leaves a stale
   * timer racing a fresh one.
   */
  async reload(): Promise<void> {
    this.cancelScheduledRenewal()
    const { secrets, lease } = await this.fetchFromVault(this.secretPath)
    this.secrets = secrets
    this.lease = lease
    this.loaded = true
    if (lease) {
      vaultLeaseSecondsRemaining.set(lease.leaseDurationSeconds)
    }
    this.scheduleRenewalIfEligible()
  }

  get(key: string): string {
    this.ensureLoaded()
    return this.toSecretValue(this.secrets.get(BaseSecretAdapter.normalizeSecretKey(key)), key)
  }

  /** Cancels any pending renewal timer. Safe to call even if none is scheduled. */
  stopLeaseRenewal(): void {
    this.cancelScheduledRenewal()
  }

  /** The currently tracked lease, if the last load/renewal returned one. */
  getLease(): VaultLease | undefined {
    return this.lease
  }

  private async fetchFromVault(
    secretPath: string,
  ): Promise<{ secrets: Map<string, string>; lease?: VaultLease }> {
    const normalizedBaseUrl = this.baseUrl.replace(/\/+$/, '')
    const normalizedSecretPath = secretPath.replace(/^\/+/, '')
    const url = `${normalizedBaseUrl}/${normalizedSecretPath}`

    let response: Response
    try {
      response = await fetch(url, {
        headers: this.token
          ? {
              Authorization: `Bearer ${this.token}`,
              Accept: 'application/json',
            }
          : { Accept: 'application/json' },
      })
    } catch (error) {
      throw new SecretLoadError(`Failed to fetch secrets from Vault at ${url}`, error instanceof Error ? error : undefined)
    }

    if (!response.ok) {
      throw new SecretLoadError(`Vault secrets endpoint returned ${response.status} ${response.statusText}`)
    }

    let body: unknown
    try {
      body = await response.json()
    } catch (error) {
      throw new SecretLoadError(`Vault secrets response was not valid JSON from ${url}`, error instanceof Error ? error : undefined)
    }

    const payload = this.resolveVaultPayload(body)
    const secrets = BaseSecretAdapter.normalizeSecretValues(payload)
    const lease = this.resolveVaultLease(body)
    return { secrets, lease }
  }

  private resolveVaultPayload(body: unknown): Record<string, unknown> {
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      const candidate = (body as Record<string, unknown>).data
      if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
        return candidate as Record<string, unknown>
      }
      return body as Record<string, unknown>
    }
    throw new SecretLoadError('Vault response payload was not an object')
  }

  /**
   * Extracts lease metadata from a Vault response envelope, e.g.
   * `{ lease_id, lease_duration, renewable, data: {...} }`. Static secrets
   * (or any response missing these fields) yield `undefined` — no renewal
   * is scheduled for them.
   */
  private resolveVaultLease(body: unknown): VaultLease | undefined {
    if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined
    const envelope = body as Record<string, unknown>
    const leaseId = envelope.lease_id
    const leaseDuration = envelope.lease_duration

    if (typeof leaseId !== 'string' || leaseId === '' || typeof leaseDuration !== 'number' || leaseDuration <= 0) {
      return undefined
    }

    return {
      leaseId,
      leaseDurationSeconds: leaseDuration,
      renewable: envelope.renewable === true,
    }
  }

  private scheduleRenewalIfEligible(): void {
    if (!this.lease?.renewable) return
    const delayMs = this.renewalDelayMs(this.lease.leaseDurationSeconds)
    // Returns the renew() promise (rather than a fire-and-forget `void`) so
    // tests using an injected `setTimeoutFn` can await the scheduled
    // callback and observe its effects deterministically. A real `setTimeout`
    // ignores the callback's return value, so this is a no-op change in
    // production.
    this.renewalTimer = this.setTimeoutFn(() => this.renew(), delayMs)
  }

  /** 70% of the lease duration, plus up to ±10% jitter (thundering-herd avoidance). */
  private renewalDelayMs(leaseDurationSeconds: number): number {
    const baseMs = leaseDurationSeconds * 1000 * LEASE_RENEWAL_THRESHOLD_RATIO
    const jitterFraction = (this.randomFn() * 2 - 1) * LEASE_RENEWAL_JITTER_RATIO
    return Math.max(0, Math.round(baseMs * (1 + jitterFraction)))
  }

  private cancelScheduledRenewal(): void {
    if (this.renewalTimer !== undefined) {
      this.clearTimeoutFn(this.renewalTimer)
      this.renewalTimer = undefined
    }
  }

  /**
   * Renews the current lease via Vault's `sys/leases/renew` endpoint.
   *
   * - On success: updates the tracked lease (Vault may extend it by less
   *   than requested) and schedules the next renewal.
   * - On denial (403/404 — the lease was revoked, expired server-side, or
   *   the token lacks permission): falls back to a full {@link reload},
   *   rotating in-memory secrets from a freshly-issued lease rather than
   *   continuing to serve one that Vault has already given up on.
   * - On any other failure (e.g. Vault unreachable): logs a metric and
   *   retries sooner than the normal schedule, so a transient blip doesn't
   *   let the lease silently expire.
   *
   * Never throws — a renewal failure must not crash the process.
   */
  private async renew(): Promise<void> {
    const lease = this.lease
    if (!lease) return
    const start = Date.now()

    try {
      const url = `${this.baseUrl.replace(/\/+$/, '')}/v1/sys/leases/renew`
      const response = await fetch(url, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        },
        body: JSON.stringify({ lease_id: lease.leaseId, increment: lease.leaseDurationSeconds }),
      })

      if (response.status === 403 || response.status === 404) {
        vaultLeaseRenewalTotal.labels('denied').inc()
        await this.reload()
        return
      }

      if (!response.ok) {
        throw new Error(`renew failed with status ${response.status}`)
      }

      const body = (await response.json()) as {
        lease_id?: string
        lease_duration?: number
        renewable?: boolean
      }
      this.lease = {
        leaseId: typeof body.lease_id === 'string' && body.lease_id !== '' ? body.lease_id : lease.leaseId,
        leaseDurationSeconds:
          typeof body.lease_duration === 'number' && body.lease_duration > 0
            ? body.lease_duration
            : lease.leaseDurationSeconds,
        renewable: body.renewable !== false,
      }
      vaultLeaseSecondsRemaining.set(this.lease.leaseDurationSeconds)
      vaultLeaseRenewalTotal.labels('success').inc()
      this.scheduleRenewalIfEligible()
    } catch {
      vaultLeaseRenewalTotal.labels('error').inc()
      this.renewalTimer = this.setTimeoutFn(() => this.renew(), LEASE_RENEWAL_ERROR_RETRY_MS)
    } finally {
      vaultLeaseRenewalDurationSeconds.observe((Date.now() - start) / 1000)
    }
  }
}
