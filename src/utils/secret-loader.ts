import fs from 'node:fs/promises'
import path from 'node:path'
import dotenv from 'dotenv'
import {
  vaultLeaseRenewalDurationSeconds,
  vaultLeaseRenewalTotal,
  vaultLeaseSecondsRemaining,
} from '../metrics.js'

/** Fraction of the lease duration at which renewal is attempted (70%). */
const LEASE_RENEWAL_THRESHOLD_RATIO = 0.7
/**
 * Random jitter applied to the renewal delay, as a fraction of the base
 * delay (±10%), so that many instances sharing similar lease timing don't
 * all renew in the same instant (thundering herd).
 */
const LEASE_RENEWAL_JITTER_RATIO = 0.1
/** Retry delay after a renewal *request* failure (not a denial). */
const LEASE_RENEWAL_ERROR_RETRY_MS = 30_000

export interface SecretAdapter {
  get(key: string): Promise<string>
  reload(): Promise<void>
}

export class SecretLoaderError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SecretLoaderError'
  }
}

export class SecretNotFoundError extends SecretLoaderError {
  public readonly key: string

  constructor(key: string) {
    super(`Secret not found: ${key}`)
    this.name = 'SecretNotFoundError'
    this.key = key
  }
}

export class SecretNotLoadedError extends SecretLoaderError {
  constructor() {
    super('Secrets are not loaded yet')
    this.name = 'SecretNotLoadedError'
  }
}

export class SecretLoadError extends SecretLoaderError {
  constructor(message: string, public readonly cause?: Error) {
    super(message)
    this.name = 'SecretLoadError'
  }
}

export type SecretProvider = 'env' | 'aws' | 'vault'

export interface SecretLoaderOptions {
  provider?: SecretProvider
  timeout?: number
  fallbackEnabled?: boolean
  awsRegion?: string
  vaultBaseUrl?: string
  vaultSecretPath?: string
  vaultToken?: string
}

abstract class BaseSecretAdapter implements SecretAdapter {
  protected loaded = false
  protected secrets = new Map<string, string>()

  abstract reload(): Promise<void>

  abstract get(key: string): Promise<string>

  protected ensureLoaded(): void {
    if (!this.loaded) {
      throw new SecretNotLoadedError()
    }
  }

  protected toSecretValue(value: string | undefined, key: string): string {
    if (value === undefined || value === '') {
      throw new SecretNotFoundError(key)
    }
    return value
  }

  protected static normalizeSecretKey(key: string): string {
    return key.trim()
  }

  protected static normalizeSecretValues(values: Record<string, unknown>): Map<string, string> {
    const map = new Map<string, string>()
    for (const [key, value] of Object.entries(values)) {
      if (typeof value === 'string' && value !== '') {
        map.set(BaseSecretAdapter.normalizeSecretKey(key), value)
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        map.set(BaseSecretAdapter.normalizeSecretKey(key), String(value))
      }
    }
    return map
  }
}

export class EnvAdapter extends BaseSecretAdapter {
  async reload(): Promise<void> {
    this.loaded = true
  }

  async get(key: string): Promise<string> {
    if (!this.loaded) {
      this.loaded = true
    }
    const normalizedKey = BaseSecretAdapter.normalizeSecretKey(key)
    const envValue = process.env[normalizedKey]
    return this.toSecretValue(envValue, normalizedKey)
  }
}

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

  async get(key: string): Promise<string> {
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

export class AwsSecretsAdapter extends BaseSecretAdapter {
  constructor(private readonly region: string) {
    super()
  }

  async reload(): Promise<void> {
    this.loaded = true
  }

  async get(key: string): Promise<string> {
    this.ensureLoaded()
    try {
      const { SecretsManagerClient, GetSecretValueCommand } = await import('@aws-sdk/client-secrets-manager')
      const client = new SecretsManagerClient({ region: this.region })
      const command = new GetSecretValueCommand({ SecretId: key })
      const response = await client.send(command)
      
      if (response.SecretString) {
        try {
          const parsed = JSON.parse(response.SecretString)
          if (parsed && typeof parsed === 'object') {
            this.secrets = BaseSecretAdapter.normalizeSecretValues(parsed)
            return this.toSecretValue(Object.values(parsed)[0] as string | undefined, key)
          }
        } catch {
          return this.toSecretValue(response.SecretString, key)
        }
      }
      throw new SecretLoadError(`Secret ${key} has no SecretString`)
    } catch (error) {
      throw new SecretLoadError(`Failed to fetch secret from AWS Secrets Manager: ${key}`, error instanceof Error ? error : undefined)
    }
  }
}

class FailoverSecretLoader implements SecretAdapter {
  private primaryAdapter: SecretAdapter
  private fallbackAdapter: SecretAdapter
  private timeout: number

  constructor(primaryAdapter: SecretAdapter, fallbackAdapter: SecretAdapter, timeout: number = 5000) {
    this.primaryAdapter = primaryAdapter
    this.fallbackAdapter = fallbackAdapter
    this.timeout = timeout
  }

  async reload(): Promise<void> {
    try {
      await this.withTimeout(this.primaryAdapter.reload(), this.timeout)
    } catch {
      await this.fallbackAdapter.reload()
    }
  }

  async get(key: string): Promise<string> {
    try {
      return await this.withTimeout(this.primaryAdapter.get(key), this.timeout)
    } catch {
      return await this.fallbackAdapter.get(key)
    }
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new SecretLoadError('Operation timed out')), timeoutMs)
      )
    ])
  }
}

export function createSecretLoader(options: SecretLoaderOptions = {}): SecretAdapter {
  const provider = options.provider ?? (process.env.SECRET_PROVIDER as SecretProvider) ?? 'env'
  const timeout = options.timeout ?? 5000
  const fallbackEnabled = options.fallbackEnabled ?? true
  const fallbackAdapter = new EnvAdapter()

  let primaryAdapter: SecretAdapter
  switch (provider) {
    case 'env':
      return fallbackAdapter
    case 'aws': {
      const region = options.awsRegion ?? process.env.AWS_REGION
      if (!region) {
        throw new SecretLoadError('AWS_REGION is required when SECRET_PROVIDER=aws')
      }
      primaryAdapter = new AwsSecretsAdapter(region)
      break
    }
    case 'vault': {
      const baseUrl = options.vaultBaseUrl ?? process.env.VAULT_BASE_URL
      const secretPath = options.vaultSecretPath ?? process.env.VAULT_SECRET_PATH
      const token = options.vaultToken ?? process.env.VAULT_TOKEN

      if (!baseUrl) {
        throw new SecretLoadError('VAULT_BASE_URL is required when SECRET_PROVIDER=vault')
      }
      if (!secretPath) {
        throw new SecretLoadError('VAULT_SECRET_PATH is required when SECRET_PROVIDER=vault')
      }
      primaryAdapter = new VaultAdapter(baseUrl, secretPath, token)
      break
    }
    default:
      throw new SecretLoadError(`Unsupported secret provider: ${provider}`)
  }

  if (fallbackEnabled) {
    return new FailoverSecretLoader(primaryAdapter, fallbackAdapter, timeout)
  }

  return primaryAdapter
}

export const secretLoader: SecretAdapter = createSecretLoader()
