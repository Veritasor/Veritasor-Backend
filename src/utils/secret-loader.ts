import fs from 'node:fs/promises'
import path from 'node:path'
import dotenv from 'dotenv'
import { logger } from './logger.js'

export interface SecretLoader {
  get(key: string): string
  reload(): Promise<void>
}

export type SecretAdapter = SecretLoader

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

export type SecretProvider = 'env' | 'file' | 'aws' | 'vault' | 'gsm'

export interface SecretLoaderOptions {
  provider?: SecretProvider
  timeout?: number
  fallbackEnabled?: boolean
  awsRegion?: string
  awsSecondaryRegion?: string
  vaultBaseUrl?: string
  vaultSecretPath?: string
  vaultToken?: string
  gcpProjectId?: string
}

abstract class BaseSecretAdapter implements SecretLoader {
  protected loaded = false
  protected secrets = new Map<string, string>()

  abstract reload(): Promise<void>

  abstract get(key: string): string

  get allSecrets(): Map<string, string> {
    return new Map(this.secrets)
  }

  set allSecrets(secrets: Map<string, string>) {
    this.secrets = new Map(secrets)
  }

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
    const entries = Object.entries(process.env)
      .filter(([, value]) => typeof value === 'string' && value.trim() !== '')
      .map(([key, value]) => [BaseSecretAdapter.normalizeSecretKey(key), value] as const)

    this.secrets = new Map(entries)
    this.loaded = true
  }

  get(key: string): string {
    if (!this.loaded) {
      this.loaded = true
    }
    const normalizedKey = BaseSecretAdapter.normalizeSecretKey(key)
    const envValue = process.env[normalizedKey]
    return this.toSecretValue(envValue, normalizedKey)
  }
}

export class FileAdapter extends BaseSecretAdapter {
  constructor(private readonly filePath: string = process.env.SECRET_FILE_PATH ?? '') {
    super()
  }

  async reload(): Promise<void> {
    const resolvedPath = this.filePath || process.env.SECRET_FILE_PATH
    if (!resolvedPath || resolvedPath.trim() === '') {
      throw new SecretLoadError('SECRET_FILE_PATH is required when SECRET_PROVIDER=file')
    }

    const raw = await fs.readFile(resolvedPath, 'utf8')
    const parsed = raw.trim().startsWith('{') ? JSON.parse(raw) : dotenv.parse(raw)
    const normalized = BaseSecretAdapter.normalizeSecretValues(parsed)

    if (normalized.size === 0) {
      throw new SecretLoadError(`Secret file contains no usable values: ${resolvedPath}`)
    }

    this.secrets = normalized
    this.loaded = true
  }

  get(key: string): string {
    this.ensureLoaded()
    const normalizedKey = BaseSecretAdapter.normalizeSecretKey(key)
    return this.toSecretValue(this.secrets.get(normalizedKey), normalizedKey)
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

export class AwsSecretsAdapter extends BaseSecretAdapter {
  constructor(
    private readonly primaryRegion: string,
    private readonly secondaryRegion?: string,
  ) {
    super()
  }

  async reload(): Promise<void> {
    this.secrets = new Map()
    this.loaded = true

    try {
      const { SecretsManagerClient, GetSecretValueCommand } = await import('@aws-sdk/client-secrets-manager')
      const client = new SecretsManagerClient({ region: this.primaryRegion })
      const response = await client.send(new GetSecretValueCommand({ SecretId: process.env.AWS_SECRET_NAME ?? 'veritasor' }))

      if (response.SecretString) {
        try {
          const parsed = JSON.parse(response.SecretString)
          if (parsed && typeof parsed === 'object') {
            this.secrets = BaseSecretAdapter.normalizeSecretValues(parsed)
            return
          }
        } catch {
          this.secrets.set('AWS_SECRET', response.SecretString)
          return
        }
      }
    } catch {
      // leave empty; callers use environment fallback or failover loader
    }
  }

  get(key: string): string {
    this.ensureLoaded()
    const normalized = BaseSecretAdapter.normalizeSecretKey(key)
    const direct = this.secrets.get(normalized)
    if (direct) {
      return direct
    }

    const fallback = this.secrets.size > 0 ? Array.from(this.secrets.values())[0] : undefined
    return this.toSecretValue(fallback, key)
  }

  // Secondary region is DR fallback only, not a reconciliation source.
  private isRetryableError(error: unknown): boolean {
    if (!(error instanceof Error)) return false

    const err = error as Record<string, unknown>
    const metadata = err.$metadata as Record<string, unknown> | undefined

    if (metadata?.httpStatusCode && Number(metadata.httpStatusCode) >= 500) {
      return true
    }

    if (!metadata) {
      const name = String(err.name ?? '')
      const message = String(err.message ?? '')
      if (/timeout|network|connection|econnrefused|enotfound|etimedout/i.test(name + ' ' + message)) {
        return true
      }
    }

    return false
  }
}

export class GsmSecretAdapter extends BaseSecretAdapter {
  private client: { accessSecretVersion: (params: { name: string }) => Promise<[{ payload?: { data?: Buffer } }]> } | null = null

  constructor(private readonly projectId: string) {
    super()
  }

  async reload(): Promise<void> {
    this.secrets = new Map()
    this.loaded = true

    try {
      const client = await this.getClient()
      const secretName = process.env.GSM_SECRET_NAME ?? 'DEFAULT_SECRET'
      const name = `projects/${this.projectId}/secrets/${secretName}/versions/latest`
      const [version] = await client.accessSecretVersion({ name })
      const payload = version.payload?.data?.toString('utf8')
      if (payload) {
        this.secrets.set(secretName, payload)
      }
    } catch {
      // leave empty; fallback path handles missing values and hot reload
    }
  }

  get(key: string): string {
    this.ensureLoaded()
    const normalized = BaseSecretAdapter.normalizeSecretKey(key)
    const direct = this.secrets.get(normalized)
    if (direct) {
      return direct
    }

    const fallback = this.secrets.size > 0 ? Array.from(this.secrets.values())[0] : undefined
    return this.toSecretValue(fallback, key)
  }

  private async getClient(): Promise<{ accessSecretVersion: (params: { name: string }) => Promise<[{ payload?: { data?: Buffer } }]> }> {
    if (!this.client) {
      const { SecretManagerServiceClient } = await import('@google-cloud/secret-manager')
      this.client = new SecretManagerServiceClient()
    }
    return this.client
  }
}

class KmsDiskCache {
  private readonly algorithm = 'aes-256-gcm'

  constructor(
    private readonly kmsKeyId: string,
    private readonly cachePath: string,
    private readonly ttlMinutes: number,
    private readonly region: string = process.env.AWS_REGION || 'us-east-1'
  ) {}

  async save(secrets: Map<string, string>): Promise<void> {
    try {
      const { KMSClient, GenerateDataKeyCommand } = await import('@aws-sdk/client-kms')
      const client = new KMSClient({ region: this.region })
      
      const dataKeyResponse = await client.send(
        new GenerateDataKeyCommand({
          KeyId: this.kmsKeyId,
          KeySpec: 'AES_256',
        })
      )

      if (!dataKeyResponse.Plaintext || !dataKeyResponse.CiphertextBlob) {
        throw new Error('Failed to generate KMS data key')
      }

      const crypto = await import('node:crypto')
      const iv = crypto.randomBytes(12)
      const cipher = crypto.createCipheriv(this.algorithm, Buffer.from(dataKeyResponse.Plaintext), iv)
      
      const payloadStr = JSON.stringify(Object.fromEntries(secrets))
      let encrypted = cipher.update(payloadStr, 'utf8', 'base64')
      encrypted += cipher.final('base64')
      const authTag = cipher.getAuthTag()

      const cachePayload = {
        ciphertextKey: Buffer.from(dataKeyResponse.CiphertextBlob).toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        encryptedData: encrypted,
        expiresAt: Date.now() + this.ttlMinutes * 60 * 1000,
      }

      const fs = await import('node:fs/promises')
      const path = await import('node:path')
      
      await fs.mkdir(path.dirname(this.cachePath), { recursive: true })
      await fs.writeFile(this.cachePath, JSON.stringify(cachePayload), { mode: 0o600 })
    } catch (err) {
      logger.error('Failed to save KMS encrypted cache', err instanceof Error ? err.message : String(err))
    }
  }

  async load(): Promise<Map<string, string> | null> {
    try {
      const fs = await import('node:fs/promises')
      let fileContent: string
      try {
        fileContent = await fs.readFile(this.cachePath, 'utf8')
      } catch (err: any) {
        if (err.code === 'ENOENT') return null
        throw err
      }

      const parsed = JSON.parse(fileContent)
      if (Date.now() > parsed.expiresAt) {
        logger.warn('KMS cache expired, ignoring')
        return null
      }

      const { KMSClient, DecryptCommand } = await import('@aws-sdk/client-kms')
      const client = new KMSClient({ region: this.region })
      
      const decryptResponse = await client.send(
        new DecryptCommand({
          CiphertextBlob: Buffer.from(parsed.ciphertextKey, 'base64'),
        })
      )

      if (!decryptResponse.Plaintext) {
        throw new Error('Failed to decrypt KMS data key')
      }

      const crypto = await import('node:crypto')
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        Buffer.from(decryptResponse.Plaintext),
        Buffer.from(parsed.iv, 'base64')
      )
      decipher.setAuthTag(Buffer.from(parsed.authTag, 'base64'))

      let decrypted = decipher.update(parsed.encryptedData, 'base64', 'utf8')
      decrypted += decipher.final('utf8')

      const secretsRecord = JSON.parse(decrypted)
      
      // Audit cache hit
      logger.info('Secret loader fell back to KMS-encrypted disk cache')
      
      const map = new Map<string, string>()
      for (const [k, v] of Object.entries(secretsRecord)) {
        map.set(k, v as string)
      }
      return map
    } catch (err) {
      logger.error('Failed to load or decrypt KMS cache (possible tampering or invalid format)', err instanceof Error ? err.message : String(err))
      return null
    }
  }
}

class FailoverSecretLoader extends BaseSecretAdapter {
  private primaryAdapter: BaseSecretAdapter
  private fallbackAdapter: BaseSecretAdapter
  private timeout: number
  private diskCache?: KmsDiskCache

  constructor(primaryAdapter: BaseSecretAdapter, fallbackAdapter: BaseSecretAdapter, timeout: number = 5000, diskCache?: KmsDiskCache) {
    super()
    this.primaryAdapter = primaryAdapter
    this.fallbackAdapter = fallbackAdapter
    this.timeout = timeout
    this.diskCache = diskCache
  }

  async reload(): Promise<void> {
    try {
      await this.withTimeout(this.primaryAdapter.reload(), this.timeout)
      this.allSecrets = this.primaryAdapter.allSecrets
      this.loaded = true
      
      if (this.diskCache) {
        await this.diskCache.save(this.allSecrets)
      }
    } catch (primaryErr) {
      if (this.diskCache) {
        const cached = await this.diskCache.load()
        if (cached) {
          this.allSecrets = cached
          this.loaded = true
          return
        }
      }
      await this.fallbackAdapter.reload()
      this.allSecrets = this.fallbackAdapter.allSecrets
      this.loaded = true
    }
  }

  get(key: string): string {
    this.ensureLoaded()
    const normalizedKey = BaseSecretAdapter.normalizeSecretKey(key)
    const direct = this.secrets.get(normalizedKey)
    if (direct !== undefined) {
      return direct
    }

    try {
      return this.fallbackAdapter.get(key)
    } catch (error) {
      if (error instanceof SecretNotFoundError) {
        return this.toSecretValue(undefined, key)
      }
      throw error
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

export function createSecretLoader(options: SecretLoaderOptions = {}): SecretLoader {
  const provider = options.provider ?? (process.env.SECRET_PROVIDER as SecretProvider) ?? 'env'
  const timeout = options.timeout ?? 5000
  const fallbackEnabled = options.fallbackEnabled ?? true
  const fallbackAdapter = new EnvAdapter()

  let primaryAdapter: BaseSecretAdapter
  switch (provider) {
    case 'env':
      return fallbackAdapter
    case 'file': {
      const filePath = process.env.SECRET_FILE_PATH || options.vaultBaseUrl
      if (!filePath) {
        throw new SecretLoadError('SECRET_FILE_PATH is required when SECRET_PROVIDER=file')
      }
      primaryAdapter = new FileAdapter(filePath)
      break
    }
    case 'aws': {
      const region = options.awsRegion ?? process.env.AWS_REGION
      if (!region) {
        throw new SecretLoadError('AWS_REGION is required when SECRET_PROVIDER=aws')
      }
      const secondaryRegion = options.awsSecondaryRegion ?? process.env.AWS_SECONDARY_REGION
      primaryAdapter = new AwsSecretsAdapter(region, secondaryRegion)
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
    case 'gsm': {
      const projectId = options.gcpProjectId ?? process.env.GCP_PROJECT_ID
      if (!projectId) {
        throw new SecretLoadError('GCP_PROJECT_ID is required when SECRET_PROVIDER=gsm')
      }
      primaryAdapter = new GsmSecretAdapter(projectId)
      break
    }
    default:
      throw new SecretLoadError(`Unsupported secret provider: ${provider}`)
  }

  if (fallbackEnabled) {
    const kmsKeyId = process.env.SECRET_CACHE_KMS_KEY_ID
    const cachePath = process.env.SECRET_CACHE_PATH
    const ttlMinutes = Number(process.env.SECRET_CACHE_TTL_MINUTES || 60 * 24)
    
    let diskCache: KmsDiskCache | undefined
    if (kmsKeyId && cachePath) {
      diskCache = new KmsDiskCache(
        kmsKeyId,
        cachePath,
        ttlMinutes,
        process.env.AWS_REGION
      )
    }

    return new FailoverSecretLoader(primaryAdapter, fallbackAdapter, timeout, diskCache)
  }

  return primaryAdapter
}

export const secretLoader: SecretLoader = createSecretLoader()
