import fs from 'node:fs/promises'
import path from 'node:path'
import dotenv from 'dotenv'

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

export class VaultAdapter extends BaseSecretAdapter {
  constructor(
    private readonly baseUrl: string,
    private readonly secretPath: string,
    private readonly token?: string,
  ) {
    super()
  }

  async reload(): Promise<void> {
    const normalizedBaseUrl = this.baseUrl.replace(/\/+$/, '')
    const normalizedSecretPath = this.secretPath.replace(/^\/+/, '')
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
    this.secrets = BaseSecretAdapter.normalizeSecretValues(payload)
    this.loaded = true
  }

  async get(key: string): Promise<string> {
    this.ensureLoaded()
    return this.toSecretValue(this.secrets.get(BaseSecretAdapter.normalizeSecretKey(key)), key)
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
