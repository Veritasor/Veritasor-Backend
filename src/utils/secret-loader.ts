import fs from 'node:fs/promises'
import path from 'node:path'
import dotenv from 'dotenv'

export interface SecretLoader {
  get(key: string): string
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

export type SecretLoaderSource = 'env' | 'file' | 'vault'

export interface SecretLoaderFactoryOptions {
  source?: SecretLoaderSource
  filePath?: string
  vaultBaseUrl?: string
  vaultSecretPath?: string
  vaultToken?: string
}

abstract class BaseSecretLoader implements SecretLoader {
  protected loaded = false
  protected secrets = new Map<string, string>()

  abstract reload(): Promise<void>

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
        map.set(BaseSecretLoader.normalizeSecretKey(key), value)
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        map.set(BaseSecretLoader.normalizeSecretKey(key), String(value))
      }
    }
    return map
  }
}

export class EnvSecretLoader extends BaseSecretLoader {
  async reload(): Promise<void> {
    this.loaded = true
  }

  get(key: string): string {
    if (!this.loaded) {
      this.loaded = true
    }

    const normalizedKey = BaseSecretLoader.normalizeSecretKey(key)
    const envValue = process.env[normalizedKey]

    return this.toSecretValue(envValue, normalizedKey)
  }
}

export class FileSecretLoader extends BaseSecretLoader {
  constructor(private readonly filePath: string) {
    super()
  }

  async reload(): Promise<void> {
    const resolvedPath = path.resolve(this.filePath)

    let content: string
    try {
      content = await fs.readFile(resolvedPath, 'utf8')
    } catch (error) {
      throw new SecretLoadError(`Failed to read secret file at ${resolvedPath}`, error instanceof Error ? error : undefined)
    }

    const data = this.parseFile(resolvedPath, content)
    this.secrets = BaseSecretLoader.normalizeSecretValues(data)
    this.loaded = true
  }

  get(key: string): string {
    this.ensureLoaded()
    return this.toSecretValue(this.secrets.get(BaseSecretLoader.normalizeSecretKey(key)), key)
  }

  private parseFile(filePath: string, content: string): Record<string, unknown> {
    const trimmed = content.trim()
    const isJson = filePath.toLowerCase().endsWith('.json') || trimmed.startsWith('{')

    if (isJson) {
      try {
        const parsed = JSON.parse(content)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return parsed as Record<string, unknown>
        }
      } catch (error) {
        throw new SecretLoadError(`Failed to parse JSON secrets file at ${filePath}`, error instanceof Error ? error : undefined)
      }
    }

    try {
      return dotenv.parse(content)
    } catch (error) {
      throw new SecretLoadError(`Failed to parse dotenv secrets file at ${filePath}`, error instanceof Error ? error : undefined)
    }
  }
}

export class VaultSecretLoader extends BaseSecretLoader {
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
    this.secrets = BaseSecretLoader.normalizeSecretValues(payload)
    this.loaded = true
  }

  get(key: string): string {
    this.ensureLoaded()
    return this.toSecretValue(this.secrets.get(BaseSecretLoader.normalizeSecretKey(key)), key)
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

export function createSecretLoader(options: SecretLoaderFactoryOptions = {}): SecretLoader {
  const source = options.source ?? (process.env.SECRET_LOADER as SecretLoaderSource) ?? 'env'

  switch (source) {
    case 'env':
      return new EnvSecretLoader()
    case 'file': {
      const filePath = options.filePath ?? process.env.SECRET_FILE_PATH
      if (!filePath) {
        throw new SecretLoadError('SECRET_FILE_PATH is required when SECRET_LOADER=file')
      }
      return new FileSecretLoader(filePath)
    }
    case 'vault': {
      const baseUrl = options.vaultBaseUrl ?? process.env.VAULT_BASE_URL
      const secretPath = options.vaultSecretPath ?? process.env.VAULT_SECRET_PATH
      const token = options.vaultToken ?? process.env.VAULT_TOKEN

      if (!baseUrl) {
        throw new SecretLoadError('VAULT_BASE_URL is required when SECRET_LOADER=vault')
      }
      if (!secretPath) {
        throw new SecretLoadError('VAULT_SECRET_PATH is required when SECRET_LOADER=vault')
      }

      return new VaultSecretLoader(baseUrl, secretPath, token)
    }
    default:
      throw new SecretLoadError(`Unsupported secret loader source: ${source}`)
  }
}

export const secretLoader: SecretLoader = createSecretLoader()
