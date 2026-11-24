
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
  source?: SecretProvider
  filePath?: string
  timeout?: number
  fallbackEnabled?: boolean
  awsRegion?: string
  awsSecondaryRegion?: string
  vaultBaseUrl?: string
  vaultSecretPath?: string
  vaultToken?: string
  gcpProjectId?: string
}

export abstract class BaseSecretAdapter implements SecretLoader {
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
