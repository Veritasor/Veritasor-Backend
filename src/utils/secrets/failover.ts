import { BaseSecretAdapter, SecretLoadError, SecretNotFoundError } from './base.js'
import { KmsDiskCache } from './kms-disk-cache.js'

export class FailoverSecretLoader extends BaseSecretAdapter {
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
