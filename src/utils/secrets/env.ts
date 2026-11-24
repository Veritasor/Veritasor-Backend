import { BaseSecretAdapter } from './base.js'

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
