import { BaseSecretAdapter } from './base.js'

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
