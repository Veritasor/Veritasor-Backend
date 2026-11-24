import { BaseSecretAdapter } from './base.js'

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
