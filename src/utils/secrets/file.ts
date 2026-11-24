import fs from 'node:fs/promises'
import path from 'node:path'
import dotenv from 'dotenv'
import { BaseSecretAdapter, SecretLoadError } from './base.js'

export class FileAdapter extends BaseSecretAdapter {
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
    this.secrets = BaseSecretAdapter.normalizeSecretValues(data)
    this.loaded = true
  }

  async get(key: string): Promise<string> {
    this.ensureLoaded()
    return this.toSecretValue(this.secrets.get(BaseSecretAdapter.normalizeSecretKey(key)), key)
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
