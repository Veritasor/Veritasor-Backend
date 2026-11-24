import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const originalEnv = { ...process.env }
let dir: string
let imports: string[]

beforeEach(async () => {
  vi.resetModules()
  imports = []
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'secret-extraction-'))
  vi.doMock('@aws-sdk/client-secrets-manager', () => {
    imports.push('aws')
    return {
      SecretsManagerClient: class { send = vi.fn(async () => ({ SecretString: '{"KEY":"aws-value"}' })) },
      GetSecretValueCommand: class {},
    }
  })
  vi.doMock('@google-cloud/secret-manager', () => {
    imports.push('gsm')
    return {
      SecretManagerServiceClient: class {
        accessSecretVersion = vi.fn(async () => [{ payload: { data: Buffer.from('gsm-value') } }])
      },
    }
  })
  vi.doMock('@aws-sdk/client-kms', () => {
    imports.push('kms')
    return {
      KMSClient: class {
        send = vi.fn(async () => ({ Plaintext: new Uint8Array(32), CiphertextBlob: new Uint8Array(16) }))
      },
      GenerateDataKeyCommand: class {},
      DecryptCommand: class {},
    }
  })
  for (const key of ['SECRET_LOADER', 'SECRET_PROVIDER', 'SECRET_CACHE_KMS_KEY_ID', 'SECRET_CACHE_PATH']) {
    delete process.env[key]
  }
})

afterEach(async () => {
  vi.unstubAllGlobals()
  for (const key of Object.keys(process.env)) {
    if (!(key in originalEnv)) delete process.env[key]
  }
  Object.assign(process.env, originalEnv)
  for (const sdk of ['@aws-sdk/client-secrets-manager', '@google-cloud/secret-manager', '@aws-sdk/client-kms']) {
    vi.doUnmock(sdk)
  }
  await fs.rm(dir, { recursive: true, force: true })
})

describe('secret provider extraction compatibility', () => {
  it('retains every runtime export and shares class/error identities with provider modules', async () => {
    const facade = await import('../secret-loader.js')
    expect(Object.keys(facade).sort()).toEqual([
      'AwsSecretsAdapter', 'EnvAdapter', 'FileAdapter', 'GsmSecretAdapter',
      'SecretLoadError', 'SecretLoaderError', 'SecretNotFoundError', 'SecretNotLoadedError',
      'VaultAdapter', 'createSecretLoader', 'secretLoader',
    ].sort())
    expect(facade.EnvAdapter).toBe((await import('./env.js')).EnvAdapter)
    expect(facade.FileAdapter).toBe((await import('./file.js')).FileAdapter)
    expect(facade.AwsSecretsAdapter).toBe((await import('./aws.js')).AwsSecretsAdapter)
    expect(facade.GsmSecretAdapter).toBe((await import('./gsm.js')).GsmSecretAdapter)
    expect(facade.VaultAdapter).toBe((await import('./vault.js')).VaultAdapter)
    expect(facade.SecretNotFoundError).toBe((await import('./base.js')).SecretNotFoundError)
    expect(facade.secretLoader).toBeInstanceOf(facade.EnvAdapter)
    expect(() => facade.secretLoader.get('EXTRACTION_MISSING')).toThrow(facade.SecretNotFoundError)
    expect(imports).toEqual([])
  }, 30_000)

  it.each(['env', 'file', 'vault'] as const)('%s reload never evaluates cloud SDK modules', async provider => {
    const { createSecretLoader } = await import('../secret-loader.js')
    const filePath = path.join(dir, 'secrets.json')
    await fs.writeFile(filePath, '{"KEY":"value"}')
    process.env.KEY = 'value'
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"data":{"KEY":"value"}}')))
    const loader = createSecretLoader({
      provider, filePath, vaultBaseUrl: 'https://vault.example', vaultSecretPath: 'secret', fallbackEnabled: false,
    })
    await loader.reload()
    expect(await loader.get('KEY')).toBe('value')
    expect(imports).toEqual([])
  })

  it.each(['aws', 'gsm'] as const)('%s loads only its selected SDK, after reload', async provider => {
    const { createSecretLoader } = await import('../secret-loader.js')
    process.env.GSM_SECRET_NAME = 'KEY'
    const loader = createSecretLoader({ provider, awsRegion: 'us-east-1', gcpProjectId: 'project', fallbackEnabled: false })
    expect(imports).toEqual([])
    await loader.reload()
    expect(loader.get('KEY')).toBe(`${provider}-value`)
    // Preserve legacy single-secret aliases as well as exact-key lookup.
    expect(loader.get('ALIAS')).toBe(`${provider}-value`)
    expect(imports).toEqual([provider])
  })

  it('retains file parsing, asynchronous reads, normalization and copied snapshots', async () => {
    const { FileAdapter, SecretNotLoadedError, SecretNotFoundError } = await import('../secret-loader.js')
    const file = path.join(dir, 'secrets.json')
    await fs.writeFile(file, '{" KEY ":"first","COUNT":2,"ENABLED":false}')
    const loader = new FileAdapter(file)
    await expect(loader.get('KEY')).rejects.toThrow(SecretNotLoadedError)
    await loader.reload()
    expect(await loader.get('KEY')).toBe('first')
    expect(await loader.get('COUNT')).toBe('2')
    expect(await loader.get('ENABLED')).toBe('false')
    loader.allSecrets.set('KEY', 'untrusted')
    expect(await loader.get('KEY')).toBe('first')
    await fs.writeFile(file, '{"KEY":"rotated"}')
    await loader.reload()
    expect(await loader.get('KEY')).toBe('rotated')
    await expect(loader.get('COUNT')).rejects.toThrow(SecretNotFoundError)
  })

  it('preserves failover and loads KMS only when encrypted caching is configured', async () => {
    const { createSecretLoader } = await import('../secret-loader.js')
    const filePath = path.join(dir, 'secrets.json')
    await fs.writeFile(filePath, '{"KEY":"cached"}')
    process.env.SECRET_CACHE_KMS_KEY_ID = 'key-id'
    process.env.SECRET_CACHE_PATH = path.join(dir, 'cache.enc')
    const loader = createSecretLoader({ provider: 'file', filePath })
    expect(imports).toEqual([])
    await loader.reload()
    expect(loader.get('KEY')).toBe('cached')
    expect(imports).toEqual(['kms'])
    expect(JSON.parse(await fs.readFile(process.env.SECRET_CACHE_PATH, 'utf8'))).toHaveProperty('encryptedData')

    process.env.FALLBACK_KEY = 'fallback'
    const fallback = createSecretLoader({ provider: 'file', filePath: path.join(dir, 'missing') })
    await fallback.reload()
    expect(fallback.get('KEY')).toBe('cached')
    expect(fallback.get('FALLBACK_KEY')).toBe('fallback')
  })
})
