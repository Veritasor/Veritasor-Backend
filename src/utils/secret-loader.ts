/**
 * Public facade and provider selection. Provider adapters live in secrets/{env,
 * file,aws,gsm,vault}.ts; base.ts owns the shared contract/errors, failover.ts
 * coordinates reload/fallback, and kms-disk-cache.ts owns encrypted caching.
 * Cloud SDK imports stay inside provider reload/client methods and cache I/O.
 */
import { config } from '../config/index.js'
import { BaseSecretAdapter, SecretLoadError } from './secrets/base.js'
import type { SecretAdapter, SecretLoader, SecretLoaderOptions, SecretProvider } from './secrets/base.js'
import { EnvAdapter } from './secrets/env.js'
import { FileAdapter } from './secrets/file.js'
import { AwsSecretsAdapter } from './secrets/aws.js'
import { GsmSecretAdapter } from './secrets/gsm.js'
import { VaultAdapter } from './secrets/vault.js'
import { KmsDiskCache } from './secrets/kms-disk-cache.js'
import { FailoverSecretLoader } from './secrets/failover.js'

export type { SecretAdapter, SecretLoader, SecretLoaderOptions, SecretProvider } from './secrets/base.js'
export { SecretLoaderError, SecretNotFoundError, SecretNotLoadedError, SecretLoadError } from './secrets/base.js'
export { EnvAdapter, FileAdapter, AwsSecretsAdapter, GsmSecretAdapter, VaultAdapter }
export type { VaultLease, VaultAdapterOptions } from './secrets/vault.js'

export function createSecretLoader(options: SecretLoaderOptions = {}): SecretAdapter {
  const provider =
    options.provider ??
    options.source ??
    (process.env.SECRET_LOADER as SecretProvider) ??
    (process.env.SECRET_PROVIDER as SecretProvider) ??
    (config?.secretLoader?.source as SecretProvider) ??
    'env'
  const timeout = options.timeout ?? 5000
  const fallbackEnabled = options.fallbackEnabled ?? true
  const fallbackAdapter = new EnvAdapter()

  let primaryAdapter: BaseSecretAdapter
  switch (provider) {
    case 'env':
      return fallbackAdapter
    case 'file': {
      const filePath =
        options.filePath ??
        config?.secretLoader?.filePath ??
        process.env.SECRET_FILE_PATH
      if (!filePath) {
        throw new SecretLoadError('SECRET_FILE_PATH is required when SECRET_LOADER=file')
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
      const baseUrl =
        options.vaultBaseUrl ??
        config?.secretLoader?.vault?.baseUrl ??
        process.env.VAULT_BASE_URL
      const secretPath =
        options.vaultSecretPath ??
        config?.secretLoader?.vault?.secretPath ??
        process.env.VAULT_SECRET_PATH
      const token =
        options.vaultToken ??
        config?.secretLoader?.vault?.token ??
        process.env.VAULT_TOKEN

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
    const kmsKeyId =
      config?.secretLoader?.cache?.kmsKeyId ?? process.env.SECRET_CACHE_KMS_KEY_ID
    const cachePath =
      config?.secretLoader?.cache?.path ?? process.env.SECRET_CACHE_PATH
    const ttlMinutes =
      config?.secretLoader?.cache?.ttlMinutes ??
      Number(process.env.SECRET_CACHE_TTL_MINUTES || 60 * 24)
    
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
