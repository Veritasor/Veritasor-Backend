import { afterEach, vi } from 'vitest'
import fs from 'node:fs/promises'
import { writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { EnvAdapter } from './secrets/env.js'
import { FileAdapter } from './secrets/file.js'
import { VaultAdapter } from './secrets/vault.js'
import { AwsSecretsAdapter } from './secrets/aws.js'
import { GsmSecretAdapter } from './secrets/gsm.js'
import { describeSecretProviderContract } from './secret-provider.contract.js'

let mockSecretString: string
let mockSend: ReturnType<typeof vi.fn>
let mockAccessSecretVersion: ReturnType<typeof vi.fn>
const directories: string[] = []

vi.mock('@google-cloud/secret-manager', () => ({
  SecretManagerServiceClient: vi.fn(function () {
    return { accessSecretVersion: mockAccessSecretVersion }
  }),
}))

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn(function () {
    return { send: mockSend }
  }),
  GetSecretValueCommand: vi.fn(function (input: { SecretId: string }) { return input }),
}))

const ORIGINAL_ENV = { ...process.env }

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) {
      delete process.env[key]
    }
  }
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    process.env[key] = value
  }
}

afterEach(async () => {
  restoreEnv()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  await Promise.all(directories.splice(0).map(dir => fs.rm(dir, { recursive: true, force: true })))
})

describeSecretProviderContract('EnvAdapter', async () => ({
  adapter: new EnvAdapter(),
  seed: (key, value) => { process.env[key] = value },
}))

describeSecretProviderContract('VaultAdapter', async () => {
  let payload: Record<string, unknown> = { data: {} }

  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    json: vi.fn(async () => payload),
  })) as typeof fetch)

  return {
    adapter: new VaultAdapter('https://vault.example.com', 'secrets', 'token'),
    seed: (_key, value) => { payload = { data: { CONTRACT_TEST_KEY: value } } },
  }
})

describeSecretProviderContract('AwsSecretsAdapter', async () => {
  mockSecretString = '{}'
  mockSend = vi.fn(async (command) => {
    const key = command.SecretId
    if (key === 'CONTRACT_MISSING_KEY') {
      throw Object.assign(new Error('Secrets Manager can\'t find the specified secret'), {
        name: 'ResourceNotFoundException',
        $metadata: { httpStatusCode: 404 },
      })
    }
    return { SecretString: mockSecretString }
  })

  return {
    adapter: new AwsSecretsAdapter('us-east-1'),
    seed: (_key, value) => { mockSecretString = JSON.stringify({ CONTRACT_TEST_KEY: value }) },
  }
})

describeSecretProviderContract('FileAdapter', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'secret-provider-contract-'))
  directories.push(dir)
  const file = path.join(dir, 'secrets.json')
  await fs.writeFile(file, '{}')
  return {
    adapter: new FileAdapter(file),
    seed: (key, value) => {
      // The contract seed hook is synchronous; write before reload reads it.
      writeFileSync(file, JSON.stringify({ [key]: value }))
    },
  }
})

describeSecretProviderContract('GsmSecretAdapter', async () => {
  let value: string | undefined
  process.env.GSM_SECRET_NAME = 'CONTRACT_TEST_KEY'
  mockAccessSecretVersion = vi.fn(async () => [{ payload: { data: value === undefined ? undefined : Buffer.from(value) } }])
  return {
    adapter: new GsmSecretAdapter('contract-project'),
    seed: (_key, next) => { value = next },
  }
})
