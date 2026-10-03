import { afterEach, vi } from 'vitest'
import { EnvAdapter, VaultAdapter, AwsSecretsAdapter } from './secret-loader.js'
import { describeSecretProviderContract } from './secret-provider.contract.js'

let mockSecretString: string
let mockSend: ReturnType<typeof vi.fn>

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

afterEach(() => {
  restoreEnv()
  vi.restoreAllMocks()
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
