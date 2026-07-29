import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Reset all mocks before importing the module under test
let tracingMod: typeof import('../../src/tracing.js')
const originalEnv = { ...process.env }

async function importTracing() {
  // Dynamic import so env is read fresh
  tracingMod = await import('../../src/tracing.js')
  return tracingMod
}

describe('resolveCloudDetectorTimeoutMs', () => {
  beforeEach(async () => {
    vi.resetModules()
    delete process.env.CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS
    await importTracing()
  })

  afterEach(() => {
    process.env = { ...originalEnv }
  })

  it('returns the default 1000 ms when env is unset', () => {
    expect(tracingMod.resolveCloudDetectorTimeoutMs()).toBe(1000)
  })

  it('reads CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS from the environment', () => {
    process.env.CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = '2000'
    expect(tracingMod.resolveCloudDetectorTimeoutMs()).toBe(2000)
  })

  it('clamps below the minimum (100 ms)', () => {
    process.env.CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = '5'
    expect(tracingMod.resolveCloudDetectorTimeoutMs()).toBe(100)
  })

  it('clamps above the maximum (5000 ms)', () => {
    process.env.CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = '60000'
    expect(tracingMod.resolveCloudDetectorTimeoutMs()).toBe(5000)
  })

  it('falls back to default when env is non-numeric', () => {
    process.env.CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = 'abc'
    expect(tracingMod.resolveCloudDetectorTimeoutMs()).toBe(1000)
  })
})

describe('detectAwsResources', () => {
  let fetchImpl: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    vi.resetModules()
    await importTracing()
    fetchImpl = vi.fn()
  })

  it('returns empty attributes when fetch times out (AbortError)', async () => {
    const controller = new AbortController()
    controller.abort()
    const attrs = await tracingMod.detectAwsResources(controller.signal, fetchImpl)
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(attrs).toEqual({})
  })

  it('returns AWS attributes when metadata service responds', async () => {
    fetchImpl
      .mockResolvedValueOnce({ ok: true, text: async () => 'i-abc123' })       // instance-id
      .mockResolvedValueOnce({ ok: true, text: async () => 't3.medium' })        // instance-type
      .mockResolvedValueOnce({ ok: true, text: async () => 'us-east-1' })        // region
      .mockResolvedValueOnce({ ok: true, text: async () => 'us-east-1a' })       // az
      .mockResolvedValueOnce({ ok: true, json: async () => ({ AccountId: '123456789012' }) }) // account

    const controller = new AbortController()
    const attrs = await tracingMod.detectAwsResources(controller.signal, fetchImpl)
    expect(attrs).toMatchObject({
      'cloud.provider': 'aws',
      'cloud.platform': 'aws_ec2',
      'host.id': 'i-abc123',
      'host.type': 't3.medium',
      'cloud.region': 'us-east-1',
      'cloud.availability_zone': 'us-east-1a',
      'cloud.account.id': '123456789012',
    })
  })

  it('returns empty when all responses are not ok', async () => {
    fetchImpl.mockResolvedValue({ ok: false })

    const controller = new AbortController()
    const attrs = await tracingMod.detectAwsResources(controller.signal, fetchImpl)
    expect(attrs).toEqual({})
  })
})

describe('detectGcpResources', () => {
  let fetchImpl: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    vi.resetModules()
    await importTracing()
    fetchImpl = vi.fn()
  })

  it('returns empty when aborted before calls', async () => {
    const controller = new AbortController()
    controller.abort()
    const attrs = await tracingMod.detectGcpResources(controller.signal, fetchImpl)
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(attrs).toEqual({})
  })

  it('returns GCP attributes when metadata server responds', async () => {
    fetchImpl
      .mockResolvedValueOnce({ ok: true, text: async () => '1234567890123456789' })      // instance-id
      .mockResolvedValueOnce({ ok: true, text: async () => 'my-gce-instance' })          // instance-name
      .mockResolvedValueOnce({ ok: true, text: async () => 'projects/my-project/zones/us-central1-a' }) // zone
      .mockResolvedValueOnce({ ok: true, text: async () => 'my-project' })               // project-id

    const controller = new AbortController()
    const attrs = await tracingMod.detectGcpResources(controller.signal, fetchImpl)
    expect(attrs).toMatchObject({
      'cloud.provider': 'gcp',
      'cloud.platform': 'gcp_compute_engine',
      'host.id': '1234567890123456789',
      'host.name': 'my-gce-instance',
      'cloud.region': 'us-central1',
      'cloud.account.id': 'my-project',
    })
  })
})

describe('detectKubernetesResources', () => {
  beforeEach(async () => {
    vi.resetModules()
    await importTracing()
    delete process.env.KUBERNETES_POD_NAME
    delete process.env.KUBERNETES_NAMESPACE
    delete process.env.KUBERNETES_NODE_NAME
    delete process.env.HOSTNAME
  })

  it('returns empty when no K8s env vars are set and /proc is unreadable', async () => {
    const readFileImpl = vi.fn().mockRejectedValue(new Error('ENOENT'))
    const controller = new AbortController()
    const attrs = await tracingMod.detectKubernetesResources(controller.signal, readFileImpl)
    expect(attrs).toEqual({})
  })

  it('extracts pod name from KUBERNETES_POD_NAME', async () => {
    process.env.KUBERNETES_POD_NAME = 'my-pod-abc'
    process.env.KUBERNETES_NAMESPACE = 'default'
    const readFileImpl = vi.fn().mockRejectedValue(new Error('ENOENT'))

    const controller = new AbortController()
    const attrs = await tracingMod.detectKubernetesResources(controller.signal, readFileImpl)
    expect(attrs).toMatchObject({
      'k8s.pod.name': 'my-pod-abc',
      'k8s.namespace.name': 'default',
      'cloud.provider': 'kubernetes',
    })
  })

  it('extracts container ID from cgroup with kubepods path', async () => {
    process.env.KUBERNETES_POD_NAME = 'my-pod'
    const cgroupContent = [
      '12:memory:/kubepods/burstable/pod123abc/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '11:cpu:/kubepods/burstable/pod123abc',
    ].join('\n')
    const readFileImpl = vi.fn().mockResolvedValue(cgroupContent)

    const controller = new AbortController()
    const attrs = await tracingMod.detectKubernetesResources(controller.signal, readFileImpl)
    expect(attrs).toMatchObject({
      'k8s.pod.name': 'my-pod',
      'container.id': '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    })
  })

  it('extracts container ID from docker cgroup path', async () => {
    const containerId = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    const cgroupContent = [
      `1:name=systemd:/docker/${containerId}`,
    ].join('\n')
    const readFileImpl = vi.fn().mockResolvedValue(cgroupContent)

    const controller = new AbortController()
    const attrs = await tracingMod.detectKubernetesResources(controller.signal, readFileImpl)
    expect(attrs).toEqual({
      'container.id': containerId,
    })
  })

  it('returns empty when aborted before cgroup read', async () => {
    process.env.KUBERNETES_POD_NAME = 'my-pod'
    const readFileImpl = vi.fn()
    const controller = new AbortController()
    controller.abort()

    const attrs = await tracingMod.detectKubernetesResources(controller.signal, readFileImpl)
    expect(readFileImpl).not.toHaveBeenCalled()
    expect(attrs).toEqual({})
  })
})

describe('detectCloudResources', () => {
  let fetchImpl: ReturnType<typeof vi.fn>
  let readFileImpl: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    vi.resetModules()
    await importTracing()
    fetchImpl = vi.fn()
    readFileImpl = vi.fn()
    delete process.env.KUBERNETES_POD_NAME
    delete process.env.KUBERNETES_NAMESPACE
    delete process.env.HOSTNAME
  })

  it('returns provider "unknown" when all detectors return empty', async () => {
    fetchImpl.mockResolvedValue({ ok: false })
    readFileImpl.mockRejectedValue(new Error('ENOENT'))

    const result = await tracingMod.detectCloudResources(500, fetchImpl, readFileImpl)
    expect(result.provider).toBe('unknown')
    expect(result.attributes).toEqual({})
  })

  it('returns provider "aws" when AWS detector finds attributes', async () => {
    fetchImpl
      // AWS calls
      .mockResolvedValueOnce({ ok: true, text: async () => 'i-test' })        // instance-id
      .mockResolvedValueOnce({ ok: true, text: async () => 't3.small' })       // instance-type
      .mockResolvedValueOnce({ ok: true, text: async () => 'us-west-2' })      // region
      .mockResolvedValueOnce({ ok: true, text: async () => 'us-west-2a' })     // az
      .mockResolvedValueOnce({ ok: true, json: async () => ({ AccountId: '123' }) }) // account
      // GCP calls — all fail
      .mockRejectedValue(new Error('ECONNREFUSED'))
      .mockRejectedValue(new Error('ECONNREFUSED'))
      .mockRejectedValue(new Error('ECONNREFUSED'))
      .mockRejectedValue(new Error('ECONNREFUSED'))

    readFileImpl.mockRejectedValue(new Error('ENOENT'))

    const result = await tracingMod.detectCloudResources(500, fetchImpl, readFileImpl)
    expect(result.provider).toBe('aws')
    expect(result.attributes['host.id']).toBe('i-test')
  })

  it('returns provider "gcp" when GCP detector finds attributes', async () => {
    // Use URL-based mock to avoid race conditions with parallel detectors
    fetchImpl.mockImplementation(async (url: string, opts?: { signal?: AbortSignal }) => {
      // AWS metadata returns not-ok (these won't be reached normally but handle them)
      if (String(url).includes('169.254.169.254')) {
        return { ok: false }
      }
      // GCP metadata returns ok
      if (String(url).includes('metadata.google.internal')) {
        const path = String(url).replace('http://metadata.google.internal/computeMetadata/v1', '')
        if (path === '/instance/id') return { ok: true, text: async () => 'gcp-instance-1' }
        if (path === '/instance/name') return { ok: true, text: async () => 'my-instance' }
        if (path === '/instance/zone') return { ok: true, text: async () => 'projects/p/zones/us-east1-b' }
        if (path === '/project/project-id') return { ok: true, text: async () => 'my-proj' }
      }
      return { ok: false }
    })

    readFileImpl.mockRejectedValue(new Error('ENOENT'))

    const result = await tracingMod.detectCloudResources(500, fetchImpl, readFileImpl)
    expect(result.provider).toBe('gcp')
    expect(result.attributes['host.id']).toBe('gcp-instance-1')
  })

  it('returns provider "kubernetes" when K8s detector finds pod name', async () => {
    fetchImpl.mockRejectedValue(new Error('ECONNREFUSED'))
    process.env.KUBERNETES_POD_NAME = 'my-pod-xyz'
    readFileImpl.mockRejectedValue(new Error('ENOENT'))

    const result = await tracingMod.detectCloudResources(500, fetchImpl, readFileImpl)
    expect(result.provider).toBe('kubernetes')
    expect(result.attributes['k8s.pod.name']).toBe('my-pod-xyz')
  })

  it('returns before the timeout even when a detector hangs', async () => {
    // GCP detector hangs, but returns on abort
    fetchImpl
      .mockImplementation((_url: string, opts: { signal: AbortSignal }) => {
        return new Promise<{ ok: boolean; text: () => Promise<string> }>((_resolve, reject) => {
          opts.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        })
      })

    readFileImpl.mockRejectedValue(new Error('ENOENT'))

    const start = Date.now()
    await tracingMod.detectCloudResources(200, fetchImpl, readFileImpl)
    const elapsed = Date.now() - start
    // Should complete within roughly the timeout
    expect(elapsed).toBeLessThan(500)
  })

  it('provider precedence: aws > gcp > kubernetes', async () => {
    // All three detectors return attributes — use URL-based mock
    fetchImpl.mockImplementation(async (url: string, opts?: { signal?: AbortSignal }) => {
      if (String(url).includes('169.254.169.254')) {
        const path = String(url).replace('http://169.254.169.254/latest/meta-data', '')
        if (path === '/instance-id') return { ok: true, text: async () => 'aws-instance' }
        if (path === '/instance-type') return { ok: true, text: async () => 'm5.large' }
        if (path === '/placement/region') return { ok: true, text: async () => 'eu-west-1' }
        if (path === '/placement/availability-zone') return { ok: true, text: async () => 'eu-west-1a' }
        if (path === '/identity-credentials/ec2/info') return { ok: true, json: async () => ({ AccountId: 'aws-acct' }) }
      }
      if (String(url).includes('metadata.google.internal')) {
        const path = String(url).replace('http://metadata.google.internal/computeMetadata/v1', '')
        if (path === '/instance/id') return { ok: true, text: async () => 'gcp-instance' }
        if (path === '/instance/name') return { ok: true, text: async () => 'gcp-name' }
        if (path === '/instance/zone') return { ok: true, text: async () => 'projects/p/zones/us-east1-b' }
        if (path === '/project/project-id') return { ok: true, text: async () => 'gcp-proj' }
      }
      return { ok: false }
    })

    process.env.KUBERNETES_POD_NAME = 'k8s-pod'
    readFileImpl.mockRejectedValue(new Error('ENOENT'))

    const result = await tracingMod.detectCloudResources(500, fetchImpl, readFileImpl)
    expect(result.provider).toBe('aws')
  })
})
