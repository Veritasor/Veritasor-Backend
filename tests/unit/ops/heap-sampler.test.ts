/**
 * tests/unit/ops/heap-sampler.test.ts
 *
 * Unit tests for the heap-sampler's exported pure functions:
 *   - sumRetainedSize()
 *   - analyseGrowth()
 *   - takeSnapshot() (mocked v8 / fs)
 *
 * We do NOT import the file-level `start()` call; instead we import the
 * exported functions directly after stubbing their deps with vi.mock.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import path from 'node:path'
import os from 'node:os'
import fs from 'node:fs'

// ---------------------------------------------------------------------------
// We must stub process.argv before the module is loaded so the parseArgs
// call inside the module uses controlled values.
// ---------------------------------------------------------------------------
const originalArgv = process.argv
beforeEach(() => {
  process.argv = [
    'node',
    'ops/soak/heap-sampler.ts',
    '--interval', '60',
    '--output', os.tmpdir(),
    '--threshold', '50',
    '--maxSnapshots', '3',
  ]
})
afterEach(() => {
  process.argv = originalArgv
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Helpers to create minimal valid .heapsnapshot JSON fixtures
// ---------------------------------------------------------------------------

/** Build a minimal heapsnapshot JSON string with a given total self_size. */
function buildHeapSnapshotJson(totalSelfSize: number, nodesCount = 4): string {
  const fields = ['type', 'name', 'id', 'self_size', 'edge_count', 'trace_node_id']
  const stride = fields.length
  const nodes: number[] = []
  const perNode = Math.floor(totalSelfSize / nodesCount)
  const remainder = totalSelfSize - perNode * (nodesCount - 1)

  for (let i = 0; i < nodesCount; i++) {
    for (let f = 0; f < stride; f++) {
      if (f === fields.indexOf('self_size')) {
        nodes.push(i === nodesCount - 1 ? remainder : perNode)
      } else {
        nodes.push(0)
      }
    }
  }
  return JSON.stringify({
    snapshot: { meta: { node_fields: fields } },
    nodes,
    edges: [],
    strings: [],
  })
}

/** Build a snapshot that contains a `retained_size` field. */
function buildHeapSnapshotWithRetained(totalRetained: number): string {
  const fields = ['type', 'name', 'id', 'self_size', 'retained_size', 'edge_count']
  const stride = fields.length
  const nodeCount = 2
  const nodes: number[] = []
  const half = Math.floor(totalRetained / nodeCount)
  for (let i = 0; i < nodeCount; i++) {
    for (let f = 0; f < stride; f++) {
      if (f === fields.indexOf('retained_size')) {
        nodes.push(i === nodeCount - 1 ? totalRetained - half : half)
      } else {
        nodes.push(0)
      }
    }
  }
  return JSON.stringify({
    snapshot: { meta: { node_fields: fields } },
    nodes,
    edges: [],
    strings: [],
  })
}

// ---------------------------------------------------------------------------
// Tests: sumRetainedSize
// ---------------------------------------------------------------------------

describe('sumRetainedSize', () => {
  it('sums self_size when retained_size is absent', async () => {
    const { sumRetainedSize } = await import('../../../ops/soak/heap-sampler.js')

    const tmpFile = path.join(os.tmpdir(), `test-snap-${Date.now()}.heapsnapshot`)
    fs.writeFileSync(tmpFile, buildHeapSnapshotJson(1024 * 1024))

    try {
      const result = sumRetainedSize(tmpFile)
      expect(result).toBe(1024 * 1024)
    } finally {
      fs.unlinkSync(tmpFile)
    }
  })

  it('prefers retained_size when present', async () => {
    const { sumRetainedSize } = await import('../../../ops/soak/heap-sampler.js')

    const tmpFile = path.join(os.tmpdir(), `test-snap-retained-${Date.now()}.heapsnapshot`)
    fs.writeFileSync(tmpFile, buildHeapSnapshotWithRetained(2 * 1024 * 1024))

    try {
      const result = sumRetainedSize(tmpFile)
      expect(result).toBe(2 * 1024 * 1024)
    } finally {
      fs.unlinkSync(tmpFile)
    }
  })

  it('throws if neither self_size nor retained_size field exists', async () => {
    const { sumRetainedSize } = await import('../../../ops/soak/heap-sampler.js')

    const bad = JSON.stringify({
      snapshot: { meta: { node_fields: ['type', 'name', 'id'] } },
      nodes: [0, 0, 0],
    })
    const tmpFile = path.join(os.tmpdir(), `test-snap-bad-${Date.now()}.heapsnapshot`)
    fs.writeFileSync(tmpFile, bad)

    try {
      expect(() => sumRetainedSize(tmpFile)).toThrow('Neither retained_size nor self_size found')
    } finally {
      fs.unlinkSync(tmpFile)
    }
  })

  it('returns 0 for an empty nodes array', async () => {
    const { sumRetainedSize } = await import('../../../ops/soak/heap-sampler.js')

    const empty = JSON.stringify({
      snapshot: { meta: { node_fields: ['type', 'self_size'] } },
      nodes: [],
    })
    const tmpFile = path.join(os.tmpdir(), `test-snap-empty-${Date.now()}.heapsnapshot`)
    fs.writeFileSync(tmpFile, empty)

    try {
      expect(sumRetainedSize(tmpFile)).toBe(0)
    } finally {
      fs.unlinkSync(tmpFile)
    }
  })
})

// ---------------------------------------------------------------------------
// Tests: analyseGrowth
// ---------------------------------------------------------------------------

describe('analyseGrowth', () => {
  /** Build a synthetic SnapshotRecord list with given retained bytes. */
  function makeRecords(bytes: number[]): any[] {
    return bytes.map((b, i) => ({
      file: `/fake/heap-${i}.heapsnapshot`,
      seq: i,
      takenAt: new Date(Date.now() + i * 60_000),
      retainedBytes: b,
    }))
  }

  it('returns leakDetected=false when growth is below threshold', async () => {
    const { analyseGrowth } = await import('../../../ops/soak/heap-sampler.js')

    // 3 snapshots: warm-up (ignored), then 100 MB → 110 MB (10 MB growth)
    const records = makeRecords([
      50 * 1024 * 1024,   // warm-up 1
      55 * 1024 * 1024,   // warm-up 2
      100 * 1024 * 1024,  // post-warm-up baseline
      110 * 1024 * 1024,  // final  (10 MB growth → below 50 MB threshold)
    ])

    const result = analyseGrowth(records)
    expect(result.leakDetected).toBe(false)
    expect(result.deltaMB).toBeCloseTo(10, 0)
    expect(result.snapCount).toBe(4)
  })

  it('returns leakDetected=true when growth exceeds threshold', async () => {
    const { analyseGrowth } = await import('../../../ops/soak/heap-sampler.js')

    // 3 snapshots: warm-up, then 100 MB → 200 MB (100 MB growth > 50 MB)
    const records = makeRecords([
      50 * 1024 * 1024,
      55 * 1024 * 1024,
      100 * 1024 * 1024,
      200 * 1024 * 1024,
    ])

    const result = analyseGrowth(records)
    expect(result.leakDetected).toBe(true)
    expect(result.deltaMB).toBeCloseTo(100, 0)
    expect(result.message).toMatch(/LEAK DETECTED/)
  })

  it('returns not-enough-data message with fewer than 3 snapshots', async () => {
    const { analyseGrowth } = await import('../../../ops/soak/heap-sampler.js')

    const result = analyseGrowth(makeRecords([100 * 1024 * 1024, 110 * 1024 * 1024]))
    expect(result.leakDetected).toBe(false)
    expect(result.message).toMatch(/Not enough post-warm-up snapshots/)
  })

  it('does not flag shrinking heap as a leak', async () => {
    const { analyseGrowth } = await import('../../../ops/soak/heap-sampler.js')

    const records = makeRecords([
      80 * 1024 * 1024,
      85 * 1024 * 1024,
      200 * 1024 * 1024,  // post-warm-up (may be high from lazy init)
      150 * 1024 * 1024,  // final – GC reclaimed memory
    ])

    const result = analyseGrowth(records)
    expect(result.leakDetected).toBe(false)
    expect(result.deltaBytes).toBeLessThan(0)
  })

  it('handles exactly 3 snapshots (minimum valid case)', async () => {
    const { analyseGrowth } = await import('../../../ops/soak/heap-sampler.js')

    const records = makeRecords([
      50 * 1024 * 1024,
      55 * 1024 * 1024,
      56 * 1024 * 1024,  // post-warm-up; last is same as first (only 1 post-warm-up)
    ])
    // Only 1 post-warm-up snapshot → need at least 2; returns not-enough-data
    const result = analyseGrowth(records)
    expect(result.message).toMatch(/Not enough post-warm-up snapshots/)
  })

  it('includes snapCount in the result', async () => {
    const { analyseGrowth } = await import('../../../ops/soak/heap-sampler.js')

    const records = makeRecords([
      50 * 1024 * 1024,
      55 * 1024 * 1024,
      100 * 1024 * 1024,
      105 * 1024 * 1024,
      110 * 1024 * 1024,
    ])
    const result = analyseGrowth(records)
    expect(result.snapCount).toBe(5)
  })

  it('message contains threshold value', async () => {
    const { analyseGrowth } = await import('../../../ops/soak/heap-sampler.js')

    const records = makeRecords([
      50 * 1024 * 1024,
      55 * 1024 * 1024,
      100 * 1024 * 1024,
      102 * 1024 * 1024,
    ])
    const result = analyseGrowth(records)
    // Threshold comes from CLI arg (50 MB in the beforeEach setup).
    expect(result.message).toMatch(/50/)
  })
})

// ---------------------------------------------------------------------------
// Tests: takeSnapshot (integration-lite with real tmp dir)
// ---------------------------------------------------------------------------

describe('takeSnapshot', () => {
  it('writes a .heapsnapshot file to the output directory', async () => {
    const { takeSnapshot } = await import('../../../ops/soak/heap-sampler.js')

    // Override OUTPUT_DIR via argv (already set in beforeEach)
    const snap = takeSnapshot()

    expect(fs.existsSync(snap.file)).toBe(true)
    expect(snap.retainedBytes).toBeGreaterThan(0)
    expect(snap.seq).toBeGreaterThanOrEqual(0)

    // Cleanup
    fs.unlinkSync(snap.file)
  })

  it('increments seq on successive calls', async () => {
    const { takeSnapshot } = await import('../../../ops/soak/heap-sampler.js')

    const s1 = takeSnapshot()
    const s2 = takeSnapshot()
    expect(s2.seq).toBeGreaterThan(s1.seq)

    fs.unlinkSync(s1.file)
    fs.unlinkSync(s2.file)
  })

  it('recorded retainedBytes matches sumRetainedSize on the written file', async () => {
    const { takeSnapshot, sumRetainedSize } = await import('../../../ops/soak/heap-sampler.js')

    const snap = takeSnapshot()
    const fromFile = sumRetainedSize(snap.file)
    expect(snap.retainedBytes).toBe(fromFile)

    fs.unlinkSync(snap.file)
  })
})
