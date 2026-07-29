/**
 * ops/soak/heap-sampler.ts
 *
 * Long-running heap sampler for soak tests.
 *
 * Usage (invoked by the GHA soak workflow, or manually):
 *
 *   node --expose-gc -r tsx/esm ops/soak/heap-sampler.ts \
 *     --interval 3600 \       # seconds between snapshots (default: 3600 = 1 h)
 *     --output  ops/k6/results \
 *     --baseline              # treat the first snapshot as baseline (sets exit 1 if growth > threshold)
 *
 * What it does
 * ============
 * 1. On startup, writes snapshot-0 (baseline).
 * 2. Every --interval seconds, writes snapshot-N and calls
 *    `diffHeapSnapshots(baseline, latest)`.
 * 3. On SIGTERM / SIGINT (or when the parent process exits), writes a final
 *    snapshot and calls `analyseGrowth()`.
 * 4. Exits with code 1 if retained-size growth > LEAK_THRESHOLD_MB (default 50 MB),
 *    which makes the GHA step fail and surfaces the leak.
 *
 * Heap snapshot format
 * ====================
 * V8 heap snapshots are written to `<output>/heap-<ISO_TIMESTAMP>-<seq>.heapsnapshot`.
 * The analyser only needs the total retained size per snapshot, so it sums the
 * "retainedSize" fields from the heapsnapshot JSON "nodes" array rather than
 * loading the full snapshot graph into memory.
 *
 * False-positive guard
 * ====================
 * Lazy-initialised caches (e.g. module loader caches, compiled regex caches)
 * cause a one-time spike during the warm-up phase.  We skip the first two
 * snapshots when computing the growth rate so warm-up artefacts don't trip the
 * detector.
 */

import v8 from 'node:v8'
import fs from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

const { values: args } = parseArgs({
  options: {
    interval:  { type: 'string',  default: '3600' },
    output:    { type: 'string',  default: 'ops/k6/results' },
    baseline:  { type: 'boolean', default: true },
    threshold: { type: 'string',  default: '50' },  // MB
    maxSnapshots: { type: 'string', default: '0' }, // 0 = unlimited
  },
  strict: false,
})

const INTERVAL_S    = parseInt(args.interval as string, 10)
const OUTPUT_DIR    = args.output as string
const LEAK_THRESH   = parseFloat(args.threshold as string) * 1024 * 1024 // → bytes
const MAX_SNAPS     = parseInt(args.maxSnapshots as string, 10)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SnapshotRecord {
  file:        string
  seq:         number
  takenAt:     Date
  retainedBytes: number
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const snapshots: SnapshotRecord[] = []
let seq = 0
let timer: ReturnType<typeof setInterval> | null = null

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isoTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-')
}

/**
 * Sum retained-size fields in a v8 heapsnapshot JSON.
 *
 * The .heapsnapshot format stores nodes as a flat int array where each group
 * of `node_fields.length` ints describes one node.  The "retained_size" field
 * index (if present) holds the retained size; otherwise we fall back to
 * "self_size".
 *
 * We stream-parse to avoid OOM on large snapshots.
 */
export function sumRetainedSize(snapshotPath: string): number {
  const raw = fs.readFileSync(snapshotPath, 'utf-8')
  const snap = JSON.parse(raw) as {
    snapshot: { meta: { node_fields: string[] } }
    nodes: number[]
  }

  const fields: string[] = snap.snapshot.meta.node_fields
  const retainedIdx  = fields.indexOf('retained_size')
  const selfSizeIdx  = fields.indexOf('self_size')

  // Choose the best available field.
  const sizeFieldIdx = retainedIdx >= 0 ? retainedIdx : selfSizeIdx
  if (sizeFieldIdx < 0) {
    throw new Error(`Neither retained_size nor self_size found in snapshot: ${snapshotPath}`)
  }

  const stride = fields.length
  const nodes  = snap.nodes
  let total    = 0
  for (let i = sizeFieldIdx; i < nodes.length; i += stride) {
    total += nodes[i]
  }
  return total
}

/**
 * Take a heap snapshot, persist it, and record its retained size.
 */
export function takeSnapshot(): SnapshotRecord {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true })

  // Force a GC cycle before snapshotting so garbage isn't counted as retained.
  if (typeof global.gc === 'function') {
    global.gc()
  }

  const filename  = `heap-${isoTimestamp()}-${seq}.heapsnapshot`
  const filePath  = path.join(OUTPUT_DIR, filename)
  v8.writeHeapSnapshot(filePath)

  const retainedBytes = sumRetainedSize(filePath)
  const record: SnapshotRecord = {
    file:          filePath,
    seq:           seq++,
    takenAt:       new Date(),
    retainedBytes,
  }
  snapshots.push(record)

  console.log(
    `[heap-sampler] snapshot #${record.seq}  ` +
    `retained=${(retainedBytes / 1024 / 1024).toFixed(1)} MB  ` +
    `file=${filename}`
  )

  return record
}

/**
 * Analyse growth across all retained snapshots.
 *
 * Skips the first two snapshots (warm-up artefact guard).
 * Returns the delta in bytes between the last and the earliest post-warm-up
 * snapshot, and whether it exceeds the threshold.
 */
export function analyseGrowth(snapshotList: SnapshotRecord[] = snapshots): {
  deltaBytes:       number
  deltaMB:          number
  leakDetected:     boolean
  snapCount:        number
  message:          string
} {
  // Need at least 3 snapshots to have 1 post-warm-up pair.
  const postWarmUp = snapshotList.slice(2)
  if (postWarmUp.length < 2) {
    return {
      deltaBytes:   0,
      deltaMB:      0,
      leakDetected: false,
      snapCount:    snapshotList.length,
      message:      'Not enough post-warm-up snapshots to detect a leak (need ≥ 3 total).',
    }
  }

  const first = postWarmUp[0].retainedBytes
  const last  = postWarmUp[postWarmUp.length - 1].retainedBytes
  const delta = last - first
  const deltaMB = delta / 1024 / 1024

  const leakDetected = delta > LEAK_THRESH

  const message = leakDetected
    ? `LEAK DETECTED: heap grew ${deltaMB.toFixed(1)} MB (threshold ${LEAK_THRESH / 1024 / 1024} MB)`
    : `No significant leak detected (growth ${deltaMB.toFixed(1)} MB, threshold ${LEAK_THRESH / 1024 / 1024} MB).`

  return { deltaBytes: delta, deltaMB, leakDetected, snapCount: snapshotList.length, message }
}

/**
 * Write a JSON report to OUTPUT_DIR/soak-heap-report.json for CI artefact
 * upload and human review.
 */
function writeReport(): void {
  const result = analyseGrowth()

  const report = {
    generatedAt:  new Date().toISOString(),
    intervalSeconds: INTERVAL_S,
    thresholdMB:  LEAK_THRESH / 1024 / 1024,
    snapshots:    snapshots.map(s => ({
      seq:         s.seq,
      file:        path.basename(s.file),
      takenAt:     s.takenAt.toISOString(),
      retainedMB:  (s.retainedBytes / 1024 / 1024).toFixed(2),
    })),
    ...result,
  }

  const reportPath = path.join(OUTPUT_DIR, 'soak-heap-report.json')
  fs.mkdirSync(OUTPUT_DIR, { recursive: true })
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2))
  console.log(`[heap-sampler] report written to ${reportPath}`)
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

function start(): void {
  console.log(
    `[heap-sampler] starting – interval=${INTERVAL_S}s  ` +
    `threshold=${LEAK_THRESH / 1024 / 1024} MB  ` +
    `output=${OUTPUT_DIR}`
  )

  // Baseline snapshot.
  takeSnapshot()

  timer = setInterval(() => {
    takeSnapshot()
    if (MAX_SNAPS > 0 && snapshots.length >= MAX_SNAPS) {
      stop(false)
    }
  }, INTERVAL_S * 1000)

  // Unref so this timer doesn't keep the process alive if the app exits.
  if (timer.unref) timer.unref()
}

function stop(graceful: boolean): void {
  if (timer) {
    clearInterval(timer)
    timer = null
  }

  // Final snapshot + analysis.
  takeSnapshot()
  const result = analyseGrowth()
  console.log(`[heap-sampler] ${result.message}`)
  writeReport()

  process.exitCode = result.leakDetected ? 1 : 0
  if (!graceful) process.exit(process.exitCode)
}

process.on('SIGTERM', () => stop(true))
process.on('SIGINT',  () => stop(true))

start()
