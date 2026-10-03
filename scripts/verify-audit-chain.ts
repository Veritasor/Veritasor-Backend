#!/usr/bin/env node
/**
 * scripts/verify-audit-chain.ts
 *
 * CLI to verify the tamper-evident hash chain of a persisted audit-log
 * export (JSON array of AuditLog entries).
 *
 * Usage
 * -----
 *   npx tsx scripts/verify-audit-chain.ts [--file <path>] [--verbose]
 *
 * Options
 *   --file <path>   Path to a JSON file containing an array of AuditLog
 *                   entries.  Reads from stdin if omitted.
 *   --verbose       Print per-entry verification details.
 *   --help          Show this help text.
 *
 * Exit codes
 *   0  Chain is intact.
 *   1  Chain is broken or the input is malformed.
 *   2  Usage error.
 *
 * Environment
 *   AUDIT_CHAIN_SECRET   HMAC key (must match the key used when the logs
 *                        were written).  The module uses a fallback test key
 *                        when this is absent – only acceptable in development.
 *
 * Example
 * -------
 *   # Export the live log and verify it
 *   curl -s -H "Authorization: Bearer $TOKEN" \
 *        http://localhost:3000/api/v1/admin/audit-logs \
 *        | jq '.data' \
 *        | npx tsx scripts/verify-audit-chain.ts
 *
 *   # Verify a previously saved snapshot
 *   npx tsx scripts/verify-audit-chain.ts --file audit-export-2026-07-29.json
 */

import fs from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import {
  verifyChain,
  type AuditLog,
} from '../src/repositories/auditLogRepository.js'

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

const { values: args, positionals } = parseArgs({
  options: {
    file:    { type: 'string'  },
    verbose: { type: 'boolean', default: false },
    help:    { type: 'boolean', default: false },
  },
  allowPositionals: true,
  strict: false,
})

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

if (args.help) {
  console.log(`
verify-audit-chain – verify the tamper-evident hash chain of an audit log export

Usage:
  npx tsx scripts/verify-audit-chain.ts [--file <path>] [--verbose]

Options:
  --file <path>   Path to a JSON file with an array of AuditLog entries.
                  Reads from stdin when omitted.
  --verbose       Print per-entry verification details.
  --help          Show this message.

Environment:
  AUDIT_CHAIN_SECRET   HMAC key (must match the value used at write time).

Exit codes:
  0  Chain intact.
  1  Chain broken or malformed input.
  2  Usage error.
  `.trim())
  process.exit(0)
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

async function readInput(): Promise<string> {
  if (args.file) {
    const filePath = path.resolve(args.file as string)
    if (!fs.existsSync(filePath)) {
      console.error(`Error: file not found: ${filePath}`)
      process.exit(2)
    }
    return fs.readFileSync(filePath, 'utf-8')
  }

  // Read from stdin
  return new Promise((resolve, reject) => {
    let buf = ''
    process.stdin.setEncoding('utf-8')
    process.stdin.on('data', chunk => { buf += chunk })
    process.stdin.on('end', () => resolve(buf))
    process.stdin.on('error', reject)
  })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const raw = await readInput()

  let entries: AuditLog[]
  try {
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) {
      console.error('Error: input must be a JSON array of AuditLog entries.')
      process.exit(1)
    }
    // Convert ISO timestamp strings back to Date objects.
    entries = parsed.map((e: any) => ({
      ...e,
      timestamp: typeof e.timestamp === 'string' ? new Date(e.timestamp) : e.timestamp,
    }))
  } catch (err) {
    console.error(`Error: failed to parse JSON input: ${(err as Error).message}`)
    process.exit(1)
  }

  if (entries.length === 0) {
    console.log('✓ Empty log – nothing to verify.')
    process.exit(0)
  }

  // Verify
  const result = verifyChain(entries)

  if (args.verbose) {
    const ordered = [...entries].sort((a, b) => a.seq - b.seq)
    console.log('\nEntry-by-entry verification:')
    for (let i = 0; i < ordered.length; i++) {
      const e = ordered[i]
      const status = (result.brokenAtIndex === null || i < result.brokenAtIndex)
        ? '✓'
        : (i === result.brokenAtIndex ? '✗ BROKEN' : '? (skipped)')
      console.log(`  [${i}] seq=${e.seq}  id=${e.id}  ${status}`)
    }
    console.log()
  }

  if (result.valid) {
    console.log(`✓ Chain intact – ${result.checkedCount} entr${result.checkedCount === 1 ? 'y' : 'ies'} verified.`)
    console.log(`  Chain root: ${result.chainRoot}`)
    process.exit(0)
  } else {
    console.error(
      `✗ Chain BROKEN at index ${result.brokenAtIndex} ` +
      `(entry id=${result.brokenAtId}).`
    )
    console.error(`  Entries checked before break: ${result.checkedCount}`)
    console.error(`  Chain root (of unverified chain): ${result.chainRoot}`)
    process.exit(1)
  }
}

main().catch(err => {
  console.error(`Unexpected error: ${(err as Error).message}`)
  process.exit(1)
})
