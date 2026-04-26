import { describe, it, expect } from 'vitest'
import express from 'express'
import request from 'supertest'
import type { Request } from 'express'
import {
  apiVersionMiddleware,
  versionResponseMiddleware,
  parseVersionToken,
  extractVersionFromAccept,
  negotiateApiVersion,
  DEFAULT_API_VERSION,
} from '../../../src/middleware/apiVersion.js'

function partialReq(
  input: Pick<Request, 'path'> & {
    headers?: Record<string, string | string[] | undefined>
    query?: Record<string, string | string[] | undefined>
  }
): Pick<Request, 'path' | 'headers' | 'query'> {
  return {
    path: input.path,
    headers: input.headers ?? {},
    query: input.query ?? {},
  } as Pick<Request, 'path' | 'headers' | 'query'>
}

describe('parseVersionToken', () => {
  it('accepts plain major integers', () => {
    expect(parseVersionToken('1')).toBe(1)
    expect(parseVersionToken('12')).toBe(12)
  })

  it('accepts optional v prefix (case insensitive)', () => {
    expect(parseVersionToken('v1')).toBe(1)
    expect(parseVersionToken('V2')).toBe(2)
  })

  it('trims whitespace', () => {
    expect(parseVersionToken('  v3  ')).toBe(3)
  })

  it('rejects zero, negatives, fractions, and junk', () => {
    expect(parseVersionToken('0')).toBeNull()
    expect(parseVersionToken('-1')).toBeNull()
    expect(parseVersionToken('1.2')).toBeNull()
    expect(parseVersionToken('v1a')).toBeNull()
    expect(parseVersionToken('')).toBeNull()
    expect(parseVersionToken(undefined)).toBeNull()
  })

  it('rejects overlong digit strings', () => {
    expect(parseVersionToken('1234')).toBeNull()
  })

  it('rejects smuggling-sized values', () => {
    expect(parseVersionToken('a'.repeat(40))).toBeNull()
  })
})

describe('extractVersionFromAccept', () => {
  it('reads version=', () => {
    expect(extractVersionFromAccept('application/json; version=1')).toBe(1)
  })

  it('reads api-version=', () => {
    expect(extractVersionFromAccept('application/json; api-version=2')).toBe(2)
    expect(extractVersionFromAccept('application/json; api-version=v2')).toBe(2)
  })

  it('reads quoted values', () => {
    expect(extractVersionFromAccept('application/json; version="1"')).toBe(1)
  })

  it('returns null on oversize Accept (ReDoS / abuse guard)', () => {
    expect(extractVersionFromAccept('a'.repeat(2000))).toBeNull()
  })

  it('returns null when no usable parameter', () => {
    expect(extractVersionFromAccept('application/json')).toBeNull()
  })
})

describe('negotiateApiVersion', () => {
  it('uses path prefix before headers', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/v1/health',
        headers: { 'x-api-version': '2' },
      })
    )
    expect(r.version).toBe('v1')
    expect(r.fallback).toBe(false)
    expect(r.source).toBe('path')
  })

  it('falls back when path requests unsupported major', () => {
    const r = negotiateApiVersion(partialReq({ path: '/api/v99/x' }))
    expect(r.version).toBe(DEFAULT_API_VERSION)
    expect(r.fallback).toBe(true)
    expect(r.source).toBe('path')
  })

  it('uses X-API-Version when path is unversioned', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/attestations',
        headers: { 'x-api-version': '1' },
      })
    )
    expect(r.version).toBe('v1')
    expect(r.fallback).toBe(false)
    expect(r.source).toBe('x-api-version')
  })

  it('uses Accept-Version after X-API-Version is invalid', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/x',
        headers: { 'x-api-version': 'nope', 'accept-version': '1' },
      })
    )
    expect(r.version).toBe('v1')
    expect(r.source).toBe('accept-version')
  })

  it('uses query apiVersion', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/y', query: { apiVersion: '1' } })
    )
    expect(r.version).toBe('v1')
    expect(r.source).toBe('query')
  })

  it('uses first element when query param is array', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/y', query: { apiVersion: ['1', '2'] } })
    )
    expect(r.version).toBe('v1')
    expect(r.source).toBe('query')
  })

  it('uses Accept parameters last before default', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/z',
        headers: { accept: 'application/json; version=1' },
      })
    )
    expect(r.version).toBe('v1')
    expect(r.source).toBe('accept')
  })

  it('defaults when nothing matches', () => {
    const r = negotiateApiVersion(partialReq({ path: '/api/a' }))
    expect(r).toEqual({
      version: DEFAULT_API_VERSION,
      fallback: false,
      source: 'default',
    })
  })

  it('ignores path segment with too many digits (falls through to headers/default)', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/v1234/x',
        headers: { 'x-api-version': '1' },
      })
    )
    expect(r.source).toBe('x-api-version')
    expect(r.version).toBe('v1')
  })

  it('ignores CRLF-smuggled X-API-Version tokens', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/a',
        headers: { 'x-api-version': '1\r\nInjected: 1' },
      })
    )
    expect(r.source).toBe('default')
  })
})

describe('apiVersion + versionResponse middleware', () => {
  const app = express()
  app.use(apiVersionMiddleware)
  app.use(versionResponseMiddleware)
  app.get('/api/ping', (_req, res) => res.status(200).send('ok'))

  it('sets API-Version and Vary on responses', async () => {
    const res = await request(app).get('/api/ping')
    expect(res.status).toBe(200)
    expect(res.headers['api-version']).toBe('v1')
    const v = res.headers.vary ?? ''
    expect(v.toLowerCase()).toContain('accept')
    expect(v.toLowerCase()).toContain('x-api-version')
  })

  it('sets API-Version-Fallback for unsupported majors', async () => {
    const res = await request(app).get('/api/ping').set('X-API-Version', '99')
    expect(res.headers['api-version']).toBe('v1')
    expect(res.headers['api-version-fallback']).toBe('true')
  })

  it('merges Vary with any value set by earlier middleware', async () => {
    const chain = express()
    chain.use((_req, res, next) => {
      res.setHeader('Vary', 'Origin')
      next()
    })
    chain.use(apiVersionMiddleware)
    chain.use(versionResponseMiddleware)
    chain.get('/z', (_req, res) => res.status(200).send('ok'))
    const res = await request(chain).get('/z')
    const vary = res.headers.vary ?? ''
    expect(vary).toMatch(/origin/i)
    expect(vary.toLowerCase()).toContain('accept')
  })
})

// ─── Contract tests: version negotiation ─────────────────────────────────────
//
// These tests pin the stable negotiation contract described in the README and
// docs/specs/api-version-negotiation.md.  They cover every negotiation source,
// all invalid-input edge cases, and the response-header contract.

describe('parseVersionToken — contract', () => {
  it('returns null for undefined', () => {
    expect(parseVersionToken(undefined)).toBeNull()
  })

  it('returns null for empty string', () => {
    expect(parseVersionToken('')).toBeNull()
  })

  it('returns null for string longer than 32 chars', () => {
    expect(parseVersionToken('v' + '1'.repeat(32))).toBeNull()
  })

  it('returns null for v0', () => {
    expect(parseVersionToken('v0')).toBeNull()
  })

  it('returns null for float', () => {
    expect(parseVersionToken('1.0')).toBeNull()
  })

  it('returns null for alphanumeric junk', () => {
    expect(parseVersionToken('v1beta')).toBeNull()
  })

  it('accepts v1 (canonical form)', () => {
    expect(parseVersionToken('v1')).toBe(1)
  })

  it('accepts bare integer 1', () => {
    expect(parseVersionToken('1')).toBe(1)
  })

  it('accepts uppercase V prefix', () => {
    expect(parseVersionToken('V1')).toBe(1)
  })
})

describe('extractVersionFromAccept — contract', () => {
  it('reads v= parameter', () => {
    expect(extractVersionFromAccept('application/json; v=1')).toBe(1)
  })

  it('reads v= with v-prefix value', () => {
    expect(extractVersionFromAccept('application/json; v=v1')).toBe(1)
  })

  it('returns null for undefined input', () => {
    expect(extractVersionFromAccept(undefined)).toBeNull()
  })

  it('returns null for non-string input', () => {
    expect(extractVersionFromAccept(42 as any)).toBeNull()
  })

  it('ignores unknown parameter keys', () => {
    expect(extractVersionFromAccept('application/json; charset=utf-8')).toBeNull()
  })

  it('picks first matching segment in multi-type Accept', () => {
    expect(
      extractVersionFromAccept('text/html, application/json; version=1')
    ).toBe(1)
  })
})

describe('negotiateApiVersion — contract: all sources', () => {
  it('path /api/v1/... → source=path, version=v1, fallback=false', () => {
    const r = negotiateApiVersion(partialReq({ path: '/api/v1/health' }))
    expect(r).toEqual({ version: 'v1', fallback: false, source: 'path' })
  })

  it('path /api/v2/... → source=path, fallback=true (unsupported)', () => {
    const r = negotiateApiVersion(partialReq({ path: '/api/v2/health' }))
    expect(r).toEqual({ version: DEFAULT_API_VERSION, fallback: true, source: 'path' })
  })

  it('X-API-Version: 1 → source=x-api-version', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/x', headers: { 'x-api-version': '1' } })
    )
    expect(r).toEqual({ version: 'v1', fallback: false, source: 'x-api-version' })
  })

  it('X-API-Version: 99 → fallback=true, source=x-api-version', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/x', headers: { 'x-api-version': '99' } })
    )
    expect(r).toEqual({ version: DEFAULT_API_VERSION, fallback: true, source: 'x-api-version' })
  })

  it('Accept-Version: 1 → source=accept-version', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/x', headers: { 'accept-version': '1' } })
    )
    expect(r).toEqual({ version: 'v1', fallback: false, source: 'accept-version' })
  })

  it('query apiVersion=1 → source=query', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/x', query: { apiVersion: '1' } })
    )
    expect(r).toEqual({ version: 'v1', fallback: false, source: 'query' })
  })

  it('query api_version=1 → source=query', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/x', query: { api_version: '1' } })
    )
    expect(r).toEqual({ version: 'v1', fallback: false, source: 'query' })
  })

  it('Accept: application/json; version=1 → source=accept', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/x', headers: { accept: 'application/json; version=1' } })
    )
    expect(r).toEqual({ version: 'v1', fallback: false, source: 'accept' })
  })

  it('Accept: application/json; v=1 → source=accept', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/x', headers: { accept: 'application/json; v=1' } })
    )
    expect(r).toEqual({ version: 'v1', fallback: false, source: 'accept' })
  })

  it('no signals → source=default, version=v1, fallback=false', () => {
    const r = negotiateApiVersion(partialReq({ path: '/api/x' }))
    expect(r).toEqual({ version: DEFAULT_API_VERSION, fallback: false, source: 'default' })
  })

  it('path wins over X-API-Version (priority order)', () => {
    const r = negotiateApiVersion(
      partialReq({ path: '/api/v1/x', headers: { 'x-api-version': '99' } })
    )
    expect(r.source).toBe('path')
    expect(r.version).toBe('v1')
  })

  it('X-API-Version wins over Accept-Version', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/x',
        headers: { 'x-api-version': '1', 'accept-version': '99' },
      })
    )
    expect(r.source).toBe('x-api-version')
  })

  it('Accept-Version wins over query', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/x',
        headers: { 'accept-version': '1' },
        query: { apiVersion: '99' },
      })
    )
    expect(r.source).toBe('accept-version')
  })

  it('query wins over Accept header', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/x',
        query: { apiVersion: '1' },
        headers: { accept: 'application/json; version=99' },
      })
    )
    expect(r.source).toBe('query')
  })

  it('invalid X-API-Version falls through to Accept-Version', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/x',
        headers: { 'x-api-version': 'garbage', 'accept-version': '1' },
      })
    )
    expect(r.source).toBe('accept-version')
    expect(r.version).toBe('v1')
  })

  it('invalid query falls through to Accept header', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/x',
        query: { apiVersion: 'bad' },
        headers: { accept: 'application/json; version=1' },
      })
    )
    expect(r.source).toBe('accept')
  })

  it('all invalid signals → default', () => {
    const r = negotiateApiVersion(
      partialReq({
        path: '/api/x',
        headers: { 'x-api-version': '!', 'accept-version': '!', accept: 'text/html' },
        query: { apiVersion: '!' },
      })
    )
    expect(r.source).toBe('default')
    expect(r.fallback).toBe(false)
  })
})

describe('versionResponseMiddleware — contract', () => {
  it('sets API-Version header to v1 by default', async () => {
    const app = express()
    app.use(apiVersionMiddleware)
    app.use(versionResponseMiddleware)
    app.get('/t', (_req, res) => res.sendStatus(200))
    const res = await request(app).get('/t')
    expect(res.headers['api-version']).toBe('v1')
  })

  it('does not set API-Version-Fallback when version is supported', async () => {
    const app = express()
    app.use(apiVersionMiddleware)
    app.use(versionResponseMiddleware)
    app.get('/t', (_req, res) => res.sendStatus(200))
    const res = await request(app).get('/t').set('X-API-Version', '1')
    expect(res.headers['api-version-fallback']).toBeUndefined()
  })

  it('sets API-Version-Fallback: true for unsupported version', async () => {
    const app = express()
    app.use(apiVersionMiddleware)
    app.use(versionResponseMiddleware)
    app.get('/t', (_req, res) => res.sendStatus(200))
    const res = await request(app).get('/t').set('X-API-Version', '999')
    expect(res.headers['api-version']).toBe('v1')
    expect(res.headers['api-version-fallback']).toBe('true')
  })

  it('merges Vary when existing value is an array', async () => {
    // Simulates a proxy or earlier middleware that set Vary as an array
    const app = express()
    app.use((_req, res, next) => {
      // Force array-valued Vary header
      res.setHeader('Vary', ['Origin', 'Cookie'])
      next()
    })
    app.use(apiVersionMiddleware)
    app.use(versionResponseMiddleware)
    app.get('/t', (_req, res) => res.sendStatus(200))
    const res = await request(app).get('/t')
    const vary = res.headers.vary ?? ''
    expect(vary).toMatch(/origin/i)
    expect(vary).toMatch(/cookie/i)
    expect(vary.toLowerCase()).toContain('accept')
    expect(vary.toLowerCase()).toContain('x-api-version')
  })

  it('uses DEFAULT_API_VERSION when req.apiVersion is not set', async () => {
    // versionResponseMiddleware without apiVersionMiddleware — req.apiVersion is undefined
    const app = express()
    app.use(versionResponseMiddleware)
    app.get('/t', (_req, res) => res.sendStatus(200))
    const res = await request(app).get('/t')
    expect(res.headers['api-version']).toBe(DEFAULT_API_VERSION)
  })

  it('includes Accept, X-API-Version, Accept-Version in Vary', async () => {
    const app = express()
    app.use(apiVersionMiddleware)
    app.use(versionResponseMiddleware)
    app.get('/t', (_req, res) => res.sendStatus(200))
    const res = await request(app).get('/t')
    const vary = (res.headers.vary ?? '').toLowerCase()
    expect(vary).toContain('accept')
    expect(vary).toContain('x-api-version')
    expect(vary).toContain('accept-version')
  })
})
