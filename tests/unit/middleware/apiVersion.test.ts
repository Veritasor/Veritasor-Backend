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
