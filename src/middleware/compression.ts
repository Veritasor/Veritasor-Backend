import type { Request, Response, NextFunction, RequestHandler } from "express";
import zlib from "node:zlib";
import { compress as zstdCompressSync } from "fzstd";

/**
 * Response compression middleware (brotli preferred, gzip fallback) with a
 * BREACH-class attack guard.
 *
 * BREACH (and CRIME) exploit the fact that an attacker who can inject content
 * into a response and observe its compressed size can recover secrets that are
 * compressed alongside their injection — most notably CSRF tokens. To stay safe
 * we refuse to compress any response that:
 *
 *   - sets a session cookie (`Set-Cookie` matching a known session cookie), or
 *   - contains a CSRF/XSRF token in its body, or
 *   - opts out explicitly via {@link disableCompression}.
 *
 * In addition we honour `Cache-Control: no-transform`, only compress when the
 * client advertises a supported encoding, and skip payloads below a size
 * threshold (small payloads gain nothing and only add CPU + the BREACH risk
 * surface).
 *
 * The middleware buffers the response body so it can both apply the guard and
 * compress the complete payload. Streamed responses (multiple `res.write`
 * calls followed by `res.end`) are reassembled and compressed correctly.
 */

export interface CompressionOptions {
  /** Minimum uncompressed size, in bytes, before compression kicks in. */
  threshold?: number;
  /**
   * Cookie names that identify a session/auth cookie. A response that sets any
   * of these will never be compressed (BREACH guard). Matched case-insensitively
   * against the cookie name in each `Set-Cookie` header.
   */
  sessionCookieNames?: string[];
  /**
   * JSON field names that indicate a CSRF/XSRF token in the body. A response
   * whose body contains any of these keys will never be compressed.
   */
  csrfFieldNames?: string[];
}

const DEFAULT_THRESHOLD = 1024; // 1KB

const DEFAULT_SESSION_COOKIE_NAMES = [
  "session",
  "sid",
  "connect.sid",
  "sessionid",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
  "auth",
  "csrf",
  "xsrf",
  "csrf_token",
  "csrf-token",
  "xsrf-token",
];

const DEFAULT_CSRF_FIELD_NAMES = [
  "csrftoken",
  "csrf_token",
  "csrf-token",
  "_csrf",
  "xsrftoken",
  "xsrf_token",
  "xsrf-token",
  "x-csrf-token",
];

/** Content types that are safe and worthwhile to compress. */
const COMPRESSIBLE_TYPE = /text|json|javascript|xml|svg|graphql|x-www-form-urlencoded/i;

const NO_COMPRESSION = Symbol("noCompression");

/**
 * Explicitly opt a single response out of compression (per-route helper).
 *
 * @example
 * router.get("/raw", (req, res) => {
 *   disableCompression(res);
 *   res.json(payload);
 * });
 */
export function disableCompression(res: Response): void {
  (res as Response & { [NO_COMPRESSION]?: boolean })[NO_COMPRESSION] = true;
}

function isCompressionDisabled(res: Response): boolean {
  return (res as Response & { [NO_COMPRESSION]?: boolean })[NO_COMPRESSION] === true;
}

/**
 * Pick the best supported encoding from the client's `Accept-Encoding` header.
 * Zstd is preferred over brotli, which is preferred over gzip when offered. Returns `null` when the
 * client supports neither (or explicitly disables one with `;q=0`).
 */
export function selectEncoding(acceptEncoding: string | undefined): "zstd" | "br" | "gzip" | null {
  if (!acceptEncoding) return null;

  const accepted = new Map<string, number>();
  for (const part of acceptEncoding.split(",")) {
    const [rawName, ...params] = part.trim().split(";");
    const name = rawName.trim().toLowerCase();
    if (!name) continue;
    let q = 1;
    for (const param of params) {
      const match = param.trim().match(/^q=(\d+(?:\.\d+)?)$/i);
      if (match) q = Number(match[1]);
    }
    accepted.set(name, q);
  }

  const wildcard = accepted.get("*");
  const supports = (name: string): boolean => {
    const q = accepted.get(name) ?? (wildcard !== undefined && wildcard > 0 ? wildcard : undefined);
    return q !== undefined && q > 0;
  };

  if (supports("zstd")) return "zstd";
  if (supports("br")) return "br";
  if (supports("gzip")) return "gzip";
  return null;
}

/** True when any `Set-Cookie` header sets a configured session cookie. */
function responseSetsSessionCookie(res: Response, sessionCookieNames: string[]): boolean {
  const raw = res.getHeader("Set-Cookie");
  if (!raw) return false;
  const cookies = Array.isArray(raw) ? raw : [String(raw)];
  const names = sessionCookieNames.map((n) => n.toLowerCase());

  return cookies.some((cookie) => {
    const cookieName = String(cookie).split("=")[0]?.trim().toLowerCase() ?? "";
    return names.includes(cookieName);
  });
}

/** True when the buffered body appears to carry a CSRF/XSRF token. */
function bodyContainsCsrfToken(body: Buffer, contentType: string, csrfFieldNames: string[]): boolean {
  if (body.length === 0) return false;
  if (!/json|text|javascript|x-www-form-urlencoded/i.test(contentType)) return false;

  const text = body.toString("utf8");
  // Match a JSON/form key (quoted or bare) that names a CSRF token field.
  return csrfFieldNames.some((field) => {
    const escaped = field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`["']?${escaped}["']?\\s*[:=]`, "i");
    return pattern.test(text);
  });
}

function compressSync(encoding: "zstd" | "br" | "gzip", data: Buffer): Buffer {
  if (encoding === "zstd") {
    return Buffer.from(zstdCompressSync(data));
  }
  if (encoding === "br") {
    return zlib.brotliCompressSync(data, {
      params: {
        [zlib.constants.BROTLI_PARAM_QUALITY]: 4,
        [zlib.constants.BROTLI_PARAM_SIZE_HINT]: data.length,
      },
    });
  }
  return zlib.gzipSync(data);
}

export function compressionMiddleware(options: CompressionOptions = {}): RequestHandler {
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const sessionCookieNames = options.sessionCookieNames ?? DEFAULT_SESSION_COOKIE_NAMES;
  const csrfFieldNames = options.csrfFieldNames ?? DEFAULT_CSRF_FIELD_NAMES;

  return function compression(req: Request, res: Response, next: NextFunction): void {
    const encoding = selectEncoding(req.headers["accept-encoding"] as string | undefined);

    const chunks: Buffer[] = [];
    let buffering = true;

    const originalWrite = res.write.bind(res) as Response["write"];
    const originalEnd = res.end.bind(res) as Response["end"];

    const toBuffer = (chunk: unknown, encodingArg?: BufferEncoding): Buffer => {
      if (Buffer.isBuffer(chunk)) return chunk;
      if (typeof chunk === "string") return Buffer.from(chunk, encodingArg ?? "utf8");
      return Buffer.from(chunk as ArrayBufferView as unknown as Uint8Array);
    };

    // Restore the originals and fall back to the un-buffered path.
    const passthrough = (): void => {
      buffering = false;
      res.write = originalWrite;
      res.end = originalEnd;
    };

    res.write = function patchedWrite(chunk: unknown, ...rest: unknown[]): boolean {
      if (!buffering || chunk == null) {
        return (originalWrite as (...args: unknown[]) => boolean)(chunk, ...rest);
      }
      const enc = typeof rest[0] === "string" ? (rest[0] as BufferEncoding) : undefined;
      chunks.push(toBuffer(chunk, enc));
      const cb = rest.find((r) => typeof r === "function") as ((error?: Error | null) => void) | undefined;
      if (cb) cb();
      return true;
    } as Response["write"];

    res.end = function patchedEnd(chunk?: unknown, ...rest: unknown[]): Response {
      if (typeof chunk === "function") {
        // signature: end(cb)
        rest.unshift(chunk);
        chunk = undefined;
      }
      if (chunk != null) {
        const enc = typeof rest[0] === "string" ? (rest[0] as BufferEncoding) : undefined;
        chunks.push(toBuffer(chunk, enc));
      }

      const body = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
      const cb = rest.find((r) => typeof r === "function") as (() => void) | undefined;

      const contentType = String(res.getHeader("Content-Type") ?? "");
      const cacheControl = String(res.getHeader("Cache-Control") ?? "");
      const alreadyEncoded = Boolean(res.getHeader("Content-Encoding"));

      const isCompressibleType = COMPRESSIBLE_TYPE.test(contentType);
      const isEligibleForCompression =
        !isCompressionDisabled(res) &&
        !alreadyEncoded &&
        res.statusCode !== 204 &&
        res.statusCode !== 304 &&
        body.length >= threshold &&
        isCompressibleType &&
        !/\bno-transform\b/i.test(cacheControl) &&
        !responseSetsSessionCookie(res, sessionCookieNames) &&
        !bodyContainsCsrfToken(body, contentType, csrfFieldNames);

      // Only advertise that the representation varies on Accept-Encoding if
      // the response is actually eligible for compression. This prevents cache
      // fragmentation for images, small files, and uncompressible payloads.
      if (isEligibleForCompression) {
        res.vary("Accept-Encoding");
      }

      passthrough();

      // If not eligible, or if the client didn't advertise a supported encoding, send uncompressed.
      if (!isEligibleForCompression || !encoding) {
        return originalEnd(body, ...(cb ? [cb] : [])) as unknown as Response;
      }

      let compressed: Buffer;
      try {
        compressed = compressSync(encoding, body);
      } catch {
        // If compression fails for any reason, send the original body.
        return originalEnd(body, ...(cb ? [cb] : [])) as unknown as Response;
      }

      res.setHeader("Content-Encoding", encoding);
      res.removeHeader("Content-Length");
      res.setHeader("Content-Length", compressed.length);

      return originalEnd(compressed, ...(cb ? [cb] : [])) as unknown as Response;
    } as Response["end"];

    next();
  };
}
