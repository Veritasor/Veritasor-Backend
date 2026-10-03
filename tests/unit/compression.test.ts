import { describe, it, expect } from "vitest";
import express, { type Express } from "express";
import request from "supertest";
import zlib from "node:zlib";
import {
  compressionMiddleware,
  disableCompression,
  selectEncoding,
  type CompressionOptions,
} from "../../src/middleware/compression.js";

/** A body comfortably above the 1KB threshold and highly compressible. */
const BIG = "veritasor-".repeat(500); // ~5KB
const SMALL = "tiny";

function makeApp(options?: CompressionOptions, configure?: (app: Express) => void): Express {
  const app = express();
  app.use(express.json());
  app.use(compressionMiddleware(options));
  configure?.(app);

  app.get("/big", (_req, res) => {
    res.type("text/plain").send(BIG);
  });
  app.get("/big-json", (_req, res) => {
    res.json({ value: BIG });
  });
  app.get("/small", (_req, res) => {
    res.type("text/plain").send(SMALL);
  });
  return app;
}

describe("selectEncoding", () => {
  it("prefers brotli when both are offered", () => {
    expect(selectEncoding("gzip, br")).toBe("br");
    expect(selectEncoding("br, gzip")).toBe("br");
  });

  it("falls back to gzip when brotli is absent", () => {
    expect(selectEncoding("gzip, deflate")).toBe("gzip");
  });

  it("returns null when neither is supported", () => {
    expect(selectEncoding("deflate")).toBeNull();
    expect(selectEncoding(undefined)).toBeNull();
  });

  it("honours q=0 to disable an encoding", () => {
    expect(selectEncoding("br;q=0, gzip")).toBe("gzip");
    expect(selectEncoding("br;q=0, gzip;q=0")).toBeNull();
  });

  it("treats a positive wildcard as support", () => {
    expect(selectEncoding("*")).toBe("br");
  });
});

describe("compressionMiddleware", () => {
  it("brotli-compresses a large response and round-trips correctly", async () => {
    const app = makeApp();
    const res = await request(app).get("/big").set("Accept-Encoding", "br, gzip");

    expect(res.headers["content-encoding"]).toBe("br");
    expect(res.headers["vary"]).toMatch(/accept-encoding/i);
    // superagent transparently decodes the body; verify it round-trips.
    expect(res.text).toBe(BIG);
  });

  it("falls back to gzip when brotli is not accepted", async () => {
    const app = makeApp();
    const res = await request(app).get("/big").set("Accept-Encoding", "gzip");

    expect(res.headers["content-encoding"]).toBe("gzip");
    expect(res.text).toBe(BIG);
  });

  it("does not compress when the client accepts no supported encoding", async () => {
    const app = makeApp();
    const res = await request(app).get("/big").set("Accept-Encoding", "identity");

    expect(res.headers["content-encoding"]).toBeUndefined();
    expect(res.text).toBe(BIG);
  });

  it("does not compress payloads below the threshold", async () => {
    const app = makeApp();
    const res = await request(app).get("/small").set("Accept-Encoding", "br, gzip");

    expect(res.headers["content-encoding"]).toBeUndefined();
    expect(res.text).toBe(SMALL);
  });

  it("respects a custom threshold", async () => {
    const app = makeApp({ threshold: 1 });
    const res = await request(app).get("/small").set("Accept-Encoding", "br");

    expect(res.headers["content-encoding"]).toBe("br");
    expect(res.text).toBe(SMALL);
  });

  it("skips compression when Cache-Control: no-transform is set", async () => {
    const app = makeApp(undefined, (a) => {
      a.get("/no-transform", (_req, res) => {
        res.set("Cache-Control", "public, no-transform").type("text/plain").send(BIG);
      });
    });
    const res = await request(app).get("/no-transform").set("Accept-Encoding", "br, gzip");

    expect(res.headers["content-encoding"]).toBeUndefined();
    expect(res.text).toBe(BIG);
  });

  it("does not compress non-compressible content types", async () => {
    const app = makeApp(undefined, (a) => {
      a.get("/binary", (_req, res) => {
        res.type("application/octet-stream").send(Buffer.from(BIG));
      });
    });
    const res = await request(app).get("/binary").set("Accept-Encoding", "br, gzip");
    expect(res.headers["content-encoding"]).toBeUndefined();
  });

  describe("BREACH guard", () => {
    it("does not compress responses that set a session cookie", async () => {
      const app = makeApp(undefined, (a) => {
        a.get("/login", (_req, res) => {
          res.setHeader("Set-Cookie", `session=abc123; HttpOnly; Path=/`);
          res.type("text/plain").send(BIG);
        });
      });
      const res = await request(app).get("/login").set("Accept-Encoding", "br, gzip");

      expect(res.headers["content-encoding"]).toBeUndefined();
      expect(res.text).toBe(BIG);
    });

    it("does not compress responses containing a CSRF token in the body", async () => {
      const app = makeApp(undefined, (a) => {
        a.get("/form", (_req, res) => {
          res.json({ csrfToken: "secret-token-value", padding: BIG });
        });
      });
      const res = await request(app).get("/form").set("Accept-Encoding", "br, gzip");

      expect(res.headers["content-encoding"]).toBeUndefined();
      const parsed = JSON.parse(res.text);
      expect(parsed.csrfToken).toBe("secret-token-value");
    });

    it("still compresses a normal cookie that is not a session cookie", async () => {
      const app = makeApp(undefined, (a) => {
        a.get("/pref", (_req, res) => {
          res.setHeader("Set-Cookie", "theme=dark; Path=/");
          res.type("text/plain").send(BIG);
        });
      });
      const res = await request(app).get("/pref").set("Accept-Encoding", "br");

      expect(res.headers["content-encoding"]).toBe("br");
      expect(res.text).toBe(BIG);
    });
  });

  it("supports per-route opt-out via disableCompression", async () => {
    const app = makeApp(undefined, (a) => {
      a.get("/raw", (_req, res) => {
        disableCompression(res);
        res.type("text/plain").send(BIG);
      });
    });
    const res = await request(app).get("/raw").set("Accept-Encoding", "br, gzip");

    expect(res.headers["content-encoding"]).toBeUndefined();
    expect(res.text).toBe(BIG);
  });

  it("compresses chunked/streamed writes correctly", async () => {
    const app = express();
    app.use(compressionMiddleware());
    app.get("/stream", (_req, res) => {
      res.type("text/plain");
      for (let i = 0; i < 200; i++) {
        res.write(`chunk-${i}-`);
      }
      res.end("done");
    });

    const res = await request(app).get("/stream").set("Accept-Encoding", "gzip");

    expect(res.headers["content-encoding"]).toBe("gzip");
    let expected = "";
    for (let i = 0; i < 200; i++) expected += `chunk-${i}-`;
    expected += "done";
    expect(res.text).toBe(expected);
  });

  it("does not double-encode an already-encoded response", async () => {
    const app = express();
    app.use(compressionMiddleware({ threshold: 1 }));
    app.get("/pre", (_req, res) => {
      const gz = zlib.gzipSync(Buffer.from(BIG));
      res.setHeader("Content-Encoding", "gzip");
      res.type("text/plain").send(gz);
    });
    const res = await request(app).get("/pre").set("Accept-Encoding", "br, gzip");

    // Must remain single gzip (not re-compressed with brotli on top).
    expect(res.headers["content-encoding"]).toBe("gzip");
    expect(res.text).toBe(BIG);
  });
});
