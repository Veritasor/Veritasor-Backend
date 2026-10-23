import https from "node:https";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Server as HttpsServer } from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { applyRotatedTlsMaterial } from "../../../src/middleware/mtls.js";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "../../fixtures/spiffe");
const initialCert = readFileSync(join(fixtureDir, "spiffe-test-cert.pem"));
const initialKey = readFileSync(join(fixtureDir, "spiffe-test-key.pem"));
const rotatedCert = readFileSync(join(fixtureDir, "mtls-rotation-cert.pem"));
const rotatedKey = readFileSync(join(fixtureDir, "mtls-rotation-key.pem"));

describe("mTLS TLS context rotation", () => {
  let server: HttpsServer | undefined;

  afterEach(async () => {
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => {
        server?.close((error) => (error ? reject(error) : resolve()));
      });
    }
    server = undefined;
  });

  it("uses the rotated server certificate and continues requesting client certificates", async () => {
    const serverClientFingerprints: Array<string | null> = [];
    server = https.createServer(
      {
        ca: initialCert,
        cert: initialCert,
        key: initialKey,
        requestCert: true,
        rejectUnauthorized: false,
      },
      (request, response) => {
        const peerCertificate = request.socket.getPeerCertificate();
        serverClientFingerprints.push(peerCertificate.fingerprint256 ?? null);
        response.end("ok");
      },
    );

    await new Promise<void>((resolve, reject) => {
      server?.once("error", reject);
      server?.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected HTTPS server to listen on a TCP address");
    }

    const initialFingerprint = await makeRequest(address.port);
    applyRotatedTlsMaterial(server, {
      ca: rotatedCert,
      cert: rotatedCert,
      key: rotatedKey,
    });
    const rotatedFingerprint = await makeRequest(address.port);

    expect(initialFingerprint).toBe(new X509Certificate(initialCert).fingerprint256);
    expect(rotatedFingerprint).toBe(new X509Certificate(rotatedCert).fingerprint256);
    expect(rotatedFingerprint).not.toBe(initialFingerprint);
    expect(serverClientFingerprints).toEqual([
      new X509Certificate(initialCert).fingerprint256,
      new X509Certificate(initialCert).fingerprint256,
    ]);
  });
});

function makeRequest(port: number): Promise<string | undefined> {
  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        host: "127.0.0.1",
        port,
        method: "GET",
        path: "/",
        cert: initialCert,
        key: initialKey,
        rejectUnauthorized: false,
        agent: false,
      },
      (response) => {
        response.resume();
        response.once("end", () => {
          resolve(response.socket.getPeerCertificate().fingerprint256);
        });
      },
    );
    request.once("error", reject);
    request.end();
  });
}
