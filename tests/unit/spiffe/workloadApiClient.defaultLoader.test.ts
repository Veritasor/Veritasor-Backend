import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";

vi.mock("@grpc/grpc-js", () => ({
  loadPackageDefinition: vi.fn(() => ({
    spiffe: {
      workload: {
        SpiffeWorkloadAPI: class MockSpiffeWorkloadAPI {
          fetchX509SVID(
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) {
            callback(null, {
              svids: [
                {
                  x509_svid: Buffer.from("cert"),
                  private_key: Buffer.from("key"),
                  spiffe_id: "spiffe://example.org/default-loader",
                },
              ],
              bundles: {
                "example.org": {
                  x509_authorities: [Buffer.from("ca")],
                },
              },
            });
          }

          fetchX509SVIDStream() {
            return new EventEmitter();
          }
        },
      },
    },
  })),
  credentials: {
    createInsecure: vi.fn(() => ({})),
  },
}));

vi.mock("@grpc/proto-loader", () => ({
  loadSync: vi.fn(() => ({})),
}));

describe("default gRPC Workload API loader", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("loads the SPIFFE Workload API client from grpc packages", async () => {
    const { createGrpcWorkloadApiClient } = await import(
      "../../../src/spiffe/workloadApiClient.js"
    );

    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
    });

    const response = await client.fetchX509Svid();
    expect(response.svids[0]?.spiffeId).toBe("spiffe://example.org/default-loader");
  });
});
