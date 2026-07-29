import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import {
  createGrpcWorkloadApiClient,
  WorkloadApiError,
} from "../../../src/spiffe/workloadApiClient.js";
import type { WorkloadApiClient } from "../../../src/spiffe/types.js";

describe("createGrpcWorkloadApiClient", () => {
  it("rejects non-unix socket addresses", () => {
    expect(() =>
      createGrpcWorkloadApiClient({ socketAddress: "tcp://127.0.0.1:8080" }),
    ).toThrow(WorkloadApiError);
  });

  it("fetches X509-SVID material through the injected gRPC loader", async () => {
    const cert = Buffer.from("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----");
    const key = Buffer.from("-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----");
    const ca = Buffer.from("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----");

    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => {
            callback(null, {
              svids: [
                {
                  x509_svid: cert,
                  private_key: key,
                  spiffe_id: "spiffe://example.org/backend",
                },
              ],
              bundles: {
                "example.org": {
                  x509_authorities: [ca],
                },
              },
            });
          },
          fetchX509SVIDStream: () => new EventEmitter(),
        }),
      },
    });

    const response = await client.fetchX509Svid();
    expect(response.svids[0]?.spiffeId).toBe("spiffe://example.org/backend");
    expect(response.bundles.get("example.org")?.authorities[0]?.toString()).toContain("CA");
  });

  it("maps stream updates and surfaces stream termination as an error", async () => {
    const stream = new EventEmitter();
    const onError = vi.fn();
    const onUpdate = vi.fn();

    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => callback(new Error("unavailable"), {}),
          fetchX509SVIDStream: () => stream,
        }),
      },
    });

    client.watchX509Svid(onUpdate, onError);
    await Promise.resolve();

    stream.emit("data", {
      svids: [
        {
          x509_svid: Buffer.from("cert"),
          private_key: Buffer.from("key"),
          spiffe_id: "spiffe://example.org/worker",
        },
      ],
      bundles: {
        "example.org": { x509_authorities: [Buffer.from("ca")] },
      },
    });
    stream.emit("end");

    expect(onUpdate).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalled();
  });

  it("surfaces stream errors from the Workload API watch", async () => {
    const stream = new EventEmitter();
    const onError = vi.fn();

    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => callback(null, { svids: [], bundles: {} }),
          fetchX509SVIDStream: () => stream,
        }),
      },
    });

    client.watchX509Svid(vi.fn(), onError);
    await Promise.resolve();

    stream.emit("error", new Error("stream failed"));
    expect(onError).toHaveBeenCalledWith(expect.any(WorkloadApiError));
  });

  it("stops establishing a watch when cancelled before the client loads", async () => {
    const onError = vi.fn();
    let resolveLoad: ((value: unknown) => void) | undefined;

    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: () =>
          new Promise((resolve) => {
            resolveLoad = resolve;
          }),
      },
    });

    const stop = client.watchX509Svid(vi.fn(), onError);
    stop();

    resolveLoad?.({
      fetchX509SVID: vi.fn(),
      fetchX509SVIDStream: () => new EventEmitter(),
    });
    await Promise.resolve();

    expect(onError).not.toHaveBeenCalled();
  });

  it("maps camelCase Workload API fields", async () => {
    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => {
            callback(null, {
              svids: [
                {
                  x509Svid: Buffer.from("cert"),
                  privateKey: Buffer.from("key"),
                  spiffeId: "spiffe://example.org/worker",
                },
              ],
              bundles: {
                "example.org": {
                  x509Authorities: [Buffer.from("ca")],
                },
              },
            });
          },
          fetchX509SVIDStream: () => new EventEmitter(),
        }),
      },
    });

    const response = await client.fetchX509Svid();
    expect(response.svids[0]?.spiffeId).toBe("spiffe://example.org/worker");
  });

  it("normalizes string and Uint8Array Workload API byte fields", async () => {
    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => {
            callback(null, {
              svids: [
                {
                  x509_svid: "pem-cert",
                  private_key: new Uint8Array([1, 2, 3]),
                  spiffe_id: "spiffe://example.org/typed",
                },
              ],
              bundles: {
                "example.org": {
                  x509_authorities: [null],
                },
              },
            });
          },
          fetchX509SVIDStream: () => new EventEmitter(),
        }),
      },
    });

    const response = await client.fetchX509Svid();
    expect(response.svids[0]?.x509Svid.toString()).toBe("pem-cert");
    expect(response.svids[0]?.privateKey).toEqual(Buffer.from([1, 2, 3]));
    expect(response.bundles.get("example.org")?.authorities[0]?.length).toBe(0);
  });

  it("accepts unix: socket paths without the triple slash prefix", async () => {
    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:/tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => callback(null, { svids: [], bundles: {} }),
          fetchX509SVIDStream: () => new EventEmitter(),
        }),
      },
    });

    await expect(client.fetchX509Svid()).resolves.toEqual({
      svids: [],
      bundles: new Map(),
    });
  });

  it("rejects fetch failures from the Workload API", async () => {
    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => callback(new Error("unavailable"), {}),
          fetchX509SVIDStream: () => new EventEmitter(),
        }),
      },
    });

    await expect(client.fetchX509Svid()).rejects.toThrow(WorkloadApiError);
  });

  it("maps federated bundle entries into the bundle map", async () => {
    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => ({
          fetchX509SVID: (
            _request: Record<string, never>,
            callback: (error: Error | null, response: Record<string, unknown>) => void,
          ) => {
            callback(null, {
              svids: [],
              federated_bundles: {
                "federated.example.org": {
                  x509_authorities: [Buffer.from("federated-ca")],
                },
              },
            });
          },
          fetchX509SVIDStream: () => new EventEmitter(),
        }),
      },
    });

    const response = await client.fetchX509Svid();
    expect(response.bundles.get("federated.example.org")?.authorities[0]?.toString()).toBe(
      "federated-ca",
    );
  });

  it("surfaces loader failures when establishing the watch stream", async () => {
    const onError = vi.fn();
    const client = createGrpcWorkloadApiClient({
      socketAddress: "unix:///tmp/spire-agent/public/api.sock",
      grpcLoader: {
        loadClient: async () => {
          throw new Error("grpc unavailable");
        },
      },
    });

    client.watchX509Svid(vi.fn(), onError);
    await vi.waitFor(() => {
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: "grpc unavailable" }),
      );
    });
  });

  it("exposes the default SPIRE agent socket path helper", async () => {
    const { defaultWorkloadApiSocketPath } = await import(
      "../../../src/spiffe/workloadApiClient.js"
    );
    expect(defaultWorkloadApiSocketPath()).toContain("spire-agent");
  });
});

describe("mock WorkloadApiClient contract", () => {
  it("allows tests to inject a fully in-memory client", async () => {
    const mockClient: WorkloadApiClient = {
      fetchX509Svid: vi.fn().mockResolvedValue({ svids: [], bundles: new Map() }),
      watchX509Svid: vi.fn().mockReturnValue(() => undefined),
    };

    await mockClient.fetchX509Svid();
    expect(mockClient.fetchX509Svid).toHaveBeenCalledOnce();
  });
});
