import path from "node:path";
import type {
  WorkloadApiClient,
  WorkloadX509Response,
  X509BundleRecord,
  X509SvidRecord,
} from "./types.js";

export class WorkloadApiError extends Error {
  constructor(message: string, public readonly cause?: Error) {
    super(message);
    this.name = "WorkloadApiError";
  }
}

const WORKLOAD_PROTO = `
syntax = "proto3";
package spiffe.workload;

service SpiffeWorkloadAPI {
  rpc FetchX509SVID(X509SVIDRequest) returns (X509SVIDResponse);
  rpc FetchX509SVIDStream(X509SVIDRequest) returns (stream X509SVIDResponse);
}

message X509SVIDRequest {}

message X509SVIDResponse {
  repeated X509SVID svids = 1;
  map<string, X509Bundle> bundles = 2;
  map<string, X509Bundle> federated_bundles = 3;
}

message X509SVID {
  bytes x509_svid = 1;
  bytes private_key = 2;
  string spiffe_id = 3;
}

message X509Bundle {
  repeated bytes x509_authorities = 1;
}
`;

export interface GrpcWorkloadApiClientOptions {
  socketAddress: string;
  grpcLoader?: GrpcLoader;
}

export interface GrpcLoader {
  loadClient(): Promise<WorkloadApiClient>;
}

function parseSocketAddress(socketAddress: string): string {
  const trimmed = socketAddress.trim();
  if (trimmed.startsWith("unix://")) {
    return `unix:${trimmed.slice("unix://".length)}`;
  }
  if (trimmed.startsWith("unix:")) {
    return trimmed;
  }
  throw new WorkloadApiError(
    `SPIFFE_WORKLOAD_API_SOCKET must be a unix socket address (got ${socketAddress})`,
  );
}

function mapResponse(raw: Record<string, unknown>): WorkloadX509Response {
  const svidsRaw = Array.isArray(raw.svids) ? raw.svids : [];
  const svids: X509SvidRecord[] = svidsRaw.map((entry) => {
    const record = entry as Record<string, unknown>;
    return {
      x509Svid: toBuffer(record.x509_svid ?? record.x509Svid),
      privateKey: toBuffer(record.private_key ?? record.privateKey),
      spiffeId: String(record.spiffe_id ?? record.spiffeId ?? ""),
    };
  });

  const bundles = new Map<string, X509BundleRecord>();
  const bundleMaps = [
    raw.bundles as Record<string, unknown> | undefined,
    raw.federated_bundles as Record<string, unknown> | undefined,
    raw.federatedBundles as Record<string, unknown> | undefined,
  ];

  for (const bundleMap of bundleMaps) {
    if (!bundleMap || typeof bundleMap !== "object") {
      continue;
    }
    for (const [trustDomain, bundleValue] of Object.entries(bundleMap)) {
      const bundle = bundleValue as Record<string, unknown>;
      const authoritiesRaw = Array.isArray(bundle.x509_authorities)
        ? bundle.x509_authorities
        : Array.isArray(bundle.x509Authorities)
          ? bundle.x509Authorities
          : [];
      bundles.set(trustDomain, {
        authorities: authoritiesRaw.map((authority) => toBuffer(authority)),
      });
    }
  }

  return { svids, bundles };
}

function toBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  if (typeof value === "string") {
    return Buffer.from(value);
  }
  return Buffer.alloc(0);
}

class GrpcWorkloadApiClient implements WorkloadApiClient {
  private readonly address: string;
  private readonly grpcLoader: GrpcLoader;
  private clientPromise: Promise<{
    fetchX509SVID: (
      request: Record<string, never>,
      callback: (error: Error | null, response: Record<string, unknown>) => void,
    ) => void;
    fetchX509SVIDStream: (
      request: Record<string, never>,
    ) => NodeJS.EventEmitter;
  }> | undefined;

  constructor(options: GrpcWorkloadApiClientOptions) {
    this.address = parseSocketAddress(options.socketAddress);
    this.grpcLoader = options.grpcLoader ?? createDefaultGrpcLoader(this.address);
  }

  async fetchX509Svid(): Promise<WorkloadX509Response> {
    const client = await this.getClient();
    return new Promise((resolve, reject) => {
      client.fetchX509SVID({}, (error, response) => {
        if (error) {
          reject(new WorkloadApiError("FetchX509SVID failed", error));
          return;
        }
        resolve(mapResponse(response));
      });
    });
  }

  watchX509Svid(
    onUpdate: (response: WorkloadX509Response) => void,
    onError: (error: Error) => void,
  ): () => void {
    let stopped = false;
    let stream: NodeJS.EventEmitter | undefined;

    void this.getClient()
      .then((client) => {
        if (stopped) {
          return;
        }
        stream = client.fetchX509SVIDStream({});
        stream.on("data", (response: Record<string, unknown>) => {
          try {
            onUpdate(mapResponse(response));
          } catch (error) {
            onError(error instanceof Error ? error : new Error(String(error)));
          }
        });
        stream.on("error", (error: Error) => {
          onError(new WorkloadApiError("FetchX509SVIDStream failed", error));
        });
        stream.on("end", () => {
          onError(new WorkloadApiError("FetchX509SVIDStream ended unexpectedly"));
        });
      })
      .catch((error) => {
        onError(error instanceof Error ? error : new Error(String(error)));
      });

    return () => {
      stopped = true;
      stream?.removeAllListeners();
    };
  }

  private getClient(): Promise<{
    fetchX509SVID: (
      request: Record<string, never>,
      callback: (error: Error | null, response: Record<string, unknown>) => void,
    ) => void;
    fetchX509SVIDStream: (
      request: Record<string, never>,
    ) => NodeJS.EventEmitter;
  }> {
    if (!this.clientPromise) {
      this.clientPromise = this.grpcLoader.loadClient();
    }
    return this.clientPromise;
  }
}

function createDefaultGrpcLoader(address: string): GrpcLoader {
  return {
    async loadClient() {
      const grpc = await import("@grpc/grpc-js");
      const protoLoader = await import("@grpc/proto-loader");
      const packageDefinition = protoLoader.loadSync(WORKLOAD_PROTO, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
      });
      const loaded = grpc.loadPackageDefinition(packageDefinition) as {
        spiffe: {
          workload: {
            SpiffeWorkloadAPI: new (
              address: string,
              credentials: unknown,
              options?: Record<string, unknown>,
            ) => {
              fetchX509SVID: (
                request: Record<string, never>,
                callback: (
                  error: Error | null,
                  response: Record<string, unknown>,
                ) => void,
              ) => void;
              fetchX509SVIDStream: (
                request: Record<string, never>,
              ) => NodeJS.EventEmitter;
            };
          };
        };
      };

      const Client = loaded.spiffe.workload.SpiffeWorkloadAPI;
      return new Client(address, grpc.credentials.createInsecure());
    },
  };
}

export function createGrpcWorkloadApiClient(
  options: GrpcWorkloadApiClientOptions,
): WorkloadApiClient {
  return new GrpcWorkloadApiClient(options);
}

export function defaultWorkloadApiSocketPath(): string {
  return path.join("/tmp", "spire-agent", "public", "api.sock");
}
