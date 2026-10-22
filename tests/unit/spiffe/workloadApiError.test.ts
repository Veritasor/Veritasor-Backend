import { describe, expect, it } from "vitest";
import {
  WorkloadApiError,
  createGrpcWorkloadApiClient,
} from "../../../src/spiffe/workloadApiClient.js";
import type {
  GrpcLoader,
  GrpcWorkloadApiClientOptions,
} from "../../../src/spiffe/workloadApiClient.js";
import type { WorkloadApiClient } from "../../../src/spiffe/types.js";

const SOCKET = "unix:///tmp/spire-agent/public/api.sock";

function createMockWorkloadApiClient(): WorkloadApiClient {
  return {
    fetchX509Svid: async () => ({
      svids: [],
      bundles: new Map(),
    }),
    watchX509Svid: () => () => undefined,
  };
}

describe("WorkloadApiError contract", () => {
  it("preserves the message and exposes the public error name", () => {
    const error = new WorkloadApiError("workload unavailable");

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(WorkloadApiError);
    expect(error.name).toBe("WorkloadApiError");
    expect(error.message).toBe("workload unavailable");
    expect(error.cause).toBeUndefined();
  });

  it("preserves the optional underlying cause", () => {
    const cause = new Error("socket unavailable");
    const error = new WorkloadApiError("FetchX509SVID failed", cause);

    expect(error.name).toBe("WorkloadApiError");
    expect(error.message).toBe("FetchX509SVID failed");
    expect(error.cause).toBe(cause);
  });

  it("uses WorkloadApiError for invalid socket boundaries", () => {
    expect(() =>
      createGrpcWorkloadApiClient({
        socketAddress: "tcp://127.0.0.1:8080",
      }),
    ).toThrow(WorkloadApiError);
  });
});

describe("gRPC client public contracts", () => {
  it("accepts a required socket address with an optional loader", () => {
    const loader: GrpcLoader = {
      loadClient: async () => createMockWorkloadApiClient(),
    };

    const options: GrpcWorkloadApiClientOptions = {
      socketAddress: SOCKET,
      grpcLoader: loader,
    };

    expect(options.socketAddress).toBe(SOCKET);
    expect(options.grpcLoader).toBe(loader);
  });

  it("preserves the default-loader boundary when no custom loader is supplied", () => {
    const client = createGrpcWorkloadApiClient({
      socketAddress: SOCKET,
    });

    expect(client).toBeDefined();
  });

  it("rejects representative invalid option and loader shapes at compile time", () => {
    const invalidOptions: GrpcWorkloadApiClientOptions = {
      /* @ts-expect-error socketAddress must be a string */
      socketAddress: 123,
    };

    const invalidLoader: GrpcLoader = {
      /* @ts-expect-error loadClient must return Promise<WorkloadApiClient> */
      loadClient: () => "not-a-client",
    };

    expect(invalidOptions).toBeDefined();
    expect(invalidLoader).toBeDefined();
  });
});
