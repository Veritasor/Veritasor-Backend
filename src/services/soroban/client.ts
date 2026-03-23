import { Networks, rpc, StrKey } from "@stellar/stellar-sdk";

export type SorobanClientConfig = {
  rpcUrl: string;
  contractId: string;
  networkPassphrase: string;
};

const DEFAULT_RPC_URL = "https://soroban-testnet.stellar.org";

function getRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export function getSorobanConfig(): SorobanClientConfig {
  const rpcUrl = process.env.SOROBAN_RPC_URL ?? DEFAULT_RPC_URL;
  const contractId = getRequiredEnv("SOROBAN_CONTRACT_ID");
  const networkPassphrase =
    process.env.SOROBAN_NETWORK_PASSPHRASE ?? Networks.TESTNET;

  if (!StrKey.isValidContract(contractId)) {
    throw new Error(
      "Invalid SOROBAN_CONTRACT_ID. Expected a valid Stellar contract address (C...).",
    );
  }

  return {
    rpcUrl,
    contractId,
    networkPassphrase,
  };
}

export function createSorobanRpcServer(rpcUrl: string): rpc.Server {
  return new rpc.Server(rpcUrl, {
    allowHttp:
      rpcUrl.startsWith("http://localhost") ||
      rpcUrl.startsWith("http://127.0.0.1"),
  });
}
