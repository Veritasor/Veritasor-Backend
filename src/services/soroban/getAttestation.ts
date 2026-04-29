import {
  Account,
  Address,
  Contract,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";
import { config } from "../../config/index.js";
import { logger } from "../../utils/logger.js";
import { createSorobanRpcServer } from "./client.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AttestationResult = {
  /** Hex-encoded Merkle root stored on-chain. */
  merkle_root: string;
  /** Unix timestamp (seconds) when the attestation was written. */
  timestamp: number;
  /** Optional schema / contract version. */
  version?: number;
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * A well-known, funded testnet account used only to build simulation
 * transactions. Read-only calls never need a real signature.
 * This is the Stellar testnet friendbot account.
 */
const SIMULATION_SOURCE =
  "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Reads an attestation from the Soroban contract.
 *
 * Calls `get_attestation(business: Address, period: String)` via a
 * simulated (read-only) transaction — no signing or fee payment required.
 *
 * ---
 * ## Caching and Staleness Contract
 *
 * **This function performs no caching.** Every call issues a fresh simulation
 * against the RPC node. Callers that need low-latency repeated reads must
 * implement their own cache layer and respect the staleness windows below.
 *
 * ### Ledger close timing
 * Stellar Testnet closes a ledger roughly every **5–6 seconds**; Mainnet
 * targets **~5 seconds**. A write committed in ledger N is visible to
 * subsequent `simulateTransaction` calls only after the RPC node has ingested
 * that ledger. In practice, allow **10–15 seconds** before treating a missing
 * result as authoritative.
 *
 * ### Read-your-writes
 * Because `simulateTransaction` reads the *latest* ledger state from the RPC
 * node, a write submitted via `submitAttestation` may not be immediately
 * visible if the RPC node is lagging. If you need read-your-writes semantics
 * (e.g. after a successful `submitAttestation`), either:
 *   - poll with a short backoff until the result appears, or
 *   - pass the `ledgerSequence` returned by `submitAttestation` and wait until
 *     the RPC node reports `latestLedger >= ledgerSequence`.
 *
 * ### Revocation lag
 * Revocations are written on-chain like any other state change and are subject
 * to the same ledger-close delay. A revoked attestation may still be returned
 * by this function for up to one ledger close (~5 s) after the revocation
 * transaction is confirmed. Consumers that enforce revocation must re-query
 * after the expected ledger close window before treating a result as valid.
 *
 * ### Cache-busting
 * There is no server-side cache to bust. If you maintain a client-side cache,
 * invalidate it:
 *   - immediately after a successful `submitAttestation` or revocation, and
 *   - after at most one ledger-close interval (≤ 10 s) for background refresh.
 *
 * ### Security note
 * Stale cached data must never be used to make authorization decisions. Always
 * re-query when the attestation is used as a gate (e.g. webhook validation,
 * on-chain proof verification). See `docs/threat-model-idempotency.md`.
 *
 * @param business  Stellar address of the business (G… or C… strkey).
 * @param period    Attestation period string, e.g. `"2026-01"`.
 * @returns         Resolved attestation data, or `null` when no record exists
 *                  for the given business / period combination.
 */
export async function getAttestation(
  business: string,
  period: string,
): Promise<AttestationResult | null> {
  const { contractId, networkPassphrase } = config.soroban;

  if (!contractId) {
    throw new Error(
      "SOROBAN_CONTRACT_ID is not configured. " +
        "Set it in your environment before calling getAttestation.",
    );
  }

  const client = createSorobanRpcServer(config.soroban.rpcUrl);
  const contract = new Contract(contractId);

  // Build a simulation-only transaction.
  // Sequence number "0" is intentional — simulated txs are never submitted.
  const sourceAccount = new Account(SIMULATION_SOURCE, "0");

  const tx = new TransactionBuilder(sourceAccount, {
    fee: "100",
    networkPassphrase,
  })
    .addOperation(
      contract.call(
        "get_attestation",
        // Soroban Address type
        new Address(business).toScVal(),
        // Soroban String type
        nativeToScVal(period, { type: "string" }),
      ),
    )
    .setTimeout(30)
    .build();

  // Simulate — this is the read path; no transaction is broadcast.
  let simResult: rpc.Api.SimulateTransactionResponse;
  try {
    simResult = await client.simulateTransaction(tx);
  } catch (err) {
    logger.error(
      { err, business, period },
      "soroban: simulateTransaction network error",
    );
    throw err;
  }

  // A simulation error usually means the contract panicked (e.g. bad input).
  if (rpc.Api.isSimulationError(simResult)) {
    logger.warn(
      { business, period, error: simResult.error },
      "soroban: get_attestation contract error",
    );
    return null;
  }

  // No result at all — contract returned nothing (shouldn't normally happen).
  if (!simResult.result) {
    logger.warn(
      { business, period },
      "soroban: get_attestation returned no result",
    );
    return null;
  }

  const retval = simResult.result.retval;

  // Soroban encodes `Option::None` as ScvVoid.
  if (retval.switch().value === xdr.ScValType.scvVoid().value) {
    return null;
  }

  // scValToNative converts the on-chain map/struct to a plain JS object.
  // The contract is expected to return a map with at least:
  //   { merkle_root: String, timestamp: u64, version?: u32 }
  const native = scValToNative(retval) as {
    merkle_root: string;
    timestamp: bigint | number;
    version?: bigint | number;
  };

  return {
    merkle_root: native.merkle_root,
    // u64 comes back as bigint from scValToNative; coerce to number safely.
    timestamp: Number(native.timestamp),
    version: native.version !== undefined ? Number(native.version) : undefined,
  };
}
