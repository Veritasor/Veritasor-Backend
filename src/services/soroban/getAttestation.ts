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
import { config } from "../../config";
import logger from "../../utils/logger";
import { getSorobanClient } from "./client";

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
 */
const SIMULATION_SOURCE =
	"GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Reads an attestation from the Soroban contract.
 *
 * Calls `get_attestation(business: Address, period: String)` via a
 * simulated (read-only) transaction — no signing or fee payment required.
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

	const client = getSorobanClient();
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
		version:
			native.version !== undefined ? Number(native.version) : undefined,
	};
}
