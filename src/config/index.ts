/**
 * App config from environment. Extend as needed.
 */
const isProduction = process.env.NODE_ENV === "production";

/**
 * CORS allowed origins.
 * - Dev: * (allow all) unless ALLOWED_ORIGINS is set.
 * - Production: ALLOWED_ORIGINS (comma-separated), or [] if unset (strict).
 */
function getAllowedOrigins(): string | string[] {
	const raw = process.env.ALLOWED_ORIGINS;
	if (raw) {
		return raw
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
	}
	if (isProduction) {
		return [];
	}
	return "*";
}

export const config = {
  cors: {
    origin: getAllowedOrigins(),
  },
  jobs: {
    attestationReminder: {
      // Run every minute
      schedule: '*/1 * * * *',
    }
  }
} as const
	cors: {
		origin: getAllowedOrigins(),
	},
	soroban: {
		/** Soroban RPC endpoint. Defaults to the public testnet node. */
		rpcUrl:
			process.env.SOROBAN_RPC_URL ?? "https://soroban-testnet.stellar.org",
		/** Deployed attestation contract address (C…). Required in production. */
		contractId: process.env.SOROBAN_CONTRACT_ID ?? "",
		/**
		 * Stellar network passphrase.
		 * Testnet:  'Test SDF Network ; September 2015'
		 * Mainnet:  'Public Global Stellar Network ; September 2015'
		 */
		networkPassphrase:
			process.env.SOROBAN_NETWORK_PASSPHRASE ??
			"Test SDF Network ; September 2015",
	},
} as const;
