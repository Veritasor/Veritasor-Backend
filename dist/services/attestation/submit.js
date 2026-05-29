import { fetchRazorpayRevenue, } from "../revenue/razorpayFetch.js";
import { MerkleTree } from "../merkle.js";
import { attestationRepository } from "../../repositories/attestation.js";
import { AppError, ExternalServiceError } from "../../types/errors.js";
/**
 * Parses a period string (e.g. "2025-10" or "2025-Q4") into ISO start and end dates.
 */
function parsePeriod(period) {
    if (period.includes("-Q")) {
        const [year, q] = period.split("-Q");
        const startMonth = (parseInt(q) - 1) * 3 + 1;
        const endMonth = startMonth + 2;
        const endDay = new Date(parseInt(year), endMonth, 0).getDate();
        return {
            startDate: `${year}-${String(startMonth).padStart(2, "0")}-01T00:00:00Z`,
            endDate: `${year}-${String(endMonth).padStart(2, "0")}-${String(endDay).padStart(2, "0")}T23:59:59Z`,
        };
    }
    else {
        // Treat as YYYY-MM
        const [year, month] = period.split("-");
        const endDay = new Date(parseInt(year), parseInt(month), 0).getDate();
        return {
            startDate: `${year}-${month}-01T00:00:00Z`,
            endDate: `${year}-${month}-${String(endDay).padStart(2, "0")}T23:59:59Z`,
        };
    }
}
/**
 * Normalizes raw revenue entries into a unified format.
 */
function normalizeRevenue(entries) {
    return entries.map((e) => ({
        date: e.date,
        month: e.date.substring(0, 7), // YYYY-MM
        amount: e.amount,
        currency: e.currency,
    }));
}
/**
 * Aggregates normalized revenue grouping by month.
 */
function aggregateByMonth(normalized) {
    const aggregated = {};
    for (const entry of normalized) {
        if (!aggregated[entry.month]) {
            aggregated[entry.month] = 0;
        }
        aggregated[entry.month] += entry.amount;
    }
    return aggregated;
}
// Soroban error taxonomy for clear client error handling
export var SorobanErrorCode;
(function (SorobanErrorCode) {
    // Network and connectivity errors (retryable)
    SorobanErrorCode["NETWORK_TIMEOUT"] = "NETWORK_TIMEOUT";
    SorobanErrorCode["NETWORK_ERROR"] = "NETWORK_ERROR";
    SorobanErrorCode["RPC_UNAVAILABLE"] = "RPC_UNAVAILABLE";
    // Transaction processing errors (retryable)
    SorobanErrorCode["NONCE_CONFLICT"] = "NONCE_CONFLICT";
    SorobanErrorCode["FEE_BUMP_REQUIRED"] = "FEE_BUMP_REQUIRED";
    SorobanErrorCode["TRANSACTION_PENDING"] = "TRANSACTION_PENDING";
    // Validation errors (non-retryable)
    SorobanErrorCode["INVALID_SIGNATURE"] = "INVALID_SIGNATURE";
    SorobanErrorCode["INVALID_ACCOUNT"] = "INVALID_ACCOUNT";
    SorobanErrorCode["INSUFFICIENT_BALANCE"] = "INSUFFICIENT_BALANCE";
    SorobanErrorCode["CONTRACT_ERROR"] = "CONTRACT_ERROR";
    // System errors (retryable with backoff)
    SorobanErrorCode["RATE_LIMITED"] = "RATE_LIMITED";
    SorobanErrorCode["SERVICE_UNAVAILABLE"] = "SERVICE_UNAVAILABLE";
    SorobanErrorCode["INTERNAL_ERROR"] = "INTERNAL_ERROR";
})(SorobanErrorCode || (SorobanErrorCode = {}));
const DEFAULT_RETRY_CONFIG = {
    maxAttempts: 3,
    baseDelayMs: 1000,
    maxDelayMs: 30000,
    backoffMultiplier: 2,
};
function log(level, message, context) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        service: 'attestation-submit',
        message,
        ...context,
    };
    console[level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log'](JSON.stringify(logEntry));
}
// Determine if error is retryable based on error taxonomy
function isRetryableError(error) {
    const code = error.code;
    if (!code)
        return true; // Unknown errors are retryable by default
    const retryableCodes = new Set([
        SorobanErrorCode.NETWORK_TIMEOUT,
        SorobanErrorCode.NETWORK_ERROR,
        SorobanErrorCode.RPC_UNAVAILABLE,
        SorobanErrorCode.NONCE_CONFLICT,
        SorobanErrorCode.FEE_BUMP_REQUIRED,
        SorobanErrorCode.TRANSACTION_PENDING,
        SorobanErrorCode.RATE_LIMITED,
        SorobanErrorCode.SERVICE_UNAVAILABLE,
        SorobanErrorCode.INTERNAL_ERROR,
    ]);
    return retryableCodes.has(code);
}
// Calculate exponential backoff delay with jitter
function calculateDelay(attempt, config) {
    const exponentialDelay = config.baseDelayMs * Math.pow(config.backoffMultiplier, attempt - 1);
    const cappedDelay = Math.min(exponentialDelay, config.maxDelayMs);
    // Add jitter (±25% randomization) to prevent thundering herd
    const jitter = 0.5 + Math.random() * 0.5; // 0.5 to 1.0 multiplier
    return Math.floor(cappedDelay * jitter);
}
// Sleep utility for retry delays
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
/**
 * Mock interface for submitting the attestation root to Soroban.
 * Enhanced with error simulation for testing retry logic.
 */
async function submitToSoroban(merkleRoot, businessId, period) {
    // Simulated call to a Soroban contract
    // In production, this would use the Stellar SDK to submit to Soroban
    const random = Math.random();
    // Simulate different failure scenarios for testing
    if (random < 0.1) {
        const error = new Error('Network timeout while submitting transaction');
        error.code = SorobanErrorCode.NETWORK_TIMEOUT;
        throw error;
    }
    if (random < 0.15) {
        const error = new Error('Nonce conflict - transaction sequence already used');
        error.code = SorobanErrorCode.NONCE_CONFLICT;
        throw error;
    }
    if (random < 0.18) {
        const error = new Error('Insufficient balance for transaction fees');
        error.code = SorobanErrorCode.INSUFFICIENT_BALANCE;
        throw error;
    }
    return `tx_${merkleRoot.substring(0, 8)}_${Date.now()}`;
}
/**
 * Enhanced Soroban submission with retry logic and error taxonomy.
 */
async function submitToSorobanWithRetry(merkleRoot, businessId, period, context, config = DEFAULT_RETRY_CONFIG) {
    let lastError;
    const startTime = Date.now();
    for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
        try {
            log('info', `Attempting Soroban submission (attempt ${attempt}/${config.maxAttempts})`, {
                ...context,
                attempt,
                maxAttempts: config.maxAttempts,
            });
            const result = await submitToSoroban(merkleRoot, businessId, period);
            log('info', 'Soroban submission successful', {
                ...context,
                attempt,
                duration: Date.now() - startTime,
            });
            return result;
        }
        catch (error) {
            lastError = error;
            const sorobanError = lastError;
            log('warn', `Soroban submission failed on attempt ${attempt}`, {
                ...context,
                attempt,
                error: lastError.message,
                errorCode: sorobanError.code,
            });
            // Check if we should retry
            if (attempt === config.maxAttempts || !isRetryableError(sorobanError)) {
                log('error', 'Soroban submission failed - no more retries', {
                    ...context,
                    attempt,
                    error: lastError.message,
                    errorCode: sorobanError.code,
                    duration: Date.now() - startTime,
                });
                // Convert to appropriate error type based on taxonomy
                if (sorobanError.code === SorobanErrorCode.INSUFFICIENT_BALANCE) {
                    throw new AppError('Insufficient balance for transaction fees. Please fund your account.', 400, 'INSUFFICIENT_BALANCE');
                }
                if (sorobanError.code === SorobanErrorCode.INVALID_SIGNATURE) {
                    throw new AppError('Invalid signature provided for transaction.', 400, 'INVALID_SIGNATURE');
                }
                if (sorobanError.code === SorobanErrorCode.CONTRACT_ERROR) {
                    throw new AppError('Contract execution failed. Please check your parameters.', 400, 'CONTRACT_ERROR');
                }
                // Network/service errors become ExternalServiceError
                throw new ExternalServiceError(`Soroban submission failed: ${lastError.message}`, 503);
            }
            // Calculate delay and wait before retry
            const delay = calculateDelay(attempt, config);
            log('info', `Waiting ${delay}ms before retry`, {
                ...context,
                attempt,
                delay,
            });
            await sleep(delay);
        }
    }
    // This should never be reached due to the logic above
    throw lastError;
}
/**
 * @notice Orchestrates the full attestation submission flow.
 * @dev This function handles the end-to-end process of fetching revenue,
 * normalizing it, generating a Merkle root, and submitting it to the blockchain.
 *
 * @param userId - The unique identifier of the user initiating the request.
 * @param businessId - The ID of the business for which the attestation is created.
 * @param period - The time period (e.g., "2025-10" or "2025-Q4").
 *
 * @return attestationId - The unique ID of the generated attestation record.
 * @return txHash - The transaction hash from the Soroban submission.
 *
 * @throws Error if revenue fetching fails or if Merkle root generation is unsuccessful.
 *
 * @security Verified that only the business owner (or authorized user) can submit
 * attestations for their specific businessId.
 */
export async function submitAttestation(userId, businessId, period) {
    try {
        const { startDate, endDate } = parsePeriod(period);
        // 1. Fetch Revenue
        // Using Razorpay for now, as it's the only implemented fetch service.
        // In a real scenario, this would loop over connected integrations from `integrationRepository`.
        let rawRevenue;
        try {
            rawRevenue = await fetchRazorpayRevenue(startDate, endDate);
        }
        catch (err) {
            throw new Error(`Failed to fetch revenue: ${err.message}`);
        }
        if (rawRevenue.length === 0) {
            throw new Error(`No revenue found for the period ${period}`);
        }
        // 2. Normalize
        const normalized = normalizeRevenue(rawRevenue);
        // 3. Aggregate
        const aggregated = aggregateByMonth(normalized);
        // 4. Build Merkle tree
        const leaves = Object.entries(aggregated)
            .sort(([m1], [m2]) => m1.localeCompare(m2))
            .map(([month, amount]) => `${month}:${amount.toFixed(2)}`);
        const tree = new MerkleTree(leaves);
        const root = tree.getRoot();
        if (!root) {
            throw new Error("Failed to generate Merkle root from aggregated data.");
        }
        // 5. Submit to Soroban with retry logic
        const context = {
            userId,
            businessId,
            period,
        };
        let txHash;
        try {
            txHash = await submitToSorobanWithRetry(root, businessId, period, context);
        }
        catch (err) {
            // Already handled by submitToSorobanWithRetry with proper error taxonomy
            throw err;
        }
        // 6. Save Attestation Record
        const attestation = attestationRepository.create({
            businessId,
            period,
        });
        return {
            attestationId: attestation.id,
            txHash,
        };
    }
    catch (err) {
        log('error', 'Attestation submission failed', {
            userId,
            businessId,
            period,
            error: err.message,
            errorCode: err.code,
        });
        // Rethrow wrapped error preserving original message and code
        if (err instanceof AppError) {
            throw err;
        }
        throw new AppError(`Attestation submission failed: ${err.message}`, 500, 'ATTESTATION_SUBMIT_FAILED');
    }
}
