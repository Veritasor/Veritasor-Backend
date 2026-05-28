import { Networks, rpc, StrKey } from "@stellar/stellar-sdk";
import { logger } from "../../utils/logger.js";

export type SorobanClientConfig = {
  rpcUrl: string;
  contractId: string;
  networkPassphrase: string;
};

/**
 * Bounded transport policy for Soroban RPC requests.
 *
 * This policy applies only to network-facing RPC methods. It deliberately uses
 * short, capped retries so malformed requests and persistent infrastructure
 * faults fail fast and remain reviewable in logs.
 */
export type SorobanRetryPolicy = {
  /** Maximum time allowed for a single RPC attempt before failing fast. */
  timeoutMs: number;
  /** Number of retry attempts after the initial call. */
  maxRetries: number;
  /** Base delay used for exponential backoff. */
  retryBaseDelayMs: number;
  /** Upper bound for retry backoff delay. */
  retryMaxDelayMs: number;
  /** Jitter ratio applied to retry delays to reduce synchronized retries. */
  retryJitterRatio: number;
  /** Circuit breaker failure threshold - number of consecutive failures before opening. */
  circuitBreakerThreshold: number;
  /** Circuit breaker reset timeout in milliseconds. */
  circuitBreakerResetMs: number;
};

type ServerMethodName =
  | "getAccount"
  | "prepareTransaction"
  | "sendTransaction"
  | "simulateTransaction";

type RetryableResultPredicate<T> = (result: T) => boolean;
type SleepFn = (delayMs: number) => Promise<void>;
type RandomFn = () => number;

/**
 * Circuit breaker states for resilience against cascading failures.
 */
export enum CircuitBreakerState {
  CLOSED = "closed",     // Normal operation
  OPEN = "open",         // Failing, rejecting requests
  HALF_OPEN = "half_open" // Testing if service recovered
}

/**
 * Observability hooks for monitoring and metrics collection.
 */
export type SorobanObservabilityHooks = {
  /** Called before each RPC attempt */
  onRequestStart?: (operationName: string, attempt: number) => void;
  /** Called after each successful RPC response */
  onRequestSuccess?: (operationName: string, attempt: number, durationMs: number) => void;
  /** Called after each failed RPC attempt */
  onRequestFailure?: (operationName: string, attempt: number, durationMs: number, error: unknown) => void;
  /** Called when circuit breaker state changes */
  onCircuitBreakerStateChange?: (oldState: CircuitBreakerState, newState: CircuitBreakerState) => void;
  /** Called when a retry occurs */
  onRetry?: (operationName: string, attempt: number, delayMs: number, error: unknown) => void;
};

export type ExecuteSorobanRequestOptions<T> = {
  operationName: string;
  execute: () => Promise<T>;
  policy?: Partial<SorobanRetryPolicy>;
  shouldRetryResult?: RetryableResultPredicate<T>;
  sleep?: SleepFn;
  random?: RandomFn;
  observabilityHooks?: SorobanObservabilityHooks;
  requestId?: string; // For request tracing
  circuitBreaker?: CircuitBreaker; // Shared circuit breaker instance
};

export class SorobanRpcTimeoutError extends Error {
  constructor(
    message: string,
    public readonly timeoutMs: number,
    public readonly operationName: string,
  ) {
    super(message);
    this.name = "SorobanRpcTimeoutError";
  }
}

export class SorobanCircuitBreakerError extends Error {
  constructor(
    message: string,
    public readonly state: CircuitBreakerState,
    public readonly operationName: string,
  ) {
    super(message);
    this.name = "SorobanCircuitBreakerError";
  }
}

const DEFAULT_RPC_URL = "https://soroban-testnet.stellar.org";
const DEFAULT_RETRY_POLICY: SorobanRetryPolicy = {
  timeoutMs: 5_000,
  maxRetries: 2,
  retryBaseDelayMs: 200,
  retryMaxDelayMs: 1_500,
  retryJitterRatio: 0.2,
  circuitBreakerThreshold: 5,
  circuitBreakerResetMs: 30_000,
};

const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 60_000;
const MAX_RETRIES = 5;
const MIN_DELAY_MS = 1;
const MAX_DELAY_MS = 30_000;
const MIN_CIRCUIT_BREAKER_THRESHOLD = 1;
const MAX_CIRCUIT_BREAKER_THRESHOLD = 20;
const MIN_CIRCUIT_BREAKER_RESET_MS = 1_000;
const MAX_CIRCUIT_BREAKER_RESET_MS = 300_000;

/**
 * Circuit breaker implementation for resilience against cascading failures.
 */
export class CircuitBreaker {
  private state: CircuitBreakerState = CircuitBreakerState.CLOSED;
  private failureCount = 0;
  private lastFailureTime = 0;
  private readonly threshold: number;
  private readonly resetTimeoutMs: number;
  private readonly onStateChange?: (oldState: CircuitBreakerState, newState: CircuitBreakerState) => void;

  constructor(
    threshold: number,
    resetTimeoutMs: number,
    onStateChange?: (oldState: CircuitBreakerState, newState: CircuitBreakerState) => void,
  ) {
    this.threshold = threshold;
    this.resetTimeoutMs = resetTimeoutMs;
    this.onStateChange = onStateChange;
  }

  /**
   * Records a successful operation, potentially closing the circuit.
   */
  recordSuccess(): void {
    if (this.state === CircuitBreakerState.HALF_OPEN) {
      this.transitionTo(CircuitBreakerState.CLOSED);
    }
    this.failureCount = 0;
  }

  /**
   * Records a failed operation, potentially opening the circuit.
   */
  recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === CircuitBreakerState.CLOSED && this.failureCount >= this.threshold) {
      this.transitionTo(CircuitBreakerState.OPEN);
    } else if (this.state === CircuitBreakerState.HALF_OPEN) {
      this.transitionTo(CircuitBreakerState.OPEN);
    }
  }

  /**
   * Checks if the circuit breaker allows the request to proceed.
   */
  canProceed(): boolean {
    switch (this.state) {
      case CircuitBreakerState.CLOSED:
        return true;
      case CircuitBreakerState.OPEN:
        if (Date.now() - this.lastFailureTime >= this.resetTimeoutMs) {
          this.transitionTo(CircuitBreakerState.HALF_OPEN);
          return true;
        }
        return false;
      case CircuitBreakerState.HALF_OPEN:
        return true;
      default:
        return false;
    }
  }

  /**
   * Gets the current circuit breaker state.
   */
  getState(): CircuitBreakerState {
    return this.state;
  }

  private transitionTo(newState: CircuitBreakerState): void {
    const oldState = this.state;
    this.state = newState;
    this.onStateChange?.(oldState, newState);
  }
}

function getRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function parseIntegerEnv(
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const rawValue = process.env[name];
  if (rawValue === undefined) {
    return fallback;
  }

  if (!/^\d+$/.test(rawValue.trim())) {
    throw new Error(
      `Invalid ${name}. Expected an integer between ${min} and ${max}.`,
    );
  }

  const value = Number.parseInt(rawValue, 10);
  if (value < min || value > max) {
    throw new Error(
      `Invalid ${name}. Expected an integer between ${min} and ${max}.`,
    );
  }

  return value;
}

function parseDecimalEnv(
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const rawValue = process.env[name];
  if (rawValue === undefined) {
    return fallback;
  }

  const value = Number(rawValue);
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new Error(
      `Invalid ${name}. Expected a number between ${min} and ${max}.`,
    );
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

/**
 * Resolves the retry and timeout policy from environment variables and
 * optional per-call overrides.
 */
export function getSorobanRetryPolicy(
  overrides: Partial<SorobanRetryPolicy> = {},
): SorobanRetryPolicy {
  const envPolicy: SorobanRetryPolicy = {
    timeoutMs: parseIntegerEnv(
      "SOROBAN_RPC_TIMEOUT_MS",
      DEFAULT_RETRY_POLICY.timeoutMs,
      MIN_TIMEOUT_MS,
      MAX_TIMEOUT_MS,
    ),
    maxRetries: parseIntegerEnv(
      "SOROBAN_RPC_MAX_RETRIES",
      DEFAULT_RETRY_POLICY.maxRetries,
      0,
      MAX_RETRIES,
    ),
    retryBaseDelayMs: parseIntegerEnv(
      "SOROBAN_RPC_RETRY_BASE_DELAY_MS",
      DEFAULT_RETRY_POLICY.retryBaseDelayMs,
      MIN_DELAY_MS,
      MAX_DELAY_MS,
    ),
    retryMaxDelayMs: parseIntegerEnv(
      "SOROBAN_RPC_RETRY_MAX_DELAY_MS",
      DEFAULT_RETRY_POLICY.retryMaxDelayMs,
      MIN_DELAY_MS,
      MAX_DELAY_MS,
    ),
    retryJitterRatio: parseDecimalEnv(
      "SOROBAN_RPC_RETRY_JITTER_RATIO",
      DEFAULT_RETRY_POLICY.retryJitterRatio,
      0,
      1,
    ),
    circuitBreakerThreshold: parseIntegerEnv(
      "SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD",
      DEFAULT_RETRY_POLICY.circuitBreakerThreshold,
      MIN_CIRCUIT_BREAKER_THRESHOLD,
      MAX_CIRCUIT_BREAKER_THRESHOLD,
    ),
    circuitBreakerResetMs: parseIntegerEnv(
      "SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS",
      DEFAULT_RETRY_POLICY.circuitBreakerResetMs,
      MIN_CIRCUIT_BREAKER_RESET_MS,
      MAX_CIRCUIT_BREAKER_RESET_MS,
    ),
  };

  const policy = {
    ...envPolicy,
    ...overrides,
  };

  if (policy.retryBaseDelayMs > policy.retryMaxDelayMs) {
    throw new Error(
      "Invalid Soroban retry policy. retryBaseDelayMs must be less than or equal to retryMaxDelayMs.",
    );
  }

  return policy;
}

function sleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

function calculateRetryDelay(
  attemptNumber: number,
  policy: SorobanRetryPolicy,
  random: RandomFn,
): number {
  const exponentialDelay = Math.min(
    policy.retryBaseDelayMs * 2 ** (attemptNumber - 1),
    policy.retryMaxDelayMs,
  );

  if (policy.retryJitterRatio === 0) {
    return exponentialDelay;
  }

  const jitterWindow = exponentialDelay * policy.retryJitterRatio;
  const jitterOffset = (random() * 2 - 1) * jitterWindow;
  const delayWithJitter = Math.round(exponentialDelay + jitterOffset);
  return Math.max(MIN_DELAY_MS, delayWithJitter);
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function hasRetryableCode(error: NodeJS.ErrnoException): boolean {
  return [
    "ECONNRESET",
    "ECONNREFUSED",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "ETIMEDOUT",
    "EAI_AGAIN",
    "ENOTFOUND",
    "UND_ERR_CONNECT_TIMEOUT",
    "UND_ERR_HEADERS_TIMEOUT",
    "UND_ERR_BODY_TIMEOUT",
    "UND_ERR_SOCKET",
    "UND_ERR_CLOSED",
    "ENETDOWN",
    "EHOSTDOWN",
    "ECONNABORTED",
  ].includes(error.code ?? "");
}

/**
 * Conservative retry classifier for RPC transport failures.
 *
 * Security note: only transient transport failures are retried. Validation
 * errors, contract errors, and other deterministic failures are surfaced
 * immediately to avoid replaying unsafe requests.
 *
 * Enhanced to handle:
 * - DNS resolution failures
 * - Stale connection errors
 * - Rate limiting (429 responses)
 * - Network connectivity issues
 */
export function isRetryableSorobanError(error: unknown): boolean {
  if (error instanceof SorobanRpcTimeoutError || isAbortError(error)) {
    return true;
  }

  if (!(error instanceof Error)) {
    return false;
  }

  const errnoError = error as NodeJS.ErrnoException;
  if (hasRetryableCode(errnoError)) {
    return true;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("temporarily unavailable") ||
    message.includes("try again later") ||
    message.includes("socket hang up") ||
    message.includes("network error") ||
    message.includes("connection reset") ||
    message.includes("connection refused") ||
    message.includes("connection timeout") ||
    message.includes("dns") ||
    message.includes("name resolution") ||
    message.includes("503") ||
    message.includes("504") ||
    message.includes("429") ||
    message.includes("rate limit") ||
    message.includes("too many requests") ||
    message.includes("fetch failed") ||
    message.includes("undici") // Undici-specific errors
  );
}

async function withSorobanTimeout<T>(
  operationName: string,
  timeoutMs: number,
  execute: () => Promise<T>,
): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new SorobanRpcTimeoutError(
          `Soroban RPC ${operationName} timed out after ${timeoutMs}ms.`,
          timeoutMs,
          operationName,
        ),
      );
    }, timeoutMs);

    void execute().then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/**
 * Executes a Soroban RPC operation with bounded timeout, retry behavior,
 * circuit breaker protection, and observability hooks.
 */
export async function executeSorobanRequest<T>(
  options: ExecuteSorobanRequestOptions<T>,
): Promise<T> {
  const policy = getSorobanRetryPolicy(options.policy);
  const sleepFn = options.sleep ?? sleep;
  const random = options.random ?? Math.random;
  const hooks = options.observabilityHooks;

  // Use provided circuit breaker or create a new one for standalone usage
  const circuitBreaker = options.circuitBreaker ?? new CircuitBreaker(
    policy.circuitBreakerThreshold,
    policy.circuitBreakerResetMs,
    (oldState, newState) => {
      hooks?.onCircuitBreakerStateChange?.(oldState, newState);
      logger.warn(
        {
          operationName: options.operationName,
          oldState,
          newState,
          requestId: options.requestId,
        },
        "soroban: circuit breaker state changed",
      );
    },
  );

  // Check circuit breaker before proceeding
  if (!circuitBreaker.canProceed()) {
    const error = new SorobanCircuitBreakerError(
      `Circuit breaker is ${circuitBreaker.getState()} for Soroban RPC ${options.operationName}`,
      circuitBreaker.getState(),
      options.operationName,
    );
    hooks?.onRequestFailure?.(options.operationName, 0, 0, error);
    throw error;
  }

  for (let attempt = 1; attempt <= policy.maxRetries + 1; attempt += 1) {
    const startTime = Date.now();
    hooks?.onRequestStart?.(options.operationName, attempt);

    try {
      const result = await withSorobanTimeout(
        options.operationName,
        policy.timeoutMs,
        options.execute,
      );

      const duration = Date.now() - startTime;
      circuitBreaker.recordSuccess();
      hooks?.onRequestSuccess?.(options.operationName, attempt, duration);

      const shouldRetry =
        options.shouldRetryResult?.(result) === true &&
        attempt <= policy.maxRetries;

      if (!shouldRetry) {
        return result;
      }

      const delayMs = calculateRetryDelay(attempt, policy, random);
      hooks?.onRetry?.(options.operationName, attempt, delayMs, null);

      logger.warn(
        {
          attempt,
          delayMs,
          operationName: options.operationName,
          requestId: options.requestId,
        },
        "soroban: retrying RPC call after retryable response",
      );
      await sleepFn(delayMs);
      continue;
    } catch (error) {
      const duration = Date.now() - startTime;
      const retryable =
        isRetryableSorobanError(error) && attempt <= policy.maxRetries;

      if (!retryable) {
        circuitBreaker.recordFailure();
        hooks?.onRequestFailure?.(options.operationName, attempt, duration, error);
        throw error;
      }

      const delayMs = calculateRetryDelay(attempt, policy, random);
      hooks?.onRetry?.(options.operationName, attempt, delayMs, error);

      logger.warn(
        {
          attempt,
          delayMs,
          operationName: options.operationName,
          requestId: options.requestId,
          errorMessage: error instanceof Error ? error.message : String(error),
          duration,
        },
        "soroban: retrying RPC call after transient transport error",
      );
      await sleepFn(delayMs);
    }
  }

  // This should never be reached due to the loop logic, but TypeScript requires it
  throw new Error("Unexpected execution path in executeSorobanRequest");
}

function wrapServerMethod<TArgs extends unknown[], TResult>(
  server: rpc.Server,
  methodName: ServerMethodName,
  method: (...args: TArgs) => Promise<TResult>,
  policy: Partial<SorobanRetryPolicy>,
  observabilityHooks?: SorobanObservabilityHooks,
  requestId?: string,
  circuitBreaker?: CircuitBreaker,
): (...args: TArgs) => Promise<TResult> {
  return async (...args: TArgs): Promise<TResult> =>
    executeSorobanRequest<TResult>({
      operationName: methodName,
      execute: () => method.apply(server, args),
      policy,
      observabilityHooks,
      requestId,
      circuitBreaker,
      shouldRetryResult:
        methodName === "sendTransaction"
          ? (result) =>
              (result as rpc.Api.SendTransactionResponse).status ===
              "TRY_AGAIN_LATER"
          : undefined,
    });
}

/**
 * Creates a Soroban RPC server with a bounded retry and timeout policy applied
 * to network-facing methods used by the backend attestation workflows.
 */
export function createSorobanRpcServer(
  rpcUrl: string,
  policyOverrides: Partial<SorobanRetryPolicy> = {},
  observabilityHooks?: SorobanObservabilityHooks,
  requestId?: string,
): rpc.Server {
  const server = new rpc.Server(rpcUrl, {
    allowHttp:
      rpcUrl.startsWith("http://localhost") ||
      rpcUrl.startsWith("http://127.0.0.1"),
  });

  // Shared circuit breaker for all operations on this server instance
  const policy = getSorobanRetryPolicy(policyOverrides);
  const circuitBreaker = new CircuitBreaker(
    policy.circuitBreakerThreshold,
    policy.circuitBreakerResetMs,
    (oldState, newState) => {
      observabilityHooks?.onCircuitBreakerStateChange?.(oldState, newState);
      logger.warn(
        {
          rpcUrl,
          oldState,
          newState,
          requestId,
        },
        "soroban: circuit breaker state changed",
      );
    },
  );

  const wrappedMethods = new Map<
    ServerMethodName,
    (...args: unknown[]) => Promise<unknown>
  >();

  return new Proxy(server, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== "function") {
        return value;
      }

      if (
        property === "getAccount" ||
        property === "prepareTransaction" ||
        property === "sendTransaction" ||
        property === "simulateTransaction"
      ) {
        const methodName = property;
        const cached = wrappedMethods.get(methodName);
        if (cached) {
          return cached;
        }

        const wrapped = wrapServerMethod(
          target,
          methodName,
          value as (...args: unknown[]) => Promise<unknown>,
          policyOverrides,
          observabilityHooks,
          requestId,
          circuitBreaker,
        );
        wrappedMethods.set(methodName, wrapped);
        return wrapped;
      }

      return value.bind(target);
    },
  }) as rpc.Server;
}
