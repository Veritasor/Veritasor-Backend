/**
 * Process-wide OpenTelemetry SDK state.
 *
 * Kept in a dedicated module so initialization, certificate rotation, and
 * shutdown can share the same instance without importing each other.
 */

/** Minimal SDK surface used by the lifecycle helpers. */
export type OpenTelemetrySdk = {
  start: () => void;
  shutdown: () => Promise<void>;
};

let sdk: OpenTelemetrySdk | undefined;
let sdkStarted = false;
let sdkStartPromise: Promise<OpenTelemetrySdk | undefined> | undefined;

/** Current SDK instance, if one has been created. */
export function getSdk(): OpenTelemetrySdk | undefined {
  return sdk;
}

/** Whether `start()` has been called on the current SDK instance. */
export function isSdkStarted(): boolean {
  return sdkStarted;
}

/** In-flight (or settled) initialization promise, if initialization began. */
export function getSdkStartPromise():
  | Promise<OpenTelemetrySdk | undefined>
  | undefined {
  return sdkStartPromise;
}

/** Cache the initialization promise so concurrent callers share it. */
export function setSdkStartPromise(
  promise: Promise<OpenTelemetrySdk | undefined>,
): void {
  sdkStartPromise = promise;
}

/** Forget the initialization promise, allowing a fresh attempt. */
export function clearSdkStartPromise(): void {
  sdkStartPromise = undefined;
}

/** Record a started SDK instance. */
export function setSdk(instance: OpenTelemetrySdk): void {
  sdk = instance;
  sdkStarted = true;
}

/** Drop the current SDK instance without shutting it down. */
export function clearSdk(): void {
  sdk = undefined;
  sdkStarted = false;
}
