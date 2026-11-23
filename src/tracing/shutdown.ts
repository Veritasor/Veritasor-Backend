/**
 * OpenTelemetry SDK shutdown.
 *
 * Stops certificate watchers before shutting down the SDK so a rotation event
 * cannot race with process exit. Safe to call repeatedly and when tracing was
 * never initialized.
 */

import {
  clearGrpcMtlsCredentials,
  stopGrpcMtlsFileWatchers,
} from "./mtls.js";
import { clearSdk, getSdk, isSdkStarted } from "./sdk-state.js";

/**
 * Flush and shut down the OpenTelemetry SDK, if it was started.
 *
 * The cached initialization promise is intentionally left in place to match
 * the historical lifecycle: shutdown is terminal for the current instance.
 */
export async function shutdownOpenTelemetry(): Promise<void> {
  stopGrpcMtlsFileWatchers();

  const sdk = getSdk();
  if (!isSdkStarted() || !sdk) {
    return;
  }

  await sdk.shutdown();
  clearSdk();
  clearGrpcMtlsCredentials();
}
