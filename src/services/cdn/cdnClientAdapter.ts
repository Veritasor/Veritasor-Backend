// src/services/cdn/cdnClientAdapter.ts

/**
 * Generic CDN client interface for purging cached URLs.
 */
export interface CdnClient {
  /**
   * Purge the given list of URLs from the CDN edge cache.
   * @param urls Array of full URLs to purge.
   */
  purge(urls: string[]): Promise<void>;
}

// Import concrete implementation and expose as singleton
import { fastlyClient } from "./fastlyClient.js";
export const cdnClient: CdnClient = fastlyClient;
