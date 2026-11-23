export interface X509SvidRecord {
  /** PEM-encoded certificate chain. */
  x509Svid: Buffer;
  /** PEM-encoded private key. */
  privateKey: Buffer;
  spiffeId: string;
}

export interface X509BundleRecord {
  /** PEM-encoded authority certificates for a trust domain. */
  authorities: Buffer[];
}

export interface WorkloadX509Response {
  svids: X509SvidRecord[];
  bundles: Map<string, X509BundleRecord>;
}

export interface TlsIdentityMaterial {
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
  spiffeId: string;
  expiresAt: Date;
}

export interface WorkloadApiClient {
  fetchX509Svid(): Promise<WorkloadX509Response>;
  watchX509Svid(
    onUpdate: (response: WorkloadX509Response) => void,
    onError: (error: Error) => void,
  ): () => void;
}
