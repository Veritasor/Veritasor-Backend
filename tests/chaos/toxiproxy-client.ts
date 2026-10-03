/**
 * Minimal Toxiproxy HTTP API client using native fetch.
 *
 * Replaces the `toxiproxy-node` / `toxiproxy-node-client` packages which
 * depend on deprecated HTTP libraries.  The API surface is intentionally
 * small — it only covers what the chaos tests actually use: create/delete
 * proxies, add/remove toxics, and list proxies.
 *
 * Docs: https://github.com/Shopify/toxiproxy#http-api
 */

export interface ToxicAttributes {
  latency?: number;
  jitter?: number;
  timeout?: number;
  toxicity?: number;
  rate?: number;
  average_size?: number;
  size_variation?: number;
  delay?: number;
  bytes?: number;
  percent?: number;
}

export interface Toxic {
  name: string;
  type: ToxicType;
  stream?: "upstream" | "downstream";
  toxicity: number;
  attributes: ToxicAttributes;
}

export type ToxicType =
  | "latency"
  | "bandwidth"
  | "slow_close"
  | "timeout"
  | "reset_peer"
  | "limit_data"
  | "slicer";

export interface Proxy {
  name: string;
  listen: string;
  upstream: string;
  enabled: boolean;
  toxics: Toxic[];
  addToxic: (toxic: Omit<Toxic, "name"> & { name?: string }) => Promise<Toxic>;
  removeToxic: (name: string) => Promise<void>;
  refreshToxics: () => Promise<void>;
  remove: () => Promise<void>;
  enable: () => Promise<void>;
  disable: () => Promise<void>;
}

export class ToxiproxyClient {
  private readonly baseUrl: string;

  constructor(baseUrl: string = "http://localhost:8474") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private async request<T>(
    path: string,
    options: RequestInit = {},
  ): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    const text = await res.text();
    let body: any = text;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      // not JSON; use raw text
    }
    if (!res.ok) {
      const err = new Error(
        `Toxiproxy ${options.method ?? "GET"} ${path} → ${res.status}: ${
          typeof body === "string" ? body : JSON.stringify(body)
        }`,
      );
      (err as any).status = res.status;
      (err as any).body = body;
      throw err;
    }
    return body as T;
  }

  private wrap(raw: any): Proxy {
    const self = this;
    return {
      ...raw,
      toxics: raw.toxics ?? [],
      async addToxic(toxic): Promise<Toxic> {
        const name =
          toxic.name ?? `${toxic.type}_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
        const created = await self.request<Toxic>(`/proxies/${raw.name}/toxics`, {
          method: "POST",
          body: JSON.stringify({
            name,
            type: toxic.type,
            stream: toxic.stream ?? "downstream",
            toxicity: toxic.toxicity ?? 1.0,
            attributes: toxic.attributes ?? {},
          }),
        });
        this.toxics.push(created);
        return created;
      },
      async removeToxic(name: string): Promise<void> {
        await self.request(`/proxies/${raw.name}/toxics/${name}`, {
          method: "DELETE",
        });
        this.toxics = this.toxics.filter((t: Toxic) => t.name !== name);
      },
      async refreshToxics(): Promise<void> {
        const updated = await self.request<any>(`/proxies/${raw.name}`);
        this.toxics = updated.toxics ?? [];
      },
      async remove(): Promise<void> {
        await self.request(`/proxies/${raw.name}`, { method: "DELETE" });
      },
      async enable(): Promise<void> {
        const updated = await self.request<any>(`/proxies/${raw.name}`, {
          method: "POST",
          body: JSON.stringify({ enabled: true }),
        });
        this.enabled = updated.enabled;
      },
      async disable(): Promise<void> {
        const updated = await self.request<any>(`/proxies/${raw.name}`, {
          method: "POST",
          body: JSON.stringify({ enabled: false }),
        });
        this.enabled = updated.enabled;
      },
    };
  }

  async version(): Promise<string> {
    const res = await this.request<{ version: string }>("/version");
    return res.version;
  }

  async getAll(): Promise<Record<string, Proxy>> {
    const raw = await this.request<Record<string, any>>("/proxies");
    const result: Record<string, Proxy> = {};
    for (const [name, data] of Object.entries(raw)) {
      result[name] = this.wrap(data);
    }
    return result;
  }

  async get(name: string): Promise<Proxy | null> {
    try {
      const raw = await this.request<any>(`/proxies/${name}`);
      return this.wrap(raw);
    } catch (err: any) {
      if (err?.status === 404) return null;
      throw err;
    }
  }

  async createProxy(input: {
    name: string;
    listen: string;
    upstream: string;
    enabled?: boolean;
  }): Promise<Proxy> {
    const raw = await this.request<any>("/proxies", {
      method: "POST",
      body: JSON.stringify({
        name: input.name,
        listen: input.listen,
        upstream: input.upstream,
        enabled: input.enabled ?? true,
      }),
    });
    return this.wrap(raw);
  }

  async getOrCreateProxy(input: {
    name: string;
    listen: string;
    upstream: string;
    enabled?: boolean;
  }): Promise<Proxy> {
    const existing = await this.get(input.name);
    if (existing) return existing;
    return this.createProxy(input);
  }

  async reset(): Promise<void> {
    await this.request("/reset", { method: "POST" });
  }
}

// ─── Toxic builder helpers ───────────────────────────────────────────────────

export function latencyToxic(
  latencyMs: number,
  jitterMs: number = 0,
  toxicity: number = 1.0,
): Omit<Toxic, "name"> & { name?: string } {
  return {
    type: "latency",
    toxicity,
    attributes: { latency: latencyMs, jitter: jitterMs },
  };
}

export function timeoutToxic(
  timeoutMs: number,
  toxicity: number = 1.0,
): Omit<Toxic, "name"> & { name?: string } {
  return {
    type: "timeout",
    toxicity,
    attributes: { timeout: timeoutMs },
  };
}

export function bandwidthToxic(
  rateKBps: number,
  toxicity: number = 1.0,
): Omit<Toxic, "name"> & { name?: string } {
  return {
    type: "bandwidth",
    toxicity,
    attributes: { rate: rateKBps },
  };
}

export function resetPeerToxic(
  timeoutMs: number = 0,
  toxicity: number = 1.0,
): Omit<Toxic, "name"> & { name?: string } {
  return {
    type: "reset_peer",
    toxicity,
    attributes: { timeout: timeoutMs },
  };
}

export function limitDataToxic(
  bytes: number,
  toxicity: number = 1.0,
): Omit<Toxic, "name"> & { name?: string } {
  return {
    type: "limit_data",
    toxicity,
    attributes: { bytes },
  };
}

export function slicerToxic(
  averageSize: number,
  delayMs: number = 0,
  sizeVariation: number = 0,
  toxicity: number = 1.0,
): Omit<Toxic, "name"> & { name?: string } {
  return {
    type: "slicer",
    toxicity,
    attributes: {
      average_size: averageSize,
      delay: delayMs,
      size_variation: sizeVariation,
    },
  };
}
