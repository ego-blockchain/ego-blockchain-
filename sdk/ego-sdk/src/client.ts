import type {
  BalanceResult,
  BlockSummary,
  EgoClientOptions,
  HealthResult,
  NodeStats,
  PendingTx,
  TxEnvelope,
  TxSubmitResult,
} from "./types";

const DEFAULT_RPC_URL = "http://localhost:8545";
const DEFAULT_TIMEOUT  = 10_000;

export class EgoClient {
  private readonly rpcUrl: string;
  private readonly timeout: number;

  constructor(options: EgoClientOptions = {}) {
    this.rpcUrl  = (options.rpcUrl ?? DEFAULT_RPC_URL).replace(/\/$/, "");
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
  }

  private async get<T>(path: string): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.rpcUrl}${path}`, { signal: controller.signal });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`HTTP ${res.status}: ${body}`);
      }
      return res.json() as Promise<T>;
    } finally {
      clearTimeout(timer);
    }
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.rpcUrl}${path}`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
        signal:  controller.signal,
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP ${res.status}: ${text}`);
      }
      return res.json() as Promise<T>;
    } finally {
      clearTimeout(timer);
    }
  }

  async health(): Promise<HealthResult> {
    return this.get<HealthResult>("/health");
  }

  async getBlocks(): Promise<BlockSummary[]> {
    return this.get<BlockSummary[]>("/chain/blocks");
  }

  async getBlock(height: number): Promise<BlockSummary> {
    return this.get<BlockSummary>(`/block/${height}`);
  }

  async getBalance(address: string): Promise<BalanceResult> {
    const addr = address.startsWith("0x") ? address.slice(2) : address;
    return this.get<BalanceResult>(`/balance/${addr}`);
  }

  async submitTx(tx: TxEnvelope): Promise<TxSubmitResult> {
    return this.post<TxSubmitResult>("/tx/submit", { tx });
  }

  async getPendingTxs(): Promise<PendingTx[]> {
    return this.get<PendingTx[]>("/chain/transactions");
  }

  async getNodeStats(): Promise<NodeStats> {
    return this.get<NodeStats>("/node/stats");
  }

  async waitForBlocks(count = 1, pollMs = 500, timeoutMs = 30_000): Promise<number> {
    const start = (await this.health()).block_height;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await sleep(pollMs);
      const current = (await this.health()).block_height;
      if (current >= start + count) return current;
    }
    throw new Error(`Timed out waiting for ${count} block(s)`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
