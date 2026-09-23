import type {
  BalanceResult,
  DeployedContract,
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

  /**
   * Call a JSON-RPC method. The node serves JSON-RPC at POST / — the REST
   * paths only cover blocks, transactions, health and nodes.
   */
  private async rpc<T>(method: string, params: unknown = {}): Promise<T> {
    const body = { jsonrpc: "2.0", id: Date.now(), method, params };
    const res = await this.post<{ result?: T; error?: { code: number; message: string } }>("/", body);
    if (res.error) throw new Error(`${method} failed (${res.error.code}): ${res.error.message}`);
    return res.result as T;
  }

  async submitTx(tx: TxEnvelope): Promise<TxSubmitResult> {
    return this.rpc<TxSubmitResult>("tx.submit", { tx });
  }

  /**
   * Read one value out of a deployed contract's state.
   *
   * Returns the raw hex the contract stored, or null when the key is unset.
   * Decoding it is the caller's job: the chain does not know what the bytes mean.
   */
  async getContractState(
    contractAddr: string,
    prefix: string,
    key: string,
  ): Promise<string | null> {
    const r = await this.rpc<{ value: string | null }>("contract.getState", {
      contractAddr,
      prefix,
      key,
    });
    return r.value ?? null;
  }

  /** Every contract this node has seen deployed. */
  async listDeployedContracts(): Promise<DeployedContract[]> {
    return this.rpc<DeployedContract[]>("contract.listDeployed", {});
  }

  /** Confirmed nonce for an address, which a contract call must be built on top of. */
  async getNonce(address: string): Promise<number> {
    const r = await this.rpc<{ nonce: number }>("wallet.getNonce", { address });
    return r.nonce ?? 0;
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
