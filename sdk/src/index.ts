/**
 * @ego-blockchain/sdk
 * Production-grade TypeScript SDK for the Ego Blockchain.
 * Connects to a local JSON-RPC server at http://127.0.0.1:47395.
 * No external dependencies — uses only built-in fetch and WebSocket.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface LedgerTx {
  hash: string;
  from: string;
  to: string;
  /** Amount in uEGOC (micro-EGOC). */
  amount: number;
  memo?: string;
  timestamp: number;
  status: string;
  block_height?: number;
  nonce: number;
  tx_type: string;
  fee_uegoc: number;
  priority_fee_uegoc: number;
}

export interface LedgerBlock {
  height: number;
  hash: string;
  prev_hash: string;
  timestamp: number;
  miner: string;
  tx_count: number;
  reward: number;
  vote_count: number;
  tx_merkle_root: string;
}

export interface LightBlockHeader {
  height: number;
  hash: string;
  prev_hash: string;
  miner: string;
  timestamp: number;
  tx_count: number;
  reward: number;
  tx_merkle_root: string;
}

export interface MerkleProof {
  tx_hash: string;
  root: string;
  /** Sibling hashes along the path from leaf to root. */
  path: string[];
  /** true = right sibling, false = left sibling at each level. */
  indices: boolean[];
}

export interface NetworkStats {
  block_count: number;
  tx_count: number;
  peer_count: number;
  pending_tx_count: number;
  finalized_height: number;
  egoc_price_usd: number;
  tps: number;
}

export interface DeployResult {
  contract_address: string;
  code_hash: string;
  /** Resource units consumed during deployment. */
  ru_used: number;
}

export interface CallResult {
  success: boolean;
  return_hex: string;
  events: ContractEvent[];
  /** Resource units consumed during the call. */
  ru_used: number;
}

export interface ContractEvent {
  topic: string;
  payload_hex: string;
  timestamp: number;
  height: number;
}

export interface ContractInfo {
  address: string;
  name: string;
  deployer: string;
  deployed_at: number;
  code_hash: string;
  /** ABI method signatures, e.g. ["transfer(address,u64)", "balance(address)"] */
  abi: string[];
}

export type SubscriptionEvent =
  | { type: 'block'; data: LightBlockHeader }
  | { type: 'transaction'; data: LedgerTx }
  | { type: 'contract_event'; data: ContractEvent & { contract_addr: string } };

// ─────────────────────────────────────────────────────────────────────────────
// Internal JSON-RPC types
// ─────────────────────────────────────────────────────────────────────────────

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params: Record<string, unknown>;
}

interface JsonRpcSuccess<T> {
  jsonrpc: '2.0';
  id: number;
  result: T;
}

interface JsonRpcError {
  jsonrpc: '2.0';
  id: number;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

type JsonRpcResponse<T> = JsonRpcSuccess<T> | JsonRpcError;

function isRpcError<T>(res: JsonRpcResponse<T>): res is JsonRpcError {
  return 'error' in res;
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom error
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Thrown when the JSON-RPC server returns an error response, or when the
 * HTTP request itself fails.
 */
export class EgoRpcError extends Error {
  /** JSON-RPC error code, or -1 for transport/HTTP errors. */
  public readonly code: number;
  public readonly data: unknown;

  constructor(message: string, code: number, data?: unknown) {
    super(message);
    this.name = 'EgoRpcError';
    this.code = code;
    this.data = data;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────────────────────

/** Convert uEGOC to EGOC (1 EGOC = 1,000,000 uEGOC). */
export function uegocToEgoc(uegoc: number): number {
  return uegoc / 1_000_000;
}

/** Convert EGOC to uEGOC (1 EGOC = 1,000,000 uEGOC). */
export function egocToUegoc(egoc: number): number {
  return Math.round(egoc * 1_000_000);
}

/**
 * Format a uEGOC value as a human-readable EGOC string.
 * @example formatEgoc(1_500_000) === "1.500000 EGOC"
 */
export function formatEgoc(uegoc: number): string {
  return `${uegocToEgoc(uegoc).toFixed(6)} EGOC`;
}

// ─────────────────────────────────────────────────────────────────────────────
// EgoClient
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_RPC_URL = 'http://127.0.0.1:47395';
const DEFAULT_WS_URL  = 'ws://127.0.0.1:47395/ws';

export interface EgoClientOptions {
  /** JSON-RPC HTTP endpoint. Defaults to http://127.0.0.1:47395 */
  rpcUrl?: string;
  /** WebSocket endpoint for subscriptions. Defaults to ws://127.0.0.1:47395/ws */
  wsUrl?: string;
}

/**
 * Main client for interacting with the Ego Blockchain node.
 *
 * All RPC calls use JSON-RPC 2.0 over HTTP fetch.
 * Subscription methods use a plain WebSocket.
 *
 * @example
 * ```ts
 * import { createClient } from '@ego-blockchain/sdk';
 * const client = createClient();
 * const balance = await client.getBalance('egot1abc...');
 * ```
 */
export class EgoClient {
  private readonly rpcUrl: string;
  private readonly wsUrl: string;
  private _requestId = 0;

  constructor(options: EgoClientOptions = {}) {
    this.rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL;
    this.wsUrl  = options.wsUrl  ?? DEFAULT_WS_URL;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Private transport
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Perform a JSON-RPC 2.0 call over HTTP.
   * @throws {EgoRpcError} on network failure or RPC-level error.
   */
  private async rpc<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = ++this._requestId;
    const body: JsonRpcRequest = {
      jsonrpc: '2.0',
      id,
      method,
      params,
    };

    let response: Response;
    try {
      response = await fetch(this.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (err) {
      throw new EgoRpcError(
        `Network error calling ${method}: ${err instanceof Error ? err.message : String(err)}`,
        -1,
        err,
      );
    }

    if (!response.ok) {
      throw new EgoRpcError(
        `HTTP ${response.status} ${response.statusText} calling ${method}`,
        -1,
      );
    }

    let json: JsonRpcResponse<T>;
    try {
      json = (await response.json()) as JsonRpcResponse<T>;
    } catch (err) {
      throw new EgoRpcError(
        `Failed to parse JSON response for ${method}: ${err instanceof Error ? err.message : String(err)}`,
        -1,
        err,
      );
    }

    if (isRpcError(json)) {
      throw new EgoRpcError(json.error.message, json.error.code, json.error.data);
    }

    return json.result;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Wallet methods
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Get the balance of an address in uEGOC.
   * @param address Bech32 Ego address (e.g. `egot1...`)
   * @returns Balance in uEGOC (micro-EGOC).
   */
  async getBalance(address: string): Promise<number> {
    return this.rpc<number>('wallet_getBalance', { address });
  }

  /**
   * Get the balance of an address in EGOC.
   * @param address Bech32 Ego address (e.g. `egot1...`)
   * @returns Balance in EGOC (1 EGOC = 1,000,000 uEGOC).
   */
  async getBalanceEgoc(address: string): Promise<number> {
    const uegoc = await this.getBalance(address);
    return uegocToEgoc(uegoc);
  }

  /**
   * Broadcast a signed transaction.
   * @returns The transaction hash.
   */
  async sendTransaction(params: {
    from: string;
    to: string;
    /** Amount in uEGOC. */
    amount: number;
    feeUegoc?: number;
    priorityFeeUegoc?: number;
    memo?: string;
  }): Promise<string> {
    return this.rpc<string>('wallet_sendTransaction', {
      from:                params.from,
      to:                  params.to,
      amount:              params.amount,
      fee_uegoc:           params.feeUegoc           ?? 0,
      priority_fee_uegoc:  params.priorityFeeUegoc   ?? 0,
      memo:                params.memo               ?? '',
    });
  }

  /**
   * Retrieve transaction history for an address.
   * @param address Bech32 Ego address.
   * @param limit   Maximum number of transactions to return. Defaults to 50.
   */
  async getTransactionHistory(address: string, limit = 50): Promise<LedgerTx[]> {
    return this.rpc<LedgerTx[]>('wallet_getTransactionHistory', { address, limit });
  }

  /**
   * Look up a single transaction by hash.
   * @returns The transaction, or `null` if not found.
   */
  async getTransaction(hash: string): Promise<LedgerTx | null> {
    return this.rpc<LedgerTx | null>('wallet_getTransaction', { hash });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Chain methods
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Retrieve full block data starting from a given height.
   * @param fromHeight Starting block height (inclusive). Defaults to 0.
   * @param limit      Maximum number of blocks to return. Defaults to 20.
   */
  async getBlocks(fromHeight = 0, limit = 20): Promise<LedgerBlock[]> {
    return this.rpc<LedgerBlock[]>('chain_getBlocks', { from_height: fromHeight, limit });
  }

  /**
   * Retrieve lightweight block headers — suitable for SPV / light clients.
   * @param fromHeight Starting block height (inclusive). Defaults to 0.
   * @param limit      Maximum number of headers to return. Defaults to 20.
   */
  async getBlockHeaders(fromHeight = 0, limit = 20): Promise<LightBlockHeader[]> {
    return this.rpc<LightBlockHeader[]>('chain_getBlockHeaders', { from_height: fromHeight, limit });
  }

  /**
   * Look up a single block by height.
   * @returns The block, or `null` if it does not exist.
   */
  async getBlock(height: number): Promise<LedgerBlock | null> {
    return this.rpc<LedgerBlock | null>('chain_getBlock', { height });
  }

  /**
   * Get a Merkle inclusion proof for a transaction.
   * @param txHash Transaction hash.
   * @returns Merkle proof, or `null` if the transaction is not yet included in a block.
   */
  async getTxProof(txHash: string): Promise<MerkleProof | null> {
    return this.rpc<MerkleProof | null>('chain_getTxProof', { tx_hash: txHash });
  }

  /**
   * Verify a Merkle inclusion proof on-node.
   * @returns `true` if the proof is valid and the transaction is included.
   */
  async verifyTxProof(proof: MerkleProof): Promise<boolean> {
    return this.rpc<boolean>('chain_verifyTxProof', {
      tx_hash: proof.tx_hash,
      root:    proof.root,
      path:    proof.path,
      indices: proof.indices,
    });
  }

  /**
   * Get a snapshot of current network statistics.
   */
  async getNetworkStats(): Promise<NetworkStats> {
    return this.rpc<NetworkStats>('chain_getNetworkStats', {});
  }

  /**
   * Get the current EGOC price in USD from the node's oracle.
   */
  async getEgocPrice(): Promise<number> {
    const stats = await this.getNetworkStats();
    return stats.egoc_price_usd;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Contract methods
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Deploy a WASM smart contract to the chain.
   * @param params.wasmHex      Compiled WASM bytecode as a hex string.
   * @param params.initArgsHex  ABI-encoded constructor arguments (hex). Optional.
   * @param params.name         Human-readable contract name. Optional.
   * @param params.abi          ABI method signatures. Optional.
   * @returns Deployment result including contract address and resource usage.
   */
  async deployContract(params: {
    wasmHex: string;
    initArgsHex?: string;
    name?: string;
    abi?: string[];
  }): Promise<DeployResult> {
    return this.rpc<DeployResult>('contract_deploy', {
      wasm_hex:      params.wasmHex,
      init_args_hex: params.initArgsHex ?? '',
      name:          params.name        ?? '',
      abi:           params.abi         ?? [],
    });
  }

  /**
   * Call an entry-point on a deployed contract.
   * @param params.contractAddr Contract address.
   * @param params.entrypoint   Entry-point name (e.g. `"transfer"`).
   * @param params.argsHex      ABI-encoded arguments (hex). Optional.
   * @returns Call result including return value, events, and resource usage.
   */
  async callContract(params: {
    contractAddr: string;
    entrypoint: string;
    argsHex?: string;
  }): Promise<CallResult> {
    return this.rpc<CallResult>('contract_call', {
      contract_addr: params.contractAddr,
      entrypoint:    params.entrypoint,
      args_hex:      params.argsHex ?? '',
    });
  }

  /**
   * Read a raw key-value entry from a contract's state store.
   * @param contractAddr Contract address.
   * @param prefix       State namespace prefix.
   * @param key          State key within the prefix.
   * @returns Hex-encoded value, or `null` if the key does not exist.
   */
  async getContractState(contractAddr: string, prefix: string, key: string): Promise<string | null> {
    return this.rpc<string | null>('contract_getState', { contract_addr: contractAddr, prefix, key });
  }

  /**
   * List all deployed contracts known to this node.
   */
  async listContracts(): Promise<ContractInfo[]> {
    return this.rpc<ContractInfo[]>('contract_list', {});
  }

  /**
   * Get the most recent events emitted by a contract.
   * @param contractAddr Contract address.
   * @param limit        Maximum number of events. Defaults to 50.
   */
  async getContractEvents(contractAddr: string, limit = 50): Promise<ContractEvent[]> {
    return this.rpc<ContractEvent[]>('contract_getEvents', { contract_addr: contractAddr, limit });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // P2P methods
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Get the list of connected peers.
   * @returns Array of peer descriptors.
   */
  async getPeers(): Promise<Array<{ address: string; endpoint: string; last_seen: number }>> {
    return this.rpc<Array<{ address: string; endpoint: string; last_seen: number }>>('p2p_getPeers', {});
  }

  // ──────────────────────────────────────────────────────────────────────────
  // WebSocket subscriptions
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Subscribe to all real-time node events (blocks, transactions, contract events).
   *
   * The returned WebSocket can be closed to stop the subscription.
   * @param callback Invoked once per parsed event.
   * @returns The raw WebSocket instance.
   */
  subscribe(callback: (event: SubscriptionEvent) => void): WebSocket {
    const ws = new WebSocket(this.wsUrl);

    ws.onopen = () => {
      ws.send(JSON.stringify({ subscribe: 'all' }));
    };

    ws.onmessage = (event: MessageEvent) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(event.data as string);
      } catch {
        // Non-JSON frame — ignore.
        return;
      }

      if (!isSubscriptionEvent(parsed)) return;
      callback(parsed);
    };

    ws.onerror = () => {
      // Errors surface via onclose; no further action needed here.
    };

    return ws;
  }

  /**
   * Subscribe only to new block headers.
   * @param callback Invoked with each new `LightBlockHeader`.
   * @returns The raw WebSocket instance.
   */
  subscribeToBlocks(callback: (header: LightBlockHeader) => void): WebSocket {
    return this.subscribe((event) => {
      if (event.type === 'block') {
        callback(event.data);
      }
    });
  }

  /**
   * Subscribe to transactions involving a specific address.
   * Fires for both incoming and outgoing transactions.
   * @param address  Bech32 Ego address to watch.
   * @param callback Invoked with each relevant `LedgerTx`.
   * @returns The raw WebSocket instance.
   */
  subscribeToAddress(address: string, callback: (tx: LedgerTx) => void): WebSocket {
    const ws = new WebSocket(this.wsUrl);

    ws.onopen = () => {
      ws.send(JSON.stringify({ subscribe: 'address', address }));
    };

    ws.onmessage = (event: MessageEvent) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(event.data as string);
      } catch {
        return;
      }

      if (!isSubscriptionEvent(parsed)) return;
      if (parsed.type === 'transaction') {
        const tx = parsed.data;
        if (tx.from === address || tx.to === address) {
          callback(tx);
        }
      }
    };

    ws.onerror = () => {
      // Errors surface via onclose.
    };

    return ws;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type guard for subscription events
// ─────────────────────────────────────────────────────────────────────────────

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isSubscriptionEvent(value: unknown): value is SubscriptionEvent {
  if (!isObject(value)) return false;
  const type = value['type'];
  if (type === 'block' || type === 'transaction' || type === 'contract_event') {
    return isObject(value['data']);
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a new `EgoClient` instance.
 *
 * @example
 * ```ts
 * import { createClient } from '@ego-blockchain/sdk';
 *
 * const client = createClient();
 * const stats  = await client.getNetworkStats();
 * console.log('Block height:', stats.finalized_height);
 * ```
 */
export function createClient(options?: EgoClientOptions): EgoClient {
  return new EgoClient(options);
}

export default createClient;
