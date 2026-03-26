export interface LedgerTx {
  hash: string;
  from: string;
  to: string;

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

  path: string[];

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

  ru_used: number;
}

export interface CallResult {
  success: boolean;
  return_hex: string;
  events: ContractEvent[];

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

  abi: string[];
}

export type SubscriptionEvent =
  | { type: 'block'; data: LightBlockHeader }
  | { type: 'transaction'; data: LedgerTx }
  | { type: 'contract_event'; data: ContractEvent & { contract_addr: string } };

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

export class EgoRpcError extends Error {

  public readonly code: number;
  public readonly data: unknown;

  constructor(message: string, code: number, data?: unknown) {
    super(message);
    this.name = 'EgoRpcError';
    this.code = code;
    this.data = data;
  }
}

export function uegocToEgoc(uegoc: number): number {
  return uegoc / 1_000_000;
}

export function egocToUegoc(egoc: number): number {
  return Math.round(egoc * 1_000_000);
}

export function formatEgoc(uegoc: number): string {
  return `${uegocToEgoc(uegoc).toFixed(6)} EGOC`;
}

const DEFAULT_RPC_URL = 'http://127.0.0.1:47395';
const DEFAULT_WS_URL  = 'ws://127.0.0.1:47395/ws';

export interface EgoClientOptions {

  rpcUrl?: string;

  wsUrl?: string;
}

export class EgoClient {
  private readonly rpcUrl: string;
  private readonly wsUrl: string;
  private _requestId = 0;

  constructor(options: EgoClientOptions = {}) {
    this.rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL;
    this.wsUrl  = options.wsUrl  ?? DEFAULT_WS_URL;
  }

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

  async getBalance(address: string): Promise<number> {
    return this.rpc<number>('wallet_getBalance', { address });
  }

  async getBalanceEgoc(address: string): Promise<number> {
    const uegoc = await this.getBalance(address);
    return uegocToEgoc(uegoc);
  }

  async sendTransaction(params: {
    from: string;
    to: string;

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

  async getTransactionHistory(address: string, limit = 50): Promise<LedgerTx[]> {
    return this.rpc<LedgerTx[]>('wallet_getTransactionHistory', { address, limit });
  }

  async getTransaction(hash: string): Promise<LedgerTx | null> {
    return this.rpc<LedgerTx | null>('wallet_getTransaction', { hash });
  }

  async getBlocks(fromHeight = 0, limit = 20): Promise<LedgerBlock[]> {
    return this.rpc<LedgerBlock[]>('chain_getBlocks', { from_height: fromHeight, limit });
  }

  async getBlockHeaders(fromHeight = 0, limit = 20): Promise<LightBlockHeader[]> {
    return this.rpc<LightBlockHeader[]>('chain_getBlockHeaders', { from_height: fromHeight, limit });
  }

  async getBlock(height: number): Promise<LedgerBlock | null> {
    return this.rpc<LedgerBlock | null>('chain_getBlock', { height });
  }

  async getTxProof(txHash: string): Promise<MerkleProof | null> {
    return this.rpc<MerkleProof | null>('chain_getTxProof', { tx_hash: txHash });
  }

  async verifyTxProof(proof: MerkleProof): Promise<boolean> {
    return this.rpc<boolean>('chain_verifyTxProof', {
      tx_hash: proof.tx_hash,
      root:    proof.root,
      path:    proof.path,
      indices: proof.indices,
    });
  }

  async getNetworkStats(): Promise<NetworkStats> {
    return this.rpc<NetworkStats>('chain_getNetworkStats', {});
  }

  async getEgocPrice(): Promise<number> {
    const stats = await this.getNetworkStats();
    return stats.egoc_price_usd;
  }

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

  async getContractState(contractAddr: string, prefix: string, key: string): Promise<string | null> {
    return this.rpc<string | null>('contract_getState', { contract_addr: contractAddr, prefix, key });
  }

  async listContracts(): Promise<ContractInfo[]> {
    return this.rpc<ContractInfo[]>('contract_list', {});
  }

  async getContractEvents(contractAddr: string, limit = 50): Promise<ContractEvent[]> {
    return this.rpc<ContractEvent[]>('contract_getEvents', { contract_addr: contractAddr, limit });
  }

  async getPeers(): Promise<Array<{ address: string; endpoint: string; last_seen: number }>> {
    return this.rpc<Array<{ address: string; endpoint: string; last_seen: number }>>('p2p_getPeers', {});
  }

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

        return;
      }

      if (!isSubscriptionEvent(parsed)) return;
      callback(parsed);
    };

    ws.onerror = () => {

    };

    return ws;
  }

  subscribeToBlocks(callback: (header: LightBlockHeader) => void): WebSocket {
    return this.subscribe((event) => {
      if (event.type === 'block') {
        callback(event.data);
      }
    });
  }

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

    };

    return ws;
  }
}

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

export function createClient(options?: EgoClientOptions): EgoClient {
  return new EgoClient(options);
}

export default createClient;
