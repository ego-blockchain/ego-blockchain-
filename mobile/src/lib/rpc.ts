/**
 * Ego Node RPC Client
 *
 * Talks to ego-node's HTTP JSON-RPC endpoint at http://127.0.0.1:8545
 * (configurable via EGO_RPC_URL).
 */

const DEFAULT_RPC = 'http://127.0.0.1:8545';
let rpcUrl = DEFAULT_RPC;

export function setRpcUrl(url: string) {
  rpcUrl = url;
}

export function getRpcUrl(): string {
  return rpcUrl;
}

// ── Core JSON-RPC call ─────────────────────────────────────────────────────

let idCounter = 0;

async function rpcCall<T>(method: string, params: unknown[] = []): Promise<T> {
  const id = ++idCounter;
  const body = JSON.stringify({ jsonrpc: '2.0', id, method, params });

  const resp = await fetch(rpcUrl, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });

  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  }

  const json = await resp.json();

  if (json.error) {
    throw new Error(`[${json.error.code}] ${json.error.message}`);
  }

  return json.result as T;
}

// ── Types ──────────────────────────────────────────────────────────────────

export interface RpcBlock {
  hash:       string;
  height:     number;
  timestamp:  number;
  txCount:    number;
  validator:  string;
}

export interface RpcTransaction {
  hash:      string;
  from:      string;
  to:        string;
  value:     string;   // uEGOC decimal string
  data:      string;   // hex calldata
  nonce:     number;
  status:    'confirmed' | 'pending' | 'failed';
  blockHash: string;
  timestamp: number;
}

export interface RpcNetworkStats {
  chainId:       number;
  blockHeight:   number;
  tps:           number;
  peerCount:     number;
  validatorCount: number;
}

// ── Balance ────────────────────────────────────────────────────────────────

/**
 * Returns the balance for `address` in uEGOC.
 */
export async function getBalance(address: string): Promise<bigint> {
  const raw = await rpcCall<string>('ego_getBalance', [address]);
  return BigInt(raw ?? '0');
}

// ── Transactions ───────────────────────────────────────────────────────────

/**
 * Fetch recent transactions for `address` (most recent first).
 */
export async function getTransactions(address: string, limit = 50): Promise<RpcTransaction[]> {
  const result = await rpcCall<RpcTransaction[]>('ego_getTransactions', [address, limit]);
  return result ?? [];
}

/**
 * Send a signed raw transaction.
 * @param signedHex  Hex-encoded signed transaction bytes.
 * @returns          Transaction hash.
 */
export async function sendRawTransaction(signedHex: string): Promise<string> {
  return rpcCall<string>('ego_sendRawTransaction', [signedHex]);
}

/**
 * Submit an unsigned send request (wallet signs locally before broadcasting).
 * This is a convenience wrapper for the mobile wallet.
 */
export async function sendTransaction(params: {
  from:  string;
  to:    string;
  value: string;  // uEGOC decimal string
  data?: string;
  nonce?: number;
}): Promise<string> {
  return rpcCall<string>('ego_sendTransaction', [params]);
}

// ── Blocks ─────────────────────────────────────────────────────────────────

export async function getBlock(hashOrHeight: string | number): Promise<RpcBlock> {
  return rpcCall<RpcBlock>('ego_getBlock', [hashOrHeight]);
}

export async function getLatestBlock(): Promise<RpcBlock> {
  return rpcCall<RpcBlock>('ego_getLatestBlock', []);
}

// ── Network stats ──────────────────────────────────────────────────────────

export async function getNetworkStats(): Promise<RpcNetworkStats> {
  return rpcCall<RpcNetworkStats>('ego_getNetworkStats', []);
}

// ── Nonce ──────────────────────────────────────────────────────────────────

export async function getNonce(address: string): Promise<number> {
  const raw = await rpcCall<string>('ego_getTransactionCount', [address]);
  return parseInt(raw ?? '0', 16);
}

// ── Utils ──────────────────────────────────────────────────────────────────

/**
 * Convert uEGOC (bigint) to a human-readable EGOC string.
 * e.g. 1_500_000n → "1.500000"
 */
export function uEgocToEgoc(uegoc: bigint): string {
  const whole = uegoc / 1_000_000n;
  const frac  = uegoc % 1_000_000n;
  return `${whole}.${frac.toString().padStart(6, '0')}`;
}

/**
 * Convert EGOC string to uEGOC bigint.
 * e.g. "1.5" → 1_500_000n
 */
export function egocToUEgoc(egoc: string): bigint {
  const parts = egoc.split('.');
  const whole = BigInt(parts[0] ?? '0');
  const fracStr = (parts[1] ?? '').padEnd(6, '0').slice(0, 6);
  const frac  = BigInt(fracStr);
  return whole * 1_000_000n + frac;
}
