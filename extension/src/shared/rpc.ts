import type {
  BalanceResponse,
  BlockSummary,
  HealthResponse,
  SubmitTxResponse,
  TxRecord,
} from './types';

export const DEFAULT_RPC_URL = 'http://127.0.0.1:47395';

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// The Ego node serves wallet data over JSON-RPC 2.0 at POST / (not REST paths).
async function jsonRpc<T>(rpcUrl: string, method: string, params: unknown): Promise<T> {
  const res = await fetchJSON<{ result?: T; error?: { message?: string } }>(rpcUrl, {
    method: 'POST',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (res.error) throw new Error(res.error.message ?? `${method} failed`);
  return res.result as T;
}

export async function getBalance(
  address: string,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<BalanceResponse> {
  const r = await jsonRpc<{ uegoc?: number; egoc?: number }>(
    rpcUrl, 'wallet.getBalance', { address },
  );
  return {
    address,
    balance_uegoc: r?.uegoc ?? 0,
    balance_egoc:  r?.egoc  ?? 0,
  };
}

export async function submitTx(
  tx: object,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<SubmitTxResponse> {
  return jsonRpc<SubmitTxResponse>(rpcUrl, 'tx.submit', { tx });
}

export interface NonceInfo {
  last_confirmed: number;
  next: number;
  fee_uegoc: number;
  chain_id: number;
}

export async function getNonceInfo(
  address: string,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<NonceInfo> {
  return jsonRpc<NonceInfo>(rpcUrl, 'wallet.getNonce', { address });
}

export async function getBlocks(rpcUrl = DEFAULT_RPC_URL): Promise<BlockSummary[]> {
  return fetchJSON<BlockSummary[]>(`${rpcUrl}/chain/blocks`);
}

export async function getTransactions(rpcUrl = DEFAULT_RPC_URL): Promise<TxRecord[]> {
  return fetchJSON<TxRecord[]>(`${rpcUrl}/chain/transactions`);
}

export interface AddressTx {
  hash: string;
  from: string;
  to: string;
  amount: number;
  fee_uegoc?: number;
  timestamp: number;
  tx_type?: string;
  block_height?: number | null;
}

export async function getAddressHistory(
  address: string,
  limit = 50,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<AddressTx[]> {
  const txs = await jsonRpc<AddressTx[] | null>(rpcUrl, 'wallet.getTransactionHistory', { address, limit });
  return txs ?? [];
}

export async function getHealth(rpcUrl = DEFAULT_RPC_URL): Promise<HealthResponse> {
  return fetchJSON<HealthResponse>(`${rpcUrl}/health`);
}

export interface ShieldedState {
  enabled: boolean;
  active: boolean;
  pool_address: string;
  pool_balance_uegoc: number;
  leaf_count: number;
  root: string;
  recent_roots: string[];
  denominations_uegoc: number[];
  max_spends: number;
  min_fee_uegoc: number;
  current_fee_uegoc: number;
  proof_system: string;
  local_height: number;
  network_tip: number;
  finalized_height: number;
  spendable_uegoc: number;
}

export interface ShieldedLeavesPage {
  from: number;
  leaves: string[];
  leaf_count: number;
}

export interface ShieldedCheck {
  nullifiers: boolean[];
  txs: { hash: string; block_height: number | null; finalized: boolean; in_mempool: boolean }[];
  local_height: number;
  network_tip: number;
  finalized_height: number;
}

function needsNewerNode(e: unknown): Error {
  const msg = (e as Error)?.message ?? String(e);
  if (/method not found|unknown method|-32601/i.test(msg)) {
    return new Error('Your Ego node is too old for shielded transactions from the extension. Update Ego Desktop to the latest version.');
  }
  return e instanceof Error ? e : new Error(msg);
}

export async function getShieldedState(address: string, rpcUrl = DEFAULT_RPC_URL): Promise<ShieldedState> {
  return jsonRpc<ShieldedState>(rpcUrl, 'shielded.state', { address }).catch(e => { throw needsNewerNode(e); });
}

export async function getShieldedLeaves(
  from: number,
  limit: number,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<ShieldedLeavesPage> {
  return jsonRpc<ShieldedLeavesPage>(rpcUrl, 'shielded.leaves', { from, limit }).catch(e => { throw needsNewerNode(e); });
}

export async function checkShielded(
  nullifiers: string[],
  txs: string[],
  rpcUrl = DEFAULT_RPC_URL,
): Promise<ShieldedCheck> {
  return jsonRpc<ShieldedCheck>(rpcUrl, 'shielded.check', { nullifiers, txs }).catch(e => { throw needsNewerNode(e); });
}

export interface SealedNotesExport {
  found: boolean;
  wallet?: string;
  sealed?: string | null;
}

export async function exportWalletNotes(
  request: { address: string; public_key: string; timestamp: number; signature: string },
  rpcUrl = DEFAULT_RPC_URL,
): Promise<SealedNotesExport> {
  return jsonRpc<SealedNotesExport>(rpcUrl, 'shielded.exportNotes', request);
}
