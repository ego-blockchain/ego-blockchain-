import type {
  BalanceResponse,
  BlockSummary,
  FaucetResponse,
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

export async function getHealth(rpcUrl = DEFAULT_RPC_URL): Promise<HealthResponse> {
  return fetchJSON<HealthResponse>(`${rpcUrl}/health`);
}

export async function requestFaucet(
  address: string,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<FaucetResponse> {
  return fetchJSON<FaucetResponse>(`${rpcUrl}/faucet?to=${encodeURIComponent(address)}`);
}
