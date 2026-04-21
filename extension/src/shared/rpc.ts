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

export async function getBalance(
  address: string,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<BalanceResponse> {
  return fetchJSON<BalanceResponse>(`${rpcUrl}/balance/${address}`);
}

export async function submitTx(
  tx: object,
  rpcUrl = DEFAULT_RPC_URL,
): Promise<SubmitTxResponse> {
  return fetchJSON<SubmitTxResponse>(`${rpcUrl}/tx/submit`, {
    method: 'POST',
    body: JSON.stringify({ tx }),
  });
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
