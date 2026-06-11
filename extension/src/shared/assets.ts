import type { TrackedAsset, AssetBalance } from './types';

export const CHAINS = {
  BTC:  { name: 'Bitcoin',  icon: '₿', color: '#f7931a', tokens: false },
  ETH:  { name: 'Ethereum', icon: 'Ξ', color: '#627EEA', tokens: true  },
  BNB:  { name: 'BNB Chain', icon: '◆', color: '#F3BA2F', tokens: true  },
  SOL:  { name: 'Solana',   icon: '◎', color: '#9945FF', tokens: false },
  DOGE: { name: 'Dogecoin', icon: 'Ð', color: '#C2A633', tokens: false },
  LTC:  { name: 'Litecoin', icon: 'Ł', color: '#A5A5A5', tokens: false },
} as const;

export type ChainId = keyof typeof CHAINS;

const EVM_RPC: Record<string, string> = {
  ETH: 'https://eth.llamarpc.com',
  BNB: 'https://bsc-dataseed.binance.org',
};

const ADDRESS_PATTERNS: Record<ChainId, RegExp> = {
  BTC:  /^(bc1[a-z0-9]{20,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
  ETH:  /^0x[0-9a-fA-F]{40}$/,
  BNB:  /^0x[0-9a-fA-F]{40}$/,
  SOL:  /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
  DOGE: /^D[a-km-zA-HJ-NP-Z1-9]{25,34}$/,
  LTC:  /^(ltc1[a-z0-9]{20,90}|[LM][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
};

export function validateAddress(chain: ChainId, address: string): boolean {
  return ADDRESS_PATTERNS[chain]?.test(address.trim()) ?? false;
}

async function fetchJson(url: string, init?: RequestInit): Promise<any> {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function evmRpc(rpc: string, method: string, params: unknown[]): Promise<string> {
  const j = await fetchJson(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (j.error) throw new Error(j.error.message ?? 'RPC error');
  return j.result as string;
}

function hexToBigInt(hex: string): bigint {
  if (!hex || hex === '0x') return 0n;
  return BigInt(hex);
}

function units(raw: bigint, decimals: number): number {
  const d = BigInt(10) ** BigInt(decimals);
  return Number(raw / d) + Number(raw % d) / Number(d);
}

function pad32(addr: string): string {
  return addr.replace(/^0x/, '').toLowerCase().padStart(64, '0');
}

function decodeAbiString(hex: string): string {
  const h = hex.replace(/^0x/, '');
  if (h.length < 128) {
    // bytes32-style symbol
    const bytes = h.match(/.{2}/g) ?? [];
    return bytes.map(b => parseInt(b, 16)).filter(c => c >= 32 && c < 127)
      .map(c => String.fromCharCode(c)).join('').trim();
  }
  const len = parseInt(h.slice(64, 128), 16);
  const data = h.slice(128, 128 + len * 2);
  const bytes = data.match(/.{2}/g) ?? [];
  return bytes.map(b => String.fromCharCode(parseInt(b, 16))).join('').trim();
}

export async function fetchTokenMeta(
  chain: 'ETH' | 'BNB',
  contract: string,
): Promise<{ symbol: string; decimals: number }> {
  const rpc = EVM_RPC[chain];
  const [symHex, decHex] = await Promise.all([
    evmRpc(rpc, 'eth_call', [{ to: contract, data: '0x95d89b41' }, 'latest']).catch(() => ''),
    evmRpc(rpc, 'eth_call', [{ to: contract, data: '0x313ce567' }, 'latest']).catch(() => '0x12'),
  ]);
  const symbol = symHex ? decodeAbiString(symHex) : '';
  const decimals = decHex && decHex !== '0x' ? parseInt(decHex, 16) : 18;
  if (!symbol) throw new Error('Not a readable token contract (no symbol)');
  if (!Number.isFinite(decimals) || decimals < 0 || decimals > 36) throw new Error('Invalid token decimals');
  return { symbol, decimals };
}

async function fetchNativeBalance(chain: ChainId, address: string): Promise<number> {
  switch (chain) {
    case 'BTC': {
      const j = await fetchJson(`https://blockstream.info/api/address/${address}`);
      const funded = j.chain_stats.funded_txo_sum + j.mempool_stats.funded_txo_sum;
      const spent  = j.chain_stats.spent_txo_sum + j.mempool_stats.spent_txo_sum;
      return (funded - spent) / 1e8;
    }
    case 'ETH':
    case 'BNB': {
      const hex = await evmRpc(EVM_RPC[chain], 'eth_getBalance', [address, 'latest']);
      return units(hexToBigInt(hex), 18);
    }
    case 'SOL': {
      const j = await fetchJson('https://api.mainnet-beta.solana.com', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getBalance', params: [address] }),
      });
      if (j.error) throw new Error(j.error.message);
      return (j.result?.value ?? 0) / 1e9;
    }
    case 'DOGE':
    case 'LTC': {
      const net = chain === 'DOGE' ? 'doge' : 'ltc';
      const j = await fetchJson(`https://api.blockcypher.com/v1/${net}/main/addrs/${address}/balance`);
      return (j.final_balance ?? j.balance ?? 0) / 1e8;
    }
  }
}

async function fetchTokenBalance(asset: TrackedAsset): Promise<number> {
  const rpc = EVM_RPC[asset.chain];
  if (!rpc || !asset.contract) throw new Error('Token not supported on this chain');
  const hex = await evmRpc(rpc, 'eth_call', [
    { to: asset.contract, data: '0x70a08231' + pad32(asset.address) },
    'latest',
  ]);
  return units(hexToBigInt(hex), asset.decimals ?? 18);
}

const STABLE = new Set(['USDT', 'USDC', 'DAI', 'BUSD', 'TUSD', 'FDUSD', 'USDD']);

export async function fetchUsdPrice(symbol: string): Promise<number> {
  const sym = symbol.toUpperCase();
  if (STABLE.has(sym)) return 1.0;
  try {
    const j = await fetchJson(`https://api.binance.com/api/v3/ticker/price?symbol=${sym}USDT`);
    const p = parseFloat(j.price);
    return Number.isFinite(p) ? p : 0;
  } catch {
    return 0;
  }
}

export async function fetchAssetBalance(asset: TrackedAsset): Promise<AssetBalance> {
  try {
    const [balance, price] = await Promise.all([
      asset.contract ? fetchTokenBalance(asset) : fetchNativeBalance(asset.chain, asset.address),
      fetchUsdPrice(asset.symbol),
    ]);
    return {
      id: asset.id,
      balance,
      price_usd: price,
      value_usd: balance * price,
    };
  } catch (e: unknown) {
    return { id: asset.id, balance: 0, price_usd: 0, value_usd: 0, error: (e as Error).message };
  }
}
