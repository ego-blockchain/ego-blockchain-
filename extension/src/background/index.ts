import {
  decryptSeed,
  encryptSeed,
  generateSeed,
  hexToSeed,
  mnemonicToSeed,
  publicKeyToAddress,
  seedToKeypair,
  seedToMnemonic,
  signMessage,
  signTransaction,
} from '../shared/crypto';
import {
  getBalance,
  getBlocks,
  getHealth,
  getTransactions,
  requestFaucet,
  submitTx,
  DEFAULT_RPC_URL,
} from '../shared/rpc';
import type {
  ExtMessage,
  ExtResponse,
  PendingConnection,
  SendTxParams,
  TrackedAsset,
  AssetBalance,
  WalletData,
} from '../shared/types';
import { NETWORKS } from '../shared/types';
import {
  CHAINS,
  fetchAssetBalance,
  fetchTokenMeta,
  validateAddress,
  type ChainId,
} from '../shared/assets';
import {
  deriveAddress,
  isSignableChain,
  sendBtc,
  sendEvm,
} from '../shared/signers';

let unlockedSeed: Uint8Array | null = null;

const pendingConnections: Map<string, {
  resolve: (approved: boolean) => void;
  info: PendingConnection;
}> = new Map();

async function loadWalletData(): Promise<WalletData | null> {
  return new Promise(resolve => {
    chrome.storage.local.get(['walletData'], result => {
      resolve((result.walletData as WalletData) ?? null);
    });
  });
}

async function saveWalletData(data: WalletData): Promise<void> {
  return new Promise(resolve => {
    chrome.storage.local.set({ walletData: data }, resolve);
  });
}

async function getNextNonce(): Promise<number> {
  return new Promise(resolve => {
    chrome.storage.local.get(['nonce'], result => {
      resolve(((result.nonce as number) ?? 0));
    });
  });
}

async function incrementNonce(): Promise<void> {
  const current = await getNextNonce();
  return new Promise(resolve => {
    chrome.storage.local.set({ nonce: current + 1 }, resolve);
  });
}

function getRpcUrl(network?: 'testnet' | 'mainnet'): string {
  if (!network) return DEFAULT_RPC_URL;
  return NETWORKS[network]?.rpcUrl ?? DEFAULT_RPC_URL;
}

async function generateWallet(password: string): Promise<ExtResponse<{ address: string; mnemonic: string[] }>> {
  const seed = generateSeed();
  const { publicKey } = seedToKeypair(seed);
  const address = publicKeyToAddress(publicKey);
  const mnemonic = await seedToMnemonic(seed);
  const encryptedSeed = await encryptSeed(seed, password);
  const publicKeyHex = Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('');

  const walletData: WalletData = {
    encryptedSeed,
    address,
    publicKeyHex,
    locked: false,
    approvedOrigins: [],
    network: 'testnet',
  };

  await saveWalletData(walletData);
  unlockedSeed = seed;

  return { success: true, data: { address, mnemonic } };
}

async function importWallet(
  input: string,
  password: string,
): Promise<ExtResponse<{ address: string }>> {
  const words = input.trim().split(/\s+/);
  let seed: Uint8Array | null = null;

  if (words.length === 24) {
    seed = mnemonicToSeed(words);
    if (!seed) return { success: false, error: 'Invalid recovery phrase — check every word (and their order)' };
  } else {
    seed = hexToSeed(input);
    if (!seed) {
      return { success: false, error: 'Provide your 24-word recovery phrase, or the 64-character hex seed (with or without 0x)' };
    }
  }

  const { publicKey } = seedToKeypair(seed);
  const address = publicKeyToAddress(publicKey);
  const encryptedSeed = await encryptSeed(seed, password);
  const publicKeyHex = Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('');

  const walletData: WalletData = {
    encryptedSeed,
    address,
    publicKeyHex,
    locked: false,
    approvedOrigins: [],
    network: 'testnet',
  };

  await saveWalletData(walletData);
  unlockedSeed = seed;

  return { success: true, data: { address } };
}

async function unlockWallet(password: string): Promise<ExtResponse<{ address: string }>> {
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet found' };

  const seed = await decryptSeed(walletData.encryptedSeed, password);
  if (!seed) return { success: false, error: 'Wrong password' };

  unlockedSeed = seed;
  walletData.locked = false;
  await saveWalletData(walletData);

  return { success: true, data: { address: walletData.address } };
}

async function lockWallet(): Promise<ExtResponse> {
  unlockedSeed = null;
  const walletData = await loadWalletData();
  if (walletData) {
    walletData.locked = true;
    await saveWalletData(walletData);
  }
  return { success: true };
}

async function getWalletState(): Promise<ExtResponse<{
  hasWallet: boolean;
  locked: boolean;
  address?: string;
  publicKeyHex?: string;
  network?: string;
  pendingConnection?: PendingConnection;
}>> {
  const walletData = await loadWalletData();
  const pending = [...pendingConnections.values()][0];

  if (!walletData) {
    return { success: true, data: { hasWallet: false, locked: true } };
  }

  return {
    success: true,
    data: {
      hasWallet: true,
      locked: !unlockedSeed,
      address: walletData.address,
      publicKeyHex: walletData.publicKeyHex,
      network: walletData.network,
      pendingConnection: pending?.info,
    },
  };
}

async function getMnemonic(password: string): Promise<ExtResponse<{ mnemonic: string[] }>> {
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet found' };

  const seed = await decryptSeed(walletData.encryptedSeed, password);
  if (!seed) return { success: false, error: 'Wrong password' };

  const mnemonic = await seedToMnemonic(seed);
  return { success: true, data: { mnemonic } };
}

async function sendTransaction(
  params: SendTxParams,
): Promise<ExtResponse<{ tx_hash: string }>> {
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };

  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet' };

  const nonce = await getNextNonce();
  const txPayload = {
    from: walletData.address,
    to: params.to,
    amount_uegoc: Math.round(params.amount_egoc * 1_000_000),
    nonce,
    memo: params.memo ?? '',
    timestamp: Date.now(),
  };

  const { tx, signature, public_key_hex } = signTransaction(txPayload, unlockedSeed);

  const txObj = {
    ...tx,
    signature,
    public_key_hex,
    type: 'Transfer',
  };

  try {
    const rpcUrl = getRpcUrl(walletData.network);
    const result = await submitTx(txObj, rpcUrl);
    await incrementNonce();
    return { success: true, data: { tx_hash: result.tx_hash } };
  } catch (e: unknown) {
    return { success: false, error: (e as Error).message };
  }
}

async function getWalletBalance(): Promise<ExtResponse<{ balance_egoc: number; balance_uegoc: number }>> {
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet' };

  try {
    const rpcUrl = getRpcUrl(walletData.network);
    const result = await getBalance(walletData.address, rpcUrl);
    return { success: true, data: { balance_egoc: result.balance_egoc, balance_uegoc: result.balance_uegoc } };
  } catch (e: unknown) {
    return { success: false, error: (e as Error).message };
  }
}

async function handleSignMessage(
  messageHex: string,
): Promise<ExtResponse<{ signature: string }>> {
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };

  const messageBytes = Uint8Array.from(
    messageHex.replace(/^0x/, '').match(/.{1,2}/g)!.map(b => parseInt(b, 16)),
  );
  const signature = signMessage(messageBytes, unlockedSeed);
  return { success: true, data: { signature } };
}

async function handleConnectDapp(info: PendingConnection): Promise<ExtResponse<{ approved: boolean }>> {
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet' };
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };

  return new Promise(resolve => {
    pendingConnections.set(info.requestId, {
      resolve: (approved: boolean) => {
        pendingConnections.delete(info.requestId);
        resolve({ success: true, data: { approved } });
      },
      info,
    });

    chrome.action.openPopup?.();
  });
}

async function approveConnection(requestId: string): Promise<ExtResponse> {
  const walletData = await loadWalletData();
  const pending = pendingConnections.get(requestId);
  if (!pending) return { success: false, error: 'No pending connection' };

  if (walletData && !walletData.approvedOrigins.includes(pending.info.origin)) {
    walletData.approvedOrigins.push(pending.info.origin);
    await saveWalletData(walletData);
  }

  pending.resolve(true);
  return { success: true };
}

async function rejectConnection(requestId: string): Promise<ExtResponse> {
  const pending = pendingConnections.get(requestId);
  if (!pending) return { success: false, error: 'No pending connection' };
  pending.resolve(false);
  return { success: true };
}

async function getAccounts(origin: string): Promise<ExtResponse<{ accounts: string[] }>> {
  const walletData = await loadWalletData();
  if (!walletData || !unlockedSeed) return { success: true, data: { accounts: [] } };
  if (!walletData.approvedOrigins.includes(origin)) return { success: true, data: { accounts: [] } };
  return { success: true, data: { accounts: [walletData.address] } };
}

async function setNetwork(network: 'testnet' | 'mainnet'): Promise<ExtResponse> {
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet' };
  walletData.network = network;
  await saveWalletData(walletData);
  return { success: true };
}

async function hasWallet(): Promise<ExtResponse<{ hasWallet: boolean }>> {
  const walletData = await loadWalletData();
  return { success: true, data: { hasWallet: walletData !== null } };
}

// ── Tracked assets (watch-only coins & tokens) ────────────────────────────────

async function loadAssets(): Promise<TrackedAsset[]> {
  return new Promise(resolve => {
    chrome.storage.local.get(['trackedAssets'], result => {
      resolve((result.trackedAssets as TrackedAsset[]) ?? []);
    });
  });
}

async function saveAssets(assets: TrackedAsset[]): Promise<void> {
  return new Promise(resolve => {
    chrome.storage.local.set({ trackedAssets: assets }, resolve);
  });
}

async function getAssets(): Promise<ExtResponse<{ assets: TrackedAsset[] }>> {
  return { success: true, data: { assets: await loadAssets() } };
}

async function addAsset(payload: {
  chain: ChainId;
  address: string;
  contract?: string;
}): Promise<ExtResponse<{ asset: TrackedAsset }>> {
  const chain = payload.chain;
  const chainInfo = CHAINS[chain];
  if (!chainInfo) return { success: false, error: `Unsupported chain: ${chain}` };

  const address = (payload.address ?? '').trim();
  if (!validateAddress(chain, address)) {
    return { success: false, error: `Invalid ${chainInfo.name} address` };
  }

  const contract = payload.contract?.trim();
  let symbol: string = chain;
  let name: string = chainInfo.name;
  let decimals: number | undefined;

  if (contract) {
    if (!chainInfo.tokens || (chain !== 'ETH' && chain !== 'BNB' && chain !== 'POL')) {
      return { success: false, error: `Tokens are not supported on ${chainInfo.name}` };
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(contract)) {
      return { success: false, error: 'Invalid token contract address' };
    }
    try {
      const meta = await fetchTokenMeta(chain, contract);
      symbol = meta.symbol;
      decimals = meta.decimals;
      const std = chain === 'ETH' ? 'ERC-20' : chain === 'BNB' ? 'BEP-20' : 'Polygon ERC-20';
      name = `${meta.symbol} (${std})`;
    } catch (e: unknown) {
      return { success: false, error: `Token lookup failed: ${(e as Error).message}` };
    }
  }

  const assets = await loadAssets();
  const duplicate = assets.find(a =>
    a.chain === chain &&
    a.address.toLowerCase() === address.toLowerCase() &&
    (a.contract ?? '').toLowerCase() === (contract ?? '').toLowerCase(),
  );
  if (duplicate) return { success: false, error: 'This asset is already in your list' };

  const asset: TrackedAsset = {
    id: crypto.randomUUID(),
    chain,
    symbol,
    name,
    address,
    contract: contract || undefined,
    decimals,
  };
  assets.push(asset);
  await saveAssets(assets);
  return { success: true, data: { asset } };
}

async function removeAsset(id: string): Promise<ExtResponse> {
  const assets = await loadAssets();
  const next = assets.filter(a => a.id !== id);
  if (next.length === assets.length) return { success: false, error: 'Asset not found' };
  await saveAssets(next);
  return { success: true };
}

async function refreshAssets(): Promise<ExtResponse<{ balances: AssetBalance[] }>> {
  const assets = await loadAssets();
  const balances = await Promise.all(assets.map(a => fetchAssetBalance(a)));
  return { success: true, data: { balances } };
}

// ── External-chain signing (BTC / ETH / BNB derived from the wallet seed) ─────

async function getChainAddresses(): Promise<ExtResponse<{ addresses: Record<string, string> }>> {
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };
  const addresses: Record<string, string> = {};
  for (const chain of ['BTC', 'ETH', 'BNB', 'POL', 'SOL', 'XRP', 'DOGE', 'LTC'] as const) {
    try {
      addresses[chain] = deriveAddress(unlockedSeed, chain);
    } catch {
      // Skip any chain that fails to derive rather than blocking all "use my address" buttons.
    }
  }
  return { success: true, data: { addresses } };
}

async function sendExternal(payload: {
  chain: string;
  to: string;
  amount: string;
  contract?: string;
  decimals?: number;
}): Promise<ExtResponse<{ txid: string; explorer_url: string }>> {
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };
  const { chain, to, amount, contract, decimals } = payload;
  if (!isSignableChain(chain)) {
    return { success: false, error: `Sending on ${chain} is not supported yet (watch-only)` };
  }
  if (!to?.trim()) return { success: false, error: 'Recipient address required' };
  if (!amount?.trim()) return { success: false, error: 'Amount required' };

  try {
    if (chain === 'BTC') {
      if (contract) return { success: false, error: 'Tokens are not supported on Bitcoin' };
      const result = await sendBtc(unlockedSeed, to.trim(), amount.trim());
      return { success: true, data: result };
    }
    const token = contract ? { contract, decimals: decimals ?? 18 } : undefined;
    const result = await sendEvm(unlockedSeed, chain, to.trim(), amount.trim(), token);
    return { success: true, data: result };
  } catch (e: unknown) {
    return { success: false, error: (e as Error).message };
  }
}

chrome.runtime.onMessage.addListener(
  (message: ExtMessage, sender, sendResponse) => {
    const { type, payload = {} } = message;

    const handle = async (): Promise<ExtResponse> => {
      switch (type) {
        case 'EGO_HAS_WALLET':
          return hasWallet();

        case 'EGO_GENERATE_WALLET':
          return generateWallet(payload.password as string);

        case 'EGO_IMPORT_WALLET':
          return importWallet(payload.input as string, payload.password as string);

        case 'EGO_UNLOCK':
          return unlockWallet(payload.password as string);

        case 'EGO_LOCK':
          return lockWallet();

        case 'EGO_GET_STATE':
          return getWalletState();

        case 'EGO_GET_ADDRESS': {
          const wd = await loadWalletData();
          if (!wd) return { success: false, error: 'No wallet' };
          return { success: true, data: { address: wd.address } };
        }

        case 'EGO_GET_BALANCE':
          return getWalletBalance();

        case 'EGO_SEND_TX':
          return sendTransaction(payload as unknown as SendTxParams);

        case 'EGO_SIGN_MESSAGE':
          return handleSignMessage(payload.message as string);

        case 'EGO_GET_MNEMONIC':
          return getMnemonic(payload.password as string);

        case 'EGO_CONNECT_DAPP':
          return handleConnectDapp(payload as unknown as PendingConnection);

        case 'EGO_APPROVE_CONNECTION':
          return approveConnection(payload.requestId as string);

        case 'EGO_REJECT_CONNECTION':
          return rejectConnection(payload.requestId as string);

        case 'EGO_GET_ACCOUNTS':
          return getAccounts((sender.origin ?? sender.url ?? '') as string);

        case 'EGO_SET_NETWORK':
          return setNetwork(payload.network as 'testnet' | 'mainnet');

        case 'EGO_GET_HEALTH': {
          const wd = await loadWalletData();
          const rpcUrl = getRpcUrl(wd?.network);
          try {
            const h = await getHealth(rpcUrl);
            return { success: true, data: h };
          } catch (e: unknown) {
            return { success: false, error: (e as Error).message };
          }
        }

        case 'EGO_GET_BLOCKS': {
          const wd = await loadWalletData();
          const rpcUrl = getRpcUrl(wd?.network);
          try {
            const blocks = await getBlocks(rpcUrl);
            return { success: true, data: blocks };
          } catch (e: unknown) {
            return { success: false, error: (e as Error).message };
          }
        }

        case 'EGO_GET_TXS': {
          const wd = await loadWalletData();
          const rpcUrl = getRpcUrl(wd?.network);
          try {
            const txs = await getTransactions(rpcUrl);
            return { success: true, data: txs };
          } catch (e: unknown) {
            return { success: false, error: (e as Error).message };
          }
        }

        case 'EGO_FAUCET': {
          const wd = await loadWalletData();
          if (!wd) return { success: false, error: 'No wallet' };
          const rpcUrl = getRpcUrl(wd.network);
          try {
            const result = await requestFaucet(wd.address, rpcUrl);
            return { success: true, data: result };
          } catch (e: unknown) {
            return { success: false, error: (e as Error).message };
          }
        }

        case 'EGO_GET_ASSETS':
          return getAssets();

        case 'EGO_ADD_ASSET':
          return addAsset(payload as { chain: ChainId; address: string; contract?: string });

        case 'EGO_REMOVE_ASSET':
          return removeAsset(payload.id as string);

        case 'EGO_REFRESH_ASSETS':
          return refreshAssets();

        case 'EGO_GET_CHAIN_ADDRESSES':
          return getChainAddresses();

        case 'EGO_SEND_EXTERNAL':
          return sendExternal(payload as {
            chain: string; to: string; amount: string; contract?: string; decimals?: number;
          });

        default:
          return { success: false, error: `Unknown message type: ${type}` };
      }
    };

    handle().then(sendResponse).catch(err => {
      sendResponse({ success: false, error: String(err) });
    });

    return true;
  },
);

chrome.runtime.onInstalled.addListener(() => {
  console.log('[Ego Wallet] Extension installed.');
});

chrome.runtime.onStartup.addListener(() => {

  unlockedSeed = null;
});
