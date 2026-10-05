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
  buildSignedEgoTx,
  buildSignedContractCallTx,
} from '../shared/crypto';
import {
  getAddressHistory,
  getBalance,
  getBlocks,
  getHealth,
  getNonceInfo,
  submitTx,
  DEFAULT_RPC_URL,
} from '../shared/rpc';
import type {
  ExtMessage,
  ExtResponse,
  MessageType,
  PendingRequest,
  SendTxParams,
  TrackedAsset,
  AssetBalance,
  WalletData,
} from '../shared/types';
import { DAPP_MESSAGES, NETWORKS } from '../shared/types';
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
import {
  cancelDeposit,
  cancelWithdrawal,
  forgetNote,
  forgetSpent,
  scanForNotes,
  shieldDeposit,
  shieldWithdraw,
  shieldedStatus,
  type ShieldedContext,
} from './shieldedService';

let unlockedSeed: Uint8Array | null = null;

const APPROVAL_TIMEOUT_MS = 5 * 60_000;
const MAX_PENDING = 20;
const MAX_PENDING_PER_SITE = 3;
const MAX_SIGN_BYTES = 16 * 1024;
const MAX_CALL_ARGS_HEX = 128 * 1024;
const EGO_ADDRESS = /^egot?1[02-9ac-hj-np-z]{20,90}$/;

interface Pending {
  info: PendingRequest;
  settle: (result: ExtResponse) => void;
  timer: ReturnType<typeof setTimeout>;
}

const pendingRequests = new Map<string, Pending>();
let approvalWindowId: number | null = null;

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
  pendingRequest?: PendingRequest;
  pendingCount: number;
}>> {
  const walletData = await loadWalletData();
  const pending = [...pendingRequests.values()][0];

  if (!walletData) {
    return { success: true, data: { hasWallet: false, locked: true, pendingCount: 0 } };
  }

  return {
    success: true,
    data: {
      hasWallet: true,
      locked: !unlockedSeed,
      address: walletData.address,
      publicKeyHex: walletData.publicKeyHex,
      network: walletData.network,
      pendingRequest: pending?.info,
      pendingCount: pendingRequests.size,
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

  try {
    const rpcUrl = getRpcUrl(walletData.network);
    // Nonce and fee come from the chain, never a local counter — this keeps
    // the extension in sync even when the same wallet is used in Ego Desktop.
    const info = await getNonceInfo(walletData.address, rpcUrl);

    const tx = buildSignedEgoTx(
      unlockedSeed,
      walletData.address,
      params.to,
      Math.round(params.amount_egoc * 1_000_000),
      info.next,
      info.fee_uegoc,
      params.memo ?? '',
    );

    const result = await submitTx(tx, rpcUrl);
    return { success: true, data: { tx_hash: result.tx_hash ?? tx.hash } };
  } catch (e: unknown) {
    return { success: false, error: (e as Error).message };
  }
}

async function callContract(
  contractAddr: string,
  entrypoint: string,
  callArgs: string,
): Promise<ExtResponse<{ tx_hash: string }>> {
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };
  if (!contractAddr || !entrypoint) {
    return { success: false, error: 'A contract call needs a contract address and an entrypoint' };
  }
  if (callArgs && !/^[0-9a-fA-F]*$/.test(callArgs)) {
    return { success: false, error: 'callArgs must be hex' };
  }

  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet' };

  try {
    const rpcUrl = getRpcUrl(walletData.network);
    // Same rule as a transfer: the nonce comes from the chain, never a local
    // counter, so the same wallet can be used here and in Ego Desktop at once.
    const info = await getNonceInfo(walletData.address, rpcUrl);

    const tx = buildSignedContractCallTx(
      unlockedSeed,
      walletData.address,
      contractAddr,
      entrypoint,
      (callArgs ?? '').toLowerCase(),
      info.next,
      info.fee_uegoc,
    );

    const result = await submitTx(tx, rpcUrl);
    return { success: true, data: { tx_hash: result.tx_hash ?? tx.hash } };
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

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/g) ?? [], b => parseInt(b, 16));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function messageBytes(raw: unknown): Uint8Array | null {
  if (typeof raw !== 'string') return null;
  if (/^0x([0-9a-fA-F]{2})*$/.test(raw)) return hexToBytes(raw.slice(2));
  return new TextEncoder().encode(raw);
}

function readableText(bytes: Uint8Array): string | undefined {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text) ? undefined : text;
  } catch {
    return undefined;
  }
}

async function handleSignMessage(
  messageHex: string,
): Promise<ExtResponse<{ signature: string }>> {
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };
  if (!/^([0-9a-f]{2})+$/.test(messageHex)) return { success: false, error: 'Nothing to sign' };
  const signature = signMessage(hexToBytes(messageHex), unlockedSeed);
  return { success: true, data: { signature } };
}

function siteOrigin(sender: chrome.runtime.MessageSender): string | null {
  const raw = sender.origin ?? sender.url;
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : null;
  } catch {
    return null;
  }
}

async function isConnected(origin: string): Promise<boolean> {
  const walletData = await loadWalletData();
  return !!walletData && walletData.approvedOrigins.includes(origin);
}

async function openApprovalWindow(): Promise<void> {
  if (approvalWindowId !== null) {
    try {
      await chrome.windows.update(approvalWindowId, { focused: true });
      return;
    } catch {
      approvalWindowId = null;
    }
  }
  const win = await chrome.windows.create({
    url: chrome.runtime.getURL('popup/index.html?approval=1'),
    type: 'popup',
    width: 376,
    height: 640,
    focused: true,
  });
  approvalWindowId = win?.id ?? null;
}

function finish(requestId: string, result: ExtResponse): void {
  const pending = pendingRequests.get(requestId);
  if (!pending) return;
  pendingRequests.delete(requestId);
  clearTimeout(pending.timer);
  pending.settle(result);
}

function askUser(request: Omit<PendingRequest, 'requestId'>): Promise<ExtResponse> {
  if (pendingRequests.size >= MAX_PENDING) {
    return Promise.resolve({ success: false, error: 'Too many requests are already waiting for approval.' });
  }
  const fromSite = [...pendingRequests.values()].filter(p => p.info.origin === request.origin).length;
  if (fromSite >= MAX_PENDING_PER_SITE) {
    return Promise.resolve({ success: false, error: 'This site already has requests waiting for approval.' });
  }
  const requestId = crypto.randomUUID();
  return new Promise(resolve => {
    const timer = setTimeout(
      () => finish(requestId, { success: false, error: 'The request was not approved in time.' }),
      APPROVAL_TIMEOUT_MS,
    );
    pendingRequests.set(requestId, { info: { ...request, requestId }, settle: resolve, timer });
    openApprovalWindow().catch(() => undefined);
  });
}

async function perform(request: PendingRequest): Promise<ExtResponse> {
  if (request.kind === 'connect') {
    const walletData = await loadWalletData();
    if (!walletData) return { success: false, error: 'No wallet' };
    if (!walletData.approvedOrigins.includes(request.origin)) {
      walletData.approvedOrigins.push(request.origin);
      await saveWalletData(walletData);
    }
    return { success: true, data: { accounts: [walletData.address] } };
  }
  if (!(await isConnected(request.origin))) {
    return { success: false, error: 'This site was disconnected from Ego Wallet.' };
  }
  switch (request.kind) {
    case 'send':
      return sendTransaction({ to: request.to ?? '', amount_egoc: request.amount_egoc ?? 0, memo: request.memo });
    case 'call':
      return callContract(request.contractAddr ?? '', request.entrypoint ?? '', request.callArgs ?? '');
    case 'sign':
      return handleSignMessage(request.message ?? '');
  }
}

async function approveRequest(requestId: string): Promise<ExtResponse> {
  const pending = pendingRequests.get(requestId);
  if (!pending) return { success: false, error: 'This request is no longer waiting.' };
  if (!unlockedSeed) return { success: false, error: 'Unlock the wallet first.' };
  pendingRequests.delete(requestId);
  clearTimeout(pending.timer);
  const result = await perform(pending.info);
  pending.settle(result);
  return result;
}

function rejectRequest(requestId: string): ExtResponse {
  if (!pendingRequests.has(requestId)) return { success: false, error: 'This request is no longer waiting.' };
  finish(requestId, { success: false, error: 'The user rejected the request.' });
  return { success: true };
}

async function dappAccounts(origin: string): Promise<ExtResponse<{ accounts: string[] }>> {
  const walletData = await loadWalletData();
  const connected = !!walletData && !!unlockedSeed && walletData.approvedOrigins.includes(origin);
  return { success: true, data: { accounts: connected && walletData ? [walletData.address] : [] } };
}

async function dappConnect(origin: string): Promise<ExtResponse> {
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'Set up Ego Wallet first.' };
  if (unlockedSeed && walletData.approvedOrigins.includes(origin)) {
    return { success: true, data: { accounts: [walletData.address] } };
  }
  return askUser({ origin, kind: 'connect' });
}

async function dappRequest(
  origin: string,
  type: MessageType,
  payload: Record<string, unknown>,
): Promise<ExtResponse> {
  if (!(await loadWalletData())) return { success: false, error: 'Set up Ego Wallet first.' };
  if (!(await isConnected(origin))) {
    return { success: false, error: 'Connect this site to Ego Wallet first (eth_requestAccounts).' };
  }
  switch (type) {
    case 'EGO_DAPP_SEND_TX': {
      const to = String(payload.to ?? '').trim();
      const amount = Number(payload.amount_egoc);
      const memo = typeof payload.memo === 'string' ? payload.memo : '';
      if (!EGO_ADDRESS.test(to)) return { success: false, error: 'The recipient is not an Ego address.' };
      if (!Number.isFinite(amount) || Math.round(amount * 1_000_000) < 1 || amount * 1_000_000 > Number.MAX_SAFE_INTEGER) {
        return { success: false, error: 'The amount is not valid.' };
      }
      if (memo.length > 256) return { success: false, error: 'The memo is longer than 256 characters.' };
      return askUser({ origin, kind: 'send', to, amount_egoc: amount, memo });
    }
    case 'EGO_DAPP_CALL_CONTRACT': {
      const contractAddr = String(payload.contractAddr ?? '').trim();
      const entrypoint = String(payload.entrypoint ?? '').trim();
      const callArgs = String(payload.callArgs ?? '').replace(/^0x/, '').toLowerCase();
      if (!/^[0-9a-zA-Z]{8,128}$/.test(contractAddr)) return { success: false, error: 'The contract address is not valid.' };
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(entrypoint)) return { success: false, error: 'The entrypoint name is not valid.' };
      if (!/^([0-9a-f]{2})*$/.test(callArgs) || callArgs.length > MAX_CALL_ARGS_HEX) {
        return { success: false, error: 'callArgs must be hex.' };
      }
      return askUser({ origin, kind: 'call', contractAddr, entrypoint, callArgs });
    }
    case 'EGO_DAPP_SIGN': {
      const bytes = messageBytes(payload.message);
      if (!bytes || bytes.length === 0) return { success: false, error: 'Nothing to sign.' };
      if (bytes.length > MAX_SIGN_BYTES) return { success: false, error: 'The message is too long to sign.' };
      return askUser({ origin, kind: 'sign', message: bytesToHex(bytes), messageText: readableText(bytes) });
    }
    default:
      return { success: false, error: `Unsupported request: ${type}` };
  }
}

async function listSites(): Promise<ExtResponse<{ sites: string[] }>> {
  const walletData = await loadWalletData();
  return { success: true, data: { sites: walletData?.approvedOrigins ?? [] } };
}

async function disconnectSite(origin: string): Promise<ExtResponse> {
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet' };
  walletData.approvedOrigins = walletData.approvedOrigins.filter(o => o !== origin);
  await saveWalletData(walletData);
  for (const pending of [...pendingRequests.values()]) {
    if (pending.info.origin === origin) {
      finish(pending.info.requestId, { success: false, error: 'This site was disconnected from Ego Wallet.' });
    }
  }
  return { success: true };
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

async function shielded<T>(fn: (ctx: ShieldedContext) => Promise<T>): Promise<ExtResponse<T>> {
  if (!unlockedSeed) return { success: false, error: 'Wallet is locked' };
  const walletData = await loadWalletData();
  if (!walletData) return { success: false, error: 'No wallet' };
  try {
    const data = await fn({
      seed: unlockedSeed,
      address: walletData.address,
      rpcUrl: getRpcUrl(walletData.network),
    });
    return { success: true, data };
  } catch (e: unknown) {
    return { success: false, error: (e as Error).message ?? String(e) };
  }
}

function fromWalletPage(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id
    && (sender.url ?? '').startsWith(chrome.runtime.getURL(''));
}

function stringList(v: unknown): string[] | null {
  return Array.isArray(v) && v.every(x => typeof x === 'string') ? (v as string[]) : null;
}

chrome.runtime.onMessage.addListener(
  (message: ExtMessage, sender, sendResponse) => {
    const { type, payload = {} } = message;

    const handle = async (): Promise<ExtResponse> => {
      if (DAPP_MESSAGES.has(type)) {
        const origin = siteOrigin(sender);
        if (!origin || !sender.tab) return { success: false, error: 'Requests must come from a web page.' };
        if (type === 'EGO_DAPP_ACCOUNTS') return dappAccounts(origin);
        if (type === 'EGO_DAPP_CONNECT') return dappConnect(origin);
        return dappRequest(origin, type, payload);
      }
      if (!fromWalletPage(sender)) {
        return { success: false, error: 'Only the Ego Wallet window can do that.' };
      }
      switch (type) {
        case 'EGO_SHIELDED_STATUS':
          return shielded(ctx => shieldedStatus(ctx));

        case 'EGO_SHIELD_DEPOSIT': {
          const amount = Number(payload.amount_uegoc);
          if (!Number.isSafeInteger(amount) || amount <= 0) return { success: false, error: 'Enter an amount to shield' };
          return shielded(ctx => shieldDeposit(ctx, amount));
        }

        case 'EGO_SHIELD_WITHDRAW': {
          const commitments = stringList(payload.commitments);
          if (!commitments || typeof payload.recipient !== 'string') {
            return { success: false, error: 'Choose the notes to spend and a recipient' };
          }
          return shielded(ctx => shieldWithdraw(ctx, commitments, payload.recipient as string));
        }

        case 'EGO_SHIELD_CANCEL_DEPOSIT':
          return shielded(ctx => cancelDeposit(ctx, String(payload.commitment ?? '')));

        case 'EGO_SHIELD_CANCEL_WITHDRAWAL':
          return shielded(ctx => cancelWithdrawal(ctx, String(payload.spent_tx ?? '')));

        case 'EGO_SHIELD_FORGET':
          return shielded(ctx => forgetNote(ctx, String(payload.commitment ?? '')));

        case 'EGO_SHIELD_FORGET_SPENT':
          return shielded(ctx => forgetSpent(ctx));

        case 'EGO_SHIELD_SCAN':
          return shielded(ctx => scanForNotes(ctx));

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

        case 'EGO_GET_MNEMONIC':
          return getMnemonic(payload.password as string);

        case 'EGO_APPROVE_REQUEST':
          return approveRequest(String(payload.requestId ?? ''));

        case 'EGO_REJECT_REQUEST':
          return rejectRequest(String(payload.requestId ?? ''));

        case 'EGO_LIST_SITES':
          return listSites();

        case 'EGO_DISCONNECT_SITE':
          return disconnectSite(String(payload.origin ?? ''));

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
          if (!wd) return { success: false, error: 'No wallet' };
          const rpcUrl = getRpcUrl(wd.network);
          try {
            const txs = await getAddressHistory(wd.address, 50, rpcUrl);
            return {
              success: true,
              data: txs.map(t => ({
                hash: t.hash,
                from: t.from,
                to: t.to,
                amount_egoc: (t.amount ?? 0) / 1_000_000,
                timestamp: t.timestamp,
                type: t.tx_type ?? 'transfer',
                pending: t.block_height == null,
              })),
            };
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

chrome.windows.onRemoved.addListener(windowId => {
  if (windowId !== approvalWindowId) return;
  approvalWindowId = null;
  for (const pending of [...pendingRequests.values()]) {
    finish(pending.info.requestId, { success: false, error: 'The user rejected the request.' });
  }
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('[Ego Wallet] Extension installed.');
});

chrome.runtime.onStartup.addListener(() => {

  unlockedSeed = null;
});
