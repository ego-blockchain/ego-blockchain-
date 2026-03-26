import * as SecureStore from 'expo-secure-store';

const KEY_WALLET   = 'ego_wallet_v1';
const KEY_SETTINGS = 'ego_settings_v1';
const KEY_TXS      = 'ego_txs_v1';

export interface StoredWallet {
  address:      string;
  publicKeyHex: string;
  seedHex:      string;
  createdAt:    number;
  network:      'testnet' | 'mainnet';
}

export interface StoredSettings {
  rpcUrl:       string;
  network:      'testnet' | 'mainnet';
  pinEnabled:   boolean;
  pinHash:      string;
  biometrics:   boolean;
  currency:     'EGOC' | 'USD';
}

export interface StoredTransaction {
  hash:      string;
  from:      string;
  to:        string;
  value:     string;
  status:    'confirmed' | 'pending' | 'failed';
  timestamp: number;
  note?:     string;
}

export async function saveWallet(wallet: StoredWallet): Promise<void> {
  await SecureStore.setItemAsync(KEY_WALLET, JSON.stringify(wallet));
}

export async function loadWallet(): Promise<StoredWallet | null> {
  const raw = await SecureStore.getItemAsync(KEY_WALLET);
  if (!raw) return null;
  try { return JSON.parse(raw) as StoredWallet; }
  catch { return null; }
}

export async function deleteWallet(): Promise<void> {
  await SecureStore.deleteItemAsync(KEY_WALLET);
}

const DEFAULT_SETTINGS: StoredSettings = {
  rpcUrl:     'http://127.0.0.1:8545',
  network:    'testnet',
  pinEnabled: false,
  pinHash:    '',
  biometrics: false,
  currency:   'EGOC',
};

export async function loadSettings(): Promise<StoredSettings> {
  const raw = await SecureStore.getItemAsync(KEY_SETTINGS);
  if (!raw) return { ...DEFAULT_SETTINGS };
  try { return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) }; }
  catch { return { ...DEFAULT_SETTINGS }; }
}

export async function saveSettings(settings: Partial<StoredSettings>): Promise<void> {
  const current = await loadSettings();
  await SecureStore.setItemAsync(KEY_SETTINGS, JSON.stringify({ ...current, ...settings }));
}

export async function loadLocalTransactions(): Promise<StoredTransaction[]> {
  const raw = await SecureStore.getItemAsync(KEY_TXS);
  if (!raw) return [];
  try { return JSON.parse(raw) as StoredTransaction[]; }
  catch { return []; }
}

export async function appendTransaction(tx: StoredTransaction): Promise<void> {
  const txs = await loadLocalTransactions();

  const updated = [tx, ...txs].slice(0, 200);
  await SecureStore.setItemAsync(KEY_TXS, JSON.stringify(updated));
}

export async function updateTransactionStatus(
  hash: string,
  status: StoredTransaction['status']
): Promise<void> {
  const txs = await loadLocalTransactions();
  const idx  = txs.findIndex(t => t.hash === hash);
  if (idx >= 0) {
    txs[idx]!.status = status;
    await SecureStore.setItemAsync(KEY_TXS, JSON.stringify(txs));
  }
}
