// ── Wallet State ──────────────────────────────────────────────────────────────

export interface WalletData {
  /** Encrypted seed: base64(iv(12) || ciphertext) */
  encryptedSeed: string;
  /** hex-encoded 20-byte address with 0x prefix */
  address: string;
  /** hex-encoded Ed25519 public key */
  publicKeyHex: string;
  /** Whether the wallet is currently locked */
  locked: boolean;
  /** Approved dApp origins */
  approvedOrigins: string[];
  /** Selected network */
  network: 'testnet' | 'mainnet';
}

export interface DecryptedWallet {
  seed: Uint8Array;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  address: string;
}

// ── RPC / Balance ─────────────────────────────────────────────────────────────

export interface BalanceResponse {
  address: string;
  balance_uegoc: number;
  balance_egoc: number;
}

export interface HealthResponse {
  status: string;
  block_height: number;
  peer_id: string;
  uptime_secs: number;
}

export interface BlockSummary {
  height: number;
  hash: string;
  tx_count: number;
  timestamp: number;
}

export interface TxRecord {
  hash: string;
  from: string;
  to?: string;
  amount_egoc?: number;
  nonce?: number;
  timestamp?: number;
  type?: string;
}

export interface SubmitTxResponse {
  tx_hash: string;
}

export interface FaucetResponse {
  success: boolean;
  to: string;
  amount_egoc: number;
  amount_uegoc: number;
  tx_hash: string;
}

// ── Message Protocol (popup ↔ background) ────────────────────────────────────

export type MessageType =
  | 'EGO_GENERATE_WALLET'
  | 'EGO_IMPORT_WALLET'
  | 'EGO_GET_ADDRESS'
  | 'EGO_GET_BALANCE'
  | 'EGO_SEND_TX'
  | 'EGO_SIGN_MESSAGE'
  | 'EGO_CONNECT_DAPP'
  | 'EGO_GET_ACCOUNTS'
  | 'EGO_APPROVE_CONNECTION'
  | 'EGO_REJECT_CONNECTION'
  | 'EGO_LOCK'
  | 'EGO_UNLOCK'
  | 'EGO_GET_STATE'
  | 'EGO_SET_NETWORK'
  | 'EGO_GET_MNEMONIC'
  | 'EGO_GET_HEALTH'
  | 'EGO_GET_BLOCKS'
  | 'EGO_GET_TXS'
  | 'EGO_FAUCET'
  | 'EGO_HAS_WALLET';

export interface ExtMessage {
  type: MessageType;
  payload?: Record<string, unknown>;
}

export interface ExtResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

// ── dApp Connection ───────────────────────────────────────────────────────────

export interface PendingConnection {
  origin: string;
  favicon?: string;
  title?: string;
  requestId: string;
}

// ── Transaction ───────────────────────────────────────────────────────────────

export interface SendTxParams {
  to: string;
  amount_egoc: number;
  memo?: string;
}

// ── Networks ──────────────────────────────────────────────────────────────────

export const NETWORKS = {
  testnet: {
    name: 'Ego Testnet',
    chainId: '0x1',
    rpcUrl: 'http://127.0.0.1:8545',
  },
  mainnet: {
    name: 'Ego Mainnet',
    chainId: '0x1',
    rpcUrl: 'http://127.0.0.1:8545',
  },
} as const;
