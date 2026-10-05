export interface WalletData {

  encryptedSeed: string;

  address: string;

  publicKeyHex: string;

  locked: boolean;

  approvedOrigins: string[];

  network: 'testnet' | 'mainnet';
}

export interface DecryptedWallet {
  seed: Uint8Array;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  address: string;
}

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

export type MessageType =
  | 'EGO_GENERATE_WALLET'
  | 'EGO_IMPORT_WALLET'
  | 'EGO_GET_ADDRESS'
  | 'EGO_GET_BALANCE'
  | 'EGO_SEND_TX'
  | 'EGO_DAPP_ACCOUNTS'
  | 'EGO_DAPP_CONNECT'
  | 'EGO_DAPP_SEND_TX'
  | 'EGO_DAPP_CALL_CONTRACT'
  | 'EGO_DAPP_SIGN'
  | 'EGO_APPROVE_REQUEST'
  | 'EGO_REJECT_REQUEST'
  | 'EGO_LIST_SITES'
  | 'EGO_DISCONNECT_SITE'
  | 'EGO_LOCK'
  | 'EGO_UNLOCK'
  | 'EGO_GET_STATE'
  | 'EGO_SET_NETWORK'
  | 'EGO_GET_MNEMONIC'
  | 'EGO_GET_HEALTH'
  | 'EGO_GET_BLOCKS'
  | 'EGO_GET_TXS'
  | 'EGO_HAS_WALLET'
  | 'EGO_GET_ASSETS'
  | 'EGO_ADD_ASSET'
  | 'EGO_REMOVE_ASSET'
  | 'EGO_REFRESH_ASSETS'
  | 'EGO_GET_CHAIN_ADDRESSES'
  | 'EGO_SEND_EXTERNAL'
  | 'EGO_SHIELDED_STATUS'
  | 'EGO_SHIELD_DEPOSIT'
  | 'EGO_SHIELD_WITHDRAW'
  | 'EGO_SHIELD_CANCEL_DEPOSIT'
  | 'EGO_SHIELD_CANCEL_WITHDRAWAL'
  | 'EGO_SHIELD_FORGET'
  | 'EGO_SHIELD_FORGET_SPENT'
  | 'EGO_SHIELD_SCAN';

export const DAPP_MESSAGES: ReadonlySet<MessageType> = new Set<MessageType>([
  'EGO_DAPP_ACCOUNTS',
  'EGO_DAPP_CONNECT',
  'EGO_DAPP_SEND_TX',
  'EGO_DAPP_CALL_CONTRACT',
  'EGO_DAPP_SIGN',
]);

export interface ExtMessage {
  type: MessageType;
  payload?: Record<string, unknown>;
}

export interface ExtResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

export type DappRequestKind = 'connect' | 'send' | 'call' | 'sign';

export interface PendingRequest {
  requestId: string;
  origin: string;
  kind: DappRequestKind;
  to?: string;
  amount_egoc?: number;
  memo?: string;
  contractAddr?: string;
  entrypoint?: string;
  callArgs?: string;
  message?: string;
  messageText?: string;
}

export interface SendTxParams {
  to: string;
  amount_egoc: number;
  memo?: string;
}

export interface TrackedAsset {
  id: string;
  chain: 'BTC' | 'ETH' | 'BNB' | 'POL' | 'SOL' | 'XRP' | 'DOGE' | 'LTC';
  symbol: string;
  name: string;
  address: string;
  contract?: string;
  decimals?: number;
}

export interface AssetBalance {
  id: string;
  balance: number;
  price_usd: number;
  value_usd: number;
  error?: string;
}

export const NETWORKS = {
  testnet: {
    name: 'Ego Testnet',
    chainId: '0x1',
    rpcUrl: 'http://127.0.0.1:47395',
  },
  mainnet: {
    name: 'Ego Mainnet',
    chainId: '0x1',
    rpcUrl: 'http://127.0.0.1:47395',
  },
} as const;
