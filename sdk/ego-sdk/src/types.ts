/** 20-byte hex address, e.g. "0xabc...def" */
export type Address = string;

/** Raw uEGOC amount (1 EGOC = 1_000_000 uEGOC) */
export type Balance = bigint;

export interface BlockSummary {
  height:    number;
  hash:      string;
  tx_count:  number;
  timestamp: number;
}

export interface BalanceResult {
  address:       Address;
  balance_uegoc: string;   // bigint as string (JSON)
  balance_egoc:  string;
}

export interface TxSubmitResult {
  tx_hash: string;
}

export interface PendingTx {
  hash:  string;
  nonce: number;
  from:  Address;
}

export interface NodeStats {
  uptime_seconds:               number;
  messages_sent:                number;
  messages_received:            number;
  bytes_sent:                   number;
  bytes_received:               number;
  peer_connections_established: number;
  pending_tx_count:             number;
  shard_count:                  number;
}

export interface HealthResult {
  status:       string;
  block_height: number;
  peer_id:      string;
}

/** Minimal transaction envelope for submission */
export interface TxEnvelope {
  from:      Address;
  to:        Address;
  amount:    string;    // uEGOC as decimal string
  nonce:     number;
  payload?:  unknown;
}

export interface EgoClientOptions {
  /** Base URL of the ego-node RPC, default http://localhost:8545 */
  rpcUrl?: string;
  /** Request timeout in ms, default 10_000 */
  timeout?: number;
}
