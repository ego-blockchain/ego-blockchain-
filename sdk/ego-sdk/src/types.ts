export type Address = string;

export type Balance = bigint;

export interface BlockSummary {
  height:    number;
  hash:      string;
  tx_count:  number;
  timestamp: number;
}

export interface BalanceResult {
  address:       Address;
  balance_uegoc: string;
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

export interface TxEnvelope {
  from:      Address;
  to:        Address;
  amount:    string;
  nonce:     number;
  payload?:  unknown;
}

export interface EgoClientOptions {

  rpcUrl?: string;

  timeout?: number;
}

export interface DeployedContract {
  address:    string;
  name:       string;
  deployer:   string;
  deployedAt: number;
  codeHash:   string;
}

export interface ContractActivity {
  seq:            number;
  height:         number;
  timestamp:      number;
  tx_hash:        string;
  from:           string;
  kind:           "deploy" | "call";
  entrypoint:     string;
  args_hex:       string;
  args_truncated: boolean;
  ok:             boolean;
  error:          string | null;
  ru_used:        number;
  events:         { topic: string; payload_hex: string }[];
}

export interface ContractQueryResult {
  success:   boolean;
  returnHex: string;
  error:     string | null;
  ruUsed:    number;
}
