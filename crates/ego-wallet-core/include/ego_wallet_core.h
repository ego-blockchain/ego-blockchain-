#ifndef EGO_WALLET_CORE_H
#define EGO_WALLET_CORE_H

#include <stddef.h>
#include <stdint.h>

/* Wallet keys and addresses shared by Ego Desktop and the iPhone wallet.
   Every function returns a JSON string to free with ego_wallet_string_free;
   on failure it is {"error": "..."}. */

/* The addresses of every built-in chain for a 32-byte Ego seed:
   [{"chain", "symbol", "address", "address_type", "explorer_prefix"}, ...] */
char *ego_wallet_addresses(const uint8_t *seed, size_t seed_len);

/* Signs an Ethereum or BNB Chain transfer as Ego Desktop would. request is JSON:
   {"chain", "nonce", "gas_price", "to", "amount", "decimals", "contract"?}
   where gas_price is the node's price in wei (20% is added) and amount is what
   the person typed. Returns {"raw", "hash", "from", "gas_price", "gas_limit",
   "fee", "amount_units"}. Nothing is sent. */
char *ego_wallet_sign_evm(const uint8_t *seed, size_t seed_len, const char *request);

/* Signs a Bitcoin or Litecoin transfer from the wallet's P2WPKH address. request
   is JSON: {"chain": "BTC"|"LTC", "to", "amount", "fee_rate" (sat/vB),
   "utxos": [{"txid", "vout", "value"}]}. Returns {"raw", "hash", "from", "fee",
   "change", "inputs", "amount_units"}. Nothing is sent. */
char *ego_wallet_sign_utxo(const uint8_t *seed, size_t seed_len, const char *request);

/* Signs a Solana, XRP, Tron or Cardano transfer. request is JSON with "chain",
   "to", "amount" and what that chain needs: SOL {"recent_blockhash"}; XRP
   {"sequence", "last_ledger", "destination_tag"?}; TRX {"block_number",
   "block_id", "block_time", "now_ms"}; ADA {"utxos": [{"tx_hash", "tx_index",
   "value"}], "ttl"}. Returns {"raw", "hash", "from", "fee", "change",
   "amount_units"}. Nothing is sent. Dogecoin goes through ego_wallet_sign_utxo. */
char *ego_wallet_sign_transfer(const uint8_t *seed, size_t seed_len, const char *request);

/* Writes a pre-sale IOU file exactly as Ego Desktop does. request is JSON:
   {"kind": "crypto"|"stripe", "mainnet_address", "testnet_address", "password",
   "now", and for crypto "pay_symbol", "pay_amount", "pay_usd_price",
   "presale_price", for stripe "session_id", "egoc_amount", "usd_amount"}.
   Returns the IOU file's JSON. */
char *ego_wallet_presale_iou(const char *request);

/* The allocation record inside an IOU file, given its password. */
char *ego_wallet_presale_open(const char *iou, const char *password);

/* Shielded EGOC as in Ego Desktop. kind is "notes", "values", "deposit" or
   "unshield"; see ego_wallet_shielded in src/ffi.rs for each request and
   answer. Proving a withdrawal takes a second or more. Nothing is sent. */
char *ego_wallet_shielded(const char *kind, const uint8_t *seed, size_t seed_len, const char *request);

void ego_wallet_string_free(char *s);

#endif
