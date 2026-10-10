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

void ego_wallet_string_free(char *s);

#endif
