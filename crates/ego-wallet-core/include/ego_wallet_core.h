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

void ego_wallet_string_free(char *s);

#endif
