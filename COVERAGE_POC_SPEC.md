# Ego Proof-of-Coverage — Beacon & Witness Protocol

Status: Phase 1 implemented (internet transport). Phases 2–3 specified.

## Why

The original Coverage tab measured internet reachability: the node pinged known peers and logged an event with the count of peers that answered. Nothing proved those interactions to anyone else — a node could not distinguish "I really witnessed peer X" from a self-asserted number. This spec replaces the self-asserted count with **signed witness receipts**: every coverage event is backed by cryptographic receipts from other nodes that actually heard our beacon.

The same message pair is transport-agnostic by design. Phase 1 runs it over the existing libp2p gossip network. Phase 2 runs the identical messages over radio on dedicated Ego coverage devices, where "heard" means an RF signal, not a TCP packet.

## Messages (`ego-poc-v1` gossip topic)

### PocBeacon

Broadcast by every online node once per epoch (240 s).

| field | type | meaning |
|---|---|---|
| beacon_id | hex string | blake3(address : epoch : random_nonce) |
| address | string | beaconer wallet address (egot1…) |
| machine_id | string | hardware id of the beaconer |
| cell | string | coverage cell derived from coarse geolocation ("" if unknown) |
| epoch | u64 | unix_timestamp / 240 |
| timestamp | i64 | unix seconds |
| transport | string | "internet" (phase 1) / "lora" (phase 2) |
| signature | hex | Ed25519 over the beacon signing bytes |

Signing bytes: `"ego/poc-beacon/v1:" beacon_id ':' address ':' machine_id ':' cell ':' epoch_u64le ':' timestamp_i64le ':' transport`

### PocWitnessReceipt

Sent by any node that hears a valid beacon.

| field | type | meaning |
|---|---|---|
| beacon_id | hex string | the beacon being witnessed |
| beaconer | string | address of the beacon sender |
| witness | string | address of the witnessing node |
| witness_machine_id | string | hardware id of the witness |
| witness_cell | string | witness's own coverage cell |
| latency_ms | u32 | observed delay (coarse in phase 1) |
| rssi_dbm | i32 | 0 in phase 1; real received signal strength in phase 2 |
| timestamp | i64 | unix seconds |
| signature | hex | Ed25519 over the witness signing bytes |

Signing bytes: `"ego/poc-witness/v1:" beacon_id ':' beaconer ':' witness ':' witness_machine_id ':' witness_cell ':' latency_ms_u32le ':' rssi_dbm_i32le ':' timestamp_i64le`

## Validation rules

Witness side (before signing a receipt):
- beacon timestamp within ±120 s of local clock; epoch consistent with timestamp
- beaconer address ≠ own address AND beaconer machine_id ≠ own machine_id (no self-witnessing, including across wallets on one machine; `EGO_POC_SAME_MACHINE=1` relaxes this for single-PC testnets only)
- beacon signature verifies against the beaconer's Ed25519 key learned from its signed PeerAnnounce; unverifiable → ignore
- at most one receipt per beaconer per epoch (rate limit)

Beaconer side (before counting a receipt):
- receipt references the currently active beacon_id
- witness ≠ self, witness machine_id ≠ own machine_id, timestamp fresh
- receipt signature verifies against the witness's known Ed25519 key
- deduplicated by witness address, capped at 22 counted witnesses (reward cap)

## Event & reward flow

Every 240 s an online node broadcasts a beacon; 60 s later it finalizes: the collected receipts become the PoC event's `peers` count and `witnesses` list (stored in `poc_events.json`, visible in the Coverage tab). Reward per event: `11,111 + 1,500 × witnesses` µEGOC, capped at 44,444. Payout continues to flow through the existing earnings pipeline.

Migration fallback: if a beacon collects zero receipts (peers on pre-witness builds), the event falls back to the legacy reachability count with an empty `witnesses` list. This fallback is removed in phase 2 — no receipts, no peer bonus.

## Phase 2 — radio (specified, not implemented)

Identical messages carried over LoRa-class radio on dedicated Ego coverage devices:
- beacons transmitted at VRF-derived pseudo-random offsets inside the epoch (unpredictable, so a cheater cannot power the radio only at known times); duty-cycle compliant
- `rssi_dbm` and `latency_ms` become real measurements; receipts fail plausibility checks if RSSI implies an impossible distance between the claimed cells of beaconer and witness
- receipts are gossiped back over the internet side-channel (the device keeps its node connection); reward requires ≥1 radio receipt — internet reachability no longer earns the peer bonus
- radio data transport is intentionally out of scope: LoRa bandwidth (kbps, duty-cycle limited) fits proofs, not payload

## Phase 3 — paid relaying (specified, not implemented)

For actual data crossing regions (e.g. Tehran → Dubai → India → Vietnam), transport rides the existing libp2p relay circuits; radio only covers last-mile segments without internet. Incentive layer:
- sender escrows EGUSD/EGOC for a message or stream
- each relay hop obtains a signed delivery receipt from the next hop (`"ego/relay-hop/v1:" stream_id ':' hop_index ':' from ':' to ':' bytes_u64le ':' timestamp`)
- hops redeem receipts against the sender's escrow pro-rata per forwarded byte; unclaimed escrow refunds after timeout
- witness receipts (this spec) provide the liveness/cell data used to pick relay paths

## Known limitations (phase 1, honest list)

- Witness receipts prove another *identity on another machine* heard you over the internet — they do not yet prove radio coverage or physical distance.
- Receipts are collected and counted by the beaconer itself; they are auditable (signed, stored) but not yet validated by consensus. Consensus validation of coverage rewards belongs to the same hardening track as the other self-asserted reward emitters.
- Geolocation is IP-based; the cell id is derived arithmetically from coarse coordinates, not a true H3 index.
- A cluster of colluding wallets on distinct machines can witness each other; machine_id and (phase 2) RF distance checks raise the cost but the full defense is stake-weighting + consensus validation.
