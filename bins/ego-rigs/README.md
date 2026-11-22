# ego-rigs

One terminal view of the EGOC earned by all your Ego Desktop computers: each computer's balance, its rewards in the last 24 hours and 7 days, when it last earned, and the total for all of them.

It only reads. It never sees a key or a recovery phrase, and nothing is installed on the other computers. It asks the Ego node on your main computer, because every node holds the same chain and can answer for any wallet address.

```
Computer       Address                Balance  Last 24 h  Last 7 days  Last reward  Status
rig-01         egot1q7x2k...9fz3m0   2,210.40     102.15       640.80  just now     earning
rig-02         egot1p4n8w...h2c6ue   1,845.12      96.30       601.25  2 min ago    earning
rig-03         egot1z9d5r...v8k4ta     930.77      41.06       388.90  5 h ago      quiet
old-laptop     egot1m3j7y...q5w2xe       0.00       0.00         0.00  never        no rewards yet
--------------------------------------------------------------------------------------------------
All computers  4 computers           4,986.29     239.51     1,630.95               2 earning

Amounts are in EGOC. Average over the last 7 days: 232.99 EGOC a day.
Read from the Ego node at http://127.0.0.1:47395 (block 190,520).
```

## Build

You need Rust 1.75 or newer.

```bash
git clone https://github.com/ego-blockchain/ego-blockchain-
cd ego-blockchain-
cargo build --release -p ego-rigs
```

The program is `target/release/ego-rigs` (`ego-rigs.exe` on Windows).

## Use

1. Install and run Ego Desktop on every computer, each with its own wallet.
2. On each computer, run `ego-rigs here`. It prints that computer's wallet address and the exact `add` line to copy.
3. On your main computer, which must be running Ego Desktop too, add each one:

   ```bash
   ego-rigs add rig-01 egot1...
   ego-rigs add rig-02 egot1...
   ```

4. Run `ego-rigs` to see the table, or `ego-rigs watch` to keep it on screen. It refreshes every 60 seconds; `--every 30` changes that.

| Command | What it does |
| --- | --- |
| `ego-rigs` or `ego-rigs show` | The table and the total |
| `ego-rigs show --json` | The same numbers as JSON, for scripts |
| `ego-rigs watch` | The table, refreshed until you press Ctrl+C |
| `ego-rigs add <name> <address>` | Add a computer, or change the address of one you already added |
| `ego-rigs remove <name>` | Remove a computer |
| `ego-rigs list` | The saved computers and where the list is kept |
| `ego-rigs here` | This computer's Ego Desktop wallet address |

## Status

| Status | Meaning |
| --- | --- |
| earning | A reward arrived in the last 2 hours |
| quiet | The last reward was 2 to 24 hours ago |
| stopped | No reward for more than a day. Check that the computer is on, online and running Ego Desktop |
| no rewards yet | This address has never been paid |

Rewards are what the network paid to the address: block rewards, fee shares and node pay. Payments between people are not counted.

## Settings

| Setting | Default |
| --- | --- |
| `--rpc <url>` or `EGO_RPC` | `http://127.0.0.1:47395`, the node inside Ego Desktop on this computer |
| `EGO_RIGS_FILE` | `%APPDATA%\ego-rigs\rigs.json` on Windows, `~/Library/Application Support/ego-rigs/rigs.json` on macOS, `~/.config/ego-rigs/rigs.json` on Linux |
| `EGO_DATA_DIR` | Where `ego-rigs here` looks for Ego Desktop's wallets, if you moved them |

The Ego network is a public test network. EGOC is not trading anywhere, so `ego-rigs` shows amounts in EGOC only, never in money.
