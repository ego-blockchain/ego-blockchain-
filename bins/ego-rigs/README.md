# ego-rigs

Run Ego nodes on servers, old PCs and any other computer, then see what all of them earn as one: each computer's balance, its rewards in the last 24 hours and 7 days, whether it is online, which version it runs, and the total for all of them.

```
Computer       Address                Balance  Last 24 h  Last 7 days  Last reward  Seen       Version  Status
rig-01         egot1q7x2k...9fz3m0   2,210.40     102.15       640.80  just now     just now   0.3.701  earning
rig-02         egot1p4n8w...h2c6ue   1,845.12      96.30       601.25  2 min ago    1 min ago  0.3.701  earning
rig-03         egot1z9d5r...v8k4ta     930.77      41.06       388.90  5 h ago      3 min ago  0.3.700  online, not earning
old-laptop     egot1m3j7y...q5w2xe       0.00       0.00         0.00  never        2 days ago 0.3.699  offline
----------------------------------------------------------------------------------------------------------------------
All computers  4 computers           4,986.29     239.51     1,630.95               3 online            2 earning

Amounts are in EGOC. Average over the last 7 days: 232.99 EGOC a day.
Read from the Ego node at http://127.0.0.1:47395 (block 190,520).
```

Every computer runs the real Ego node, the one inside Ego Desktop, in its server mode. `ego-rigs` only reads. It never sees a key or a recovery phrase, and you do not open any ports: nodes announce themselves to the network with a signed message, and the main computer's node keeps the last one it heard from each, so it knows when each computer was last online and which version it runs, even when they are in different houses.

## 1. Run the node on each computer

Install Ego Desktop from [egoblockchain.com/download](https://egoblockchain.com/download), then start it in server mode. The first start creates a wallet for that computer.

**With ego-rigs** (Windows, macOS or Linux):

```bash
ego-rigs start
```

It finds Ego Desktop where the installer put it (on Linux, the newest `.AppImage` in the current folder, `~/Applications`, `~/Downloads`, your home folder or `/opt/ego`), runs it in server mode, and starts it again whenever the node stops to restart itself. Use `--app <path>` if it is somewhere else.

**Without ego-rigs:**

| System | Command |
| --- | --- |
| Windows | `& "C:\Program Files\Ego Desktop\Ego Desktop.exe" --server` |
| macOS | `"/Applications/Ego Desktop.app/Contents/MacOS/Ego Desktop" --server` |
| Linux | `APPIMAGE_EXTRACT_AND_RUN=1 ./ego-desktop_*_amd64.AppImage --server` |

Press Ctrl+C to stop it.

**Write down the 24 words.** A new wallet is shown as new when the node starts. Run `ego-rigs phrase` (or Ego Desktop with `--recovery-phrase`) and write the words on paper, in order. Anyone who has them can take that computer's coins, and nobody can give them back to you if they are lost.

### Start at boot on Linux

`ego-node.service` in this folder runs the AppImage as a system service that starts at boot and restarts on its own:

```bash
sudo useradd --system --create-home ego
sudo mkdir -p /opt/ego
sudo cp ego-desktop_*_amd64.AppImage /opt/ego/ego-desktop.AppImage
sudo chmod +x /opt/ego/ego-desktop.AppImage
sudo cp ego-node.service /etc/systemd/system/
sudo systemctl enable --now ego-node
journalctl -u ego-node -f
```

The wallet then lives in `/home/ego/.local/share/EgoDesktop`. Show its address with `sudo -u ego /opt/ego/ego-desktop.AppImage --appimage-extract-and-run --address`, and its 24 words with `--recovery-phrase` in place of `--address`.

### Things that stop a computer from earning

- **A datacenter, VPN or proxy connection.** Rented cloud servers do not earn; the network refuses those connections so nobody can fake thousands of nodes. Computers on a normal home or office connection earn.
- **More than 2 nodes on one computer.** From block 192,341 each node names its computer on the chain, as a one-way hash of the computer's ID, never the ID itself. Only 2 nodes per computer then earn check-in pay and the full chance to be drawn as a block maker. A third node on the same computer only earns for the files it stores. From block 193,781 it keeps one point in the block maker draw, so a small network keeps making blocks when a computer goes offline, but it is still not paid for check-ins. This also covers several data folders and Docker containers on one server. A place frees up when one of the 2 nodes has been offline for a week.
- **An old version.** When a new version is required, the node stops making blocks until it is updated.

## 2. Add the computers on your main one

On each computer, run `ego-rigs here`. It prints that computer's wallet address and the exact line to copy. On your main computer, which runs Ego Desktop too (opened as usual or with `ego-rigs start`), add each one:

```bash
ego-rigs add rig-01 egot1...
ego-rigs add rig-02 egot1...
```

## 3. See them all

Run `ego-rigs` for the table, or `ego-rigs watch` to keep it on screen. It refreshes every 60 seconds; `--every 30` changes that.

| Command | What it does |
| --- | --- |
| `ego-rigs start` | Run the node on this computer in server mode |
| `ego-rigs phrase` | Show this computer's 24 words |
| `ego-rigs here` | Show this computer's wallet address |
| `ego-rigs add <name> <address>` | Add a computer, or change the address of one you already added |
| `ego-rigs remove <name>` | Remove a computer |
| `ego-rigs list` | The saved computers and where the list is kept |
| `ego-rigs` or `ego-rigs show` | The table and the total |
| `ego-rigs show --json` | The same numbers as JSON, for scripts |
| `ego-rigs watch` | The table, refreshed until you press Ctrl+C |

| Status | Meaning |
| --- | --- |
| earning | A reward arrived in the last 2 hours |
| online, not earning | The node was heard in the last 15 minutes but has not been paid for 2 hours. New nodes start this way while they catch up |
| online, no rewards yet | The node is online and has never been paid |
| offline | The node has not been heard for 15 minutes. Check that the computer is on, online and running the node |

A version shown in yellow is older than the main computer's. If the main computer runs an older Ego Desktop, Seen and Version stay empty and the status falls back to the time since the last reward (quiet after 2 hours, stopped after a day).

Rewards are what the network paid to the address: block rewards, fee shares and node pay. Payments between people are not counted.

## Build

You need Rust 1.75 or newer.

```bash
git clone https://github.com/ego-blockchain/ego-blockchain-
cd ego-blockchain-
cargo build --release -p ego-rigs
```

The program is `target/release/ego-rigs` (`ego-rigs.exe` on Windows).

## Settings

| Setting | Default |
| --- | --- |
| `--rpc <url>` or `EGO_RPC` | `http://127.0.0.1:47395`, the node on this computer |
| `--app <path>` or `EGO_DESKTOP_APP` | Where `start` and `phrase` find Ego Desktop |
| `EGO_RIGS_FILE` | `%APPDATA%\ego-rigs\rigs.json` on Windows, `~/Library/Application Support/ego-rigs/rigs.json` on macOS, `~/.config/ego-rigs/rigs.json` on Linux |
| `EGO_DATA_DIR` | Ego Desktop's data folder, if you moved it |

The Ego network is a public test network. EGOC is not trading anywhere, so `ego-rigs` shows amounts in EGOC only, never in money.
