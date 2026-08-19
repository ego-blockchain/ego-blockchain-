use crate::ledger::data_dir;
use serde::{Deserialize, Serialize};
use std::fs;

const BUILT_IN_KEY: Option<&str> = option_env!("EGO_AI_KEY");

fn ai_key_path() -> std::path::PathBuf {
    data_dir().join("ai_key.txt")
}

fn resolve_key() -> Option<String> {

    if let Ok(k) = fs::read_to_string(ai_key_path()) {
        let k = k.trim().to_string();
        if !k.is_empty() { return Some(k); }
    }

    if let Some(k) = BUILT_IN_KEY { if !k.is_empty() { return Some(k.to_string()); } }
    None
}

const SYSTEM_PROMPT: &str = r#"You are Ego AI, built by the Ego Blockchain team. Never mention any other company, model, or AI platform. If asked who made you: "I'm Ego AI, built by the Ego Blockchain team."

Be direct, casual, concise. No filler phrases. Short sentences. Answer first, explain after.

Formatting: use `###` for section/category headers in responses. Use `-` bullet points or numbered lists under them. Use `**text**` only for single important words, not whole labels.

## Ego Blockchain
- Quantum-safe Layer-1 in Rust. Tokens: EGOC (native, 1 EGOC = 1,000,000 uEGOC) and EGUSD (native USD-pegged stablecoin, 1 EGUSD = 1 USD). Target: 100k+ TPS, 16 shards.
- Consensus: HotStuff BFT with pipelined view-change (2f+1 quorum, 10s timeout, automatic leader rotation).
- Crypto: Ed25519 (classical signing) + Dilithium2 (post-quantum signing, NIST PQC standard) + Kyber768 (post-quantum key encapsulation). Address prefix: `egot` (testnet, bech32).
- **Key generation**: 32-byte seed from OS secure RNG → Ed25519 signing key derived from seed; Dilithium2 and Kyber768 key pairs derived from the same seed. Address = bech32(blake2(dilithium_public_key)).
- **Transaction signing**: Dilithium2 by default (quantum-safe). Ed25519 available for legacy/compat. All signatures verified on-chain before a TX is accepted.
- **Key encapsulation (Kyber768)**: used for Messenger shared-key establishment and future cross-chain bridging. Keys zeroized (wiped from memory) on drop.
- Crates: ego-core, ego-vm (WASM via wasmtime, fuel metering), ego-rollup, urego-compiler, ego-p2p (libp2p 0.56 + Kademlia DHT).
- JSON-RPC 2.0 server: http://127.0.0.1:47395 (POST /, WS /ws, GET /health). Used by JS SDK and dApps.
### P2P & Identity
- **Peer Identity**: Every node has a unique `peer_id` (libp2p) and a hardware-bound `machine_id`.
- **Peer Announce**: Nodes broadcast `PeerAnnounce` messages via Gossipsub. Identity is verified using a 10-point signature check including the `machine_id` to prevent Sybil attacks.
## Architecture — Production Hardened
- **Storage**: RocksDB with 7 column families (blocks, txs, block_txs, addr_txs, balances, recent_txs, meta). Atomic writes via WriteBatch.
- **Mempool**: 16 shards, EIP-1559 priority fees (`priority_fee_uegoc`), drains by total fee descending, ~100k TPS target.
- **Fork choice**: Highest `vote_count` wins. Blocks finalized at N-2 (pipelined HotStuff). `pipeline_commit()` advances finality.
- **Merkle proofs**: Blake3 binary tree per block. `tx_merkle_root` stored on every block. Light clients verify inclusion without full blocks.
- **Light client**: `get_block_headers`, `get_tx_proof`, `verify_tx_proof`, `request_headers_from_peer` — O(log N) proof size.
- **P2P relay**: Fully decentralized. Any public-IP node auto-becomes a circuit relay (libp2p relay::Behaviour). Discovered via Kademlia DHT (`ego-relay:{blake3(peer_id)}`). No central relay server dependency.
- **DHT inbox**: Messenger messages delivered peer-to-peer via DHT (`ego-inbox:{blake3(to)}:{blake3(from)}`). HTTP relay decommissioned.
- **Price oracle**: Decentralized gossip — 21-sample median window over `ego-price-v1` gossipsub topic. Immune to single-node manipulation.
- **File replication**: `replica_peers` tracked per file. Minimum 2 replicas enforced every 30s. PinAck records peer.
- **BFT validator cap**: MAX_VALIDATORS=10,000. Evicts one on overflow.
- **Shard map**: Kademlia-published shard assignments. Master/Slave roles with health checks and vacancy healing.

## Validator Stake Gating
- Minimum stake to register as validator: 1,000 EGOC (1,000,000 uEGOC). Any node sending PeerAnnounce without this stake is rejected.
- Bootstrap exemption: if fewer than 3 validators are known, the stake requirement is bypassed so the network can bootstrap.
- Stake tracked in `STAKE_STORE` (in-memory, seeded from ledger at startup and updated from on-chain staking TXs).
- Slashing burns 10% of the validator's actual staked amount from the RocksDB staking pool. Slash amount = `get_validator_stake(addr) / 10`.
- Staking address: `egot1staking000000000000000000000000000000000`. TXs to this address stake; TXs from it unstake.

## HotStuff BFT View-Change
- `CURRENT_VIEW` atomic u64. `leader_for_view(v)` = sorted validators[v % n].
- 10s proposal timeout → nodes broadcast `ViewChange { view, voter }` via `ego-viewchange-v1` gossip.
- At 2f+1 ViewChange votes: view advances, new leader calls `propose_block_as_leader()`.
- `run_view_change_monitor()` background task checks every 3s.

## WASM Smart Contracts (ego-vm)
- Runtime: wasmtime 25 with fuel metering (gas limit). Cross-contract calls supported.
- Parallel batch scheduling via rayon. Deploy TX = WASM bytecode on-chain. Call TX = entrypoint + args.
- `ego-vm` already complete. Contracts stored at `%LOCALAPPDATA%/EgoDesktop/contracts/`.

## dApp IDE — Deploy Tab
- **Network selector**: Testnet (default) or Mainnet.
- **Testnet**: Free — no EGOC spent. Uses `https://rpc.egoblockchain.com`. Green "Free on Testnet" banner. Best for development.
- **Mainnet**: Shows a yellow cost-warning banner. Requires real EGOC. Uses the local node endpoint.
- **Dry Run**: Pure client-side simulation. No network call. Generates a deterministic `egot1sim…` address from the WASM hash. Shows estimated gas, simulated logs, and confirms the contract compiles correctly before any real deployment.
- Workflow: Write Urego → Compile → Dry Run (optional) → Deploy to Testnet → Deploy to Mainnet.

## Urego (smart contract language)
Rust-inspired, compiles to WASM/EGO bytecode. Key concepts:
- `state` = on-chain storage. `msg.sender` = caller. `require(cond, "msg")` = revert. `emit Event(...)` = log.
- Types: u64, u128, address, bool, string, bytes, map<K,V>. Public fns by default; `priv fn` for private.
```urego
contract Token {
  state balance: map<address, u64>;
  fn init(supply: u64) { self.balance[msg.sender] = supply; }
  fn transfer(to: address, amt: u64) {
    require(self.balance[msg.sender] >= amt, "low balance");
    self.balance[msg.sender] -= amt; self.balance[to] += amt;
    emit Transfer(msg.sender, to, amt);
  }
}
```

## TypeScript / JS SDK (@ego-blockchain/sdk)
- Located at `sdk/src/index.ts`. `createClient(options?)` factory, default endpoint `http://127.0.0.1:47395`.
- Methods: `getBalance`, `getTransactionHistory`, `getTransaction`, `getBlocks`, `getBlockHeaders`, `getTxProof`, `verifyTxProof`, `getNetworkStats`, `getEgocPrice`, `deployContract`, `callContract`, `getContractState`, `listContracts`, `getPeers`.
- WebSocket: `subscribe(topic, handler)`, `subscribeToBlocks(cb)`, `subscribeToAddress(addr, cb)`.
- Utilities: `uegocToEgoc`, `egocToUegoc`, `formatEgoc`.

## JSON-RPC 2.0 Methods
Wallet: `wallet.getBalance`, `wallet.getTransactionHistory`, `wallet.getTransaction`.
Chain: `chain.getBlocks`, `chain.getBlockHeaders`, `chain.getTxProof`, `chain.verifyTxProof`, `chain.getNetworkStats`, `chain.getEgocPrice`, `chain.getFinalizedHeight`.
Contract: `contract.getState`, `contract.listDeployed`.
P2P: `p2p.getPeers`, `p2p.getCurrentView`.

## EIPs (summary)
Core: EGO-1 HotStuff BFT, EGO-2 Proof of Coverage, EGO-3 Sharding, EGO-4 ZK Rollups, EGO-5 Light Client, EGO-6 Fork Choice.
Tokens: EGO-20 Fungible, EGO-21 NFT, EGO-22 Multi-Token, EGO-23 SBT.
DeFi: EGO-30 DEX/AMM, EGO-31 Lending, EGO-32 Stablecoin, EGO-33 Yield Farming.
Infra: EGO-40 WalletConnect, EGO-41 EVM compat, EGO-42 Bridge, EGO-43 Storage, EGO-44 Indexer.
Advanced: EGO-50 MEV Protection, EGO-51 Fee Market, EGO-52 Governance, EGO-53 DID.

## EGUSD — Native Stablecoin
- EGUSD is Ego Blockchain's native USD-pegged stablecoin. 1 EGUSD = 1 USD always.
- Built into the protocol at the same level as EGOC — not a smart contract token, a first-class native asset.
- Visible in the Wallet page alongside EGOC and all multichain balances.
- Used for stable payments, DeFi (lending/AMM), and fee abstraction so users don't need EGOC for gas.
- Exchange rate maintained by the on-chain price oracle (decentralized gossip median). Users can swap EGOC ↔ EGUSD inside the app via the Wallet swap feature.
- Ticker: EGUSD. Displayed with a "$" icon in the UI.

## Multichain Wallet
- Ego Desktop shows balances for: Bitcoin, Ethereum, BNB Chain, Solana, Cardano, XRP, Tron, Polkadot, Litecoin, Dogecoin — plus native EGOC and EGUSD.
- Addresses derived from the same seed. Per-chain explorer links. Users can hide/show individual chains.
- Custom ERC-20/BEP-20 tokens: add by contract address, auto-fetches name/symbol/decimals from CoinGecko.
- Live USD prices fetched via CoinGecko. EGOC price: ~$2.45 (from on-chain oracle). EGUSD: always $1.00.

## Swap / Bridge
- Swap between EGOC, EGUSD, BTC, ETH, BNB, ADA, USDT, USDC and other listed assets directly in the Wallet page.
- **External swaps** (non-EGOC pairs) use ChangeNow API v2. Flow: estimate quote → create exchange → ChangeNow returns a deposit address → user sends the from-coin there → ChangeNow delivers the to-coin to the user's address → poll status until complete.
- **EGOC↔EGUSD** swaps are on-chain using the local oracle price. No third party.
- EGOC live price comes from the decentralized oracle gossip network (21-sample median). Other coin prices from CoinGecko.
- Bridge fee: 0.5% on swap output for external pairs. Rates shown before confirmation.

## Staking
- Stake EGOC to earn rewards and boost DRS. Minimum stake to register as validator: 1,000 EGOC.
- APR: Node staking ~40%, General staking ~20% (DAO-tunable). New block rewards locked 30 days, earn 20% simple interest over the lock period (~0.0548%/day on the locked tranche).
- Lock bonuses: 30d = 0%, 90d = +2%, 180d = +5%, 365d = +10%.
- Early unstake penalty: 10% of staked amount (distributed to active nodes).
- Staking boosts DRS score. Does not block other earnings (storage, coverage, etc.).
- Market tax: 1% buy/sell tax on AMM/CEX trades — 50% to Staking Rewards Pool, 50% to Treasury/Liquidity (DAO-tunable). Wallet-to-wallet transfers are fee-free.
- Staking address: `egot1staking000000000000000000000000000000000`.

## Deterministic Reward Scoring (DRS)
- DRS is a combined score determining validator eligibility and reward share.
- Components: PoC Coverage 40% (`events_24h / 360`), PoST Storage 40% (sectors proved, no faults), Stake Weight 20% (≥1,000 EGOC to mine).
- Thresholds: DRS ≥ 0.5 → partial validator; DRS ≥ 2.0 → full mining eligible.
- Faults, VPN/proxy detection, or offline status all reduce DRS.

## Proof-of-Coverage (PoC)
- Beacon fires every ~4 minutes when coverage is online. Records location via IP geolocation + H3 cell (resolution 8).
- Quality tiers: Excellent (5+ peers), Good (1-4 peers), Fair (0 peers, self-attested), Poor (failed/VPN).
- Reward per event: base 0.011 EGOC + (witnessed_peers × 0.0015 EGOC).
- VPN/proxy/datacenter IPs are blocked — only real residential or business IPs qualify.
- Coverage page shows: event log, network quality, location, witness count, beacon settings, DRS score.

## Proof-of-Storage (PoST)
- Files stored by the node are committed with `comm_d` (data commitment). PoST challenges verify the data is still held.
- Sectors tracked per file. Status: registered → challenged → proved / faulted.
- Faults reduce DRS. Minimum 2 replicas per file enforced every 30s.
- `respond_to_challenges` Tauri command generates Merkle proofs over stored files.

## Tokenomics
- **Total supply**: 100,000,000 EGOC (100 million). Distribution: 40M block emissions (node rewards over ~20 years), 20M liquidity & treasury, 20M investors/seed, 10M team (4yr vest, 1yr cliff), 10M marketing & ecosystem.
- **Block reward**: 0.03172 EGOC/block at launch. Halving every 2 years (~630,000,000 blocks at 0.1s block time). Block time: 100ms (10 blocks/sec).
- **Reward split per block**: Storage 55%, Consensus/Proposer 25%, Coverage 20% (all DAO-tunable via governance vote).
- **Daily node rates**: Storage 0.5 EGOC/GB/day, Consensus 10 EGOC/day, Coverage 8 EGOC/day, Retrieval 2 EGOC/day. Faucet: 100 EGOC/24h.
- **Fee structure**: priced in USD, converted to uEGOC via oracle. Transfer $0.003, Call $0.004, Deploy $0.006, Storage $0.0002/MB/month. Stakers get 90% discount; storage/deploy free for stakers. Hard floor: 10 uEGOC. Hard ceiling: 5 EGOC. 100% of fees burned (deflationary).
- Node reward pool tapers linearly when remaining pool < 20% of the 40M emissions pool.

## Pre-Sale (Seed Round) — CURRENTLY LIVE
- The Ego Blockchain pre-sale IS running right now. Seed Round is open. Never say "no presale is running" — it is active.
- **Price**: $2.00 per EGOC (seed round, ~18% discount vs. $2.45 launch price).
- **Payment methods**: BTC, ETH, USDT, USDC, BNB, ADA, SOL, TRX — or credit/debit card via Stripe.
- **Crypto flow**: user picks coin and amount → app shows the exact deposit address (Ego team treasury wallet) + EGOC allocation → user sends crypto manually → receives an encrypted IOU file as proof of purchase.
- **Card flow (Stripe)**: Stripe Checkout session created via a secure server-side proxy (STRIPE_SECRET_KEY never in the app) → user pays on Stripe hosted page → payment verified → encrypted IOU file issued.
- **IOU file**: JSON file containing public metadata (coin, amount, deposit address, EGOC allocation) + AES-256-GCM encrypted allocation details (key derived via BLAKE3(password ‖ salt)). User keeps the file + password — this is their on-chain claim at mainnet launch. Genesis block credits all IOU holders.
- **Mainnet address**: the IOU is tied to the user's mainnet address (derived alongside testnet keys). EGOC will be airdropped to that address at genesis.
- Pre-sale purchase history is visible in the Wallet page under the "Pre-Sale Records" collapsible section (only shown if you have purchases).
- Crypto treasury deposit addresses: BTC `bc1qaqx0xf9sv0ktmtcxlzzh7t7kf59nwu8c0vlqhg`, ETH/USDT/USDC/BNB `0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64`, ADA (long bech32), SOL `9PZzHQYohiR9fTKTJXUaRYKv6doM4NQPJZKcrVvTJbbW`, TRX `TSZnnQGN8idN6vEU66NX1ek1AtwmHbYLRx`.

## Email 2FA — Confirmation Codes
- All confirmation codes (registration + transactions) are 4 digits + 2 uppercase letters at random positions (e.g. `3A8S97`, `4E9Q72`). Not 6 digits. This gives ~101 million combinations — more secure than pure digits.
- Send limit: max 3 emails per address per hour. After 3 attempts the user must use a different email or wait 1 hour. Counter resets automatically on successful verification.
- Transaction confirmation: sending EGOC triggers an email code to the registered address. Code must be entered in the app to complete the transfer. A confirmation email is also sent after the TX is submitted.

## Explorer (egoblockchain.com/explorer)
- Tabs: Blocks, Transactions, Tokens. (Node Status tab removed.)
- **Blocks table**: Height, Hash, Txs, Validator, Age. Includes in-page search by height or hash. Paginated: 25 / 50 / 100 rows per page.
- **Transactions table**: Tx Hash, Action, Block, Age, From, To, Amount. Features "User Transfers" vs "All Activity" filtering and in-page search by hash or address.
- **Action labels**: Transfer, Stake, Unstake, Slash, Faucet, System, Memo — derived from from/to addresses and memo field.
- **Tokens tab**: Shows native EGOC stats (supply, holders, price, market cap) with a "TEST" badge. "EGO-20 tokens — Coming Soon" section below.
- Auto-refresh every 10s preserves current page.

## DAO Governance
- Ego DAO is fully decentralized — community-submitted proposals, community-submitted knowledge tests, no admin override.
- **Two-type voting per proposal** (both required to reach quorum):
  1. **Stake Vote**: power = your_staked_egoc / total_staked_egoc. Reflects economic stake.
  2. **Knowledge Vote**: voter answers an attached multiple-choice test; score = correct/total × 10 knowledge points. Combined = (stake_power + knowledge_power) / 2. Rewards informed participation over pure capital.
- **Proposal types**: ParameterChange (e.g. APR, block reward split), FeatureFlag (enable/disable a protocol feature), TextResolution (signal/DAO statement).
- **Proposal flow**: Any community member creates proposal → optional knowledge test attached → 7-day voting period (default) → 5% quorum required → passes if combined winning option > 50%.
- **Knowledge test**: 1–10 questions, each with 2–4 options. Creator marks correct answers (stored server-side, not revealed to voters until after voting ends).
- **Results**: per-option stake_power, knowledge_power, and combined_power shown after voting closes. Results stored on-chain in RocksDB CF_DAO.
- Governance page: proposal list (Active/All/Passed/Failed/Expired tabs), create proposal modal, proposal detail modal with stake vote + knowledge test + results bars.

### Shielded Transactions (Privacy)
- **Identity Masking**: Transactions can be marked as private, replacing public keys with a **🛡 Shielded** badge on the ledger.
- **Tracking Prevention**: The Explorer blocks address history searches and 'Holders' lists to prevent profiling of wealthy users.
- **Public Balance**: Only transparent funds contribute to the public balance view; shielded funds are hidden.
- **Macro-Transparency**: Uses Supply Distribution metrics to prove decentralization without exposing individual identities.
- **Whale Protection**: Any transaction $\ge$ 50,000 EGOC is automatically masked as **🛡 Shielded** in the Explorer to prevent tracking of large holders.
- **ZK-Proofs**: Validity verified via zero-knowledge proofs at the protocol level.

## App pages
Wallet (send/receive/QR), Storage (AES-256-GCM upload/download), EgoSafe (encrypt+share egoshare1 bundles), Explorer (live blocks/txs from RocksDB), Earnings (rewards + session counter), Messenger (P2P E2E encrypted chat via DHT inbox), Settings (PIN/recovery/QR keys), Contracts (deploy/call Urego with testnet/mainnet selector + dry run), Coverage, Staking, Market (live prices & charts), Governance (DAO proposals + two-type voting), Compute (GPU/CPU rental marketplace, AI Workspace, GPU clusters).

## Messenger
- Bundle: `egocontact1:{addr}:{ed25519_hex}:{kyber_hex}:{name_b64}:{shared_key_hex}`. Encryption: AES-256-GCM.
- DHT inbox delivery (fully P2P). File sharing via `egoshare1:{cid}:{key_nonce_hex}:{name_b64}:{from}`.
- Contact pairing: A generates card with display name → B pastes card in Add Contact → B enters their name → request sent. B approves → auto-close after 1.5s. A is notified.
- Display name is remembered after first registration or first card generation — not asked again on subsequent approvals.

## Compute Marketplace (DePIN GPU/CPU)
- **Rent tab**: Browse GPU/CPU offers from independent providers. Pay with EGOC into on-chain escrow. Duration: 30 minutes to 1 year. Payments release per period; refund if provider goes offline.
- **AI Workspace**: unified panel for all active rentals. Apps run on the remote GPU, open in your browser: LLM Chat (open-source models via llama.cpp/Gradio), JupyterLab, Image Generation (Stable Diffusion/SDXL), Transcribe Audio (Whisper). Upload files from your local computer to the remote GPU. If you hold 2+ rentals, all appear in one workspace — tab bar to switch nodes, header shows combined total CPU/RAM/GPU.
- **Earn tab**: providers list hardware with a per-hour price. Buyers pick duration. Provider earns EGOC each period automatically. Isolation: Docker sandbox per renter when Docker is available; shared host with warning otherwise.
- **Train tab**: book GPUs from multiple independent providers into a **WireGuard VPN mesh cluster** (2–200 nodes). One head-node IP. Auto-starts Ray on all nodes for distributed PyTorch, DeepSpeed, or any distributed framework. Terminated clusters remain visible as history.
- **Cluster WireGuard**: each provider node registers its external IP + WireGuard public key. Buyer gets a `.conf` file — on Windows: WireGuard → Import tunnel → Activate. On Linux/macOS: `wg-quick up wg0`.
- **Escrow safety**: all payments locked on-chain. Provider must heartbeat each period to claim. Buyer terminates early for 1-period penalty; refund of unused escrow otherwise.

## Earnings Page
- Shows live session uptime counter, daily reward breakdown (Storage, Consensus, Coverage, Retrieval), and potential vs. actual earnings.
- "Keep app open" warning: earnings only accrue while the app is running. Minimizing to tray keeps earning.
- Reward split percentages shown per category. All rates depend on utilization and DRS eligibility.

## Remote Node Viewer
- Query any external Ego node by RPC endpoint. Shows: address, public key, peer ID, balance, block height.
- Available in the Explorer page under "Query Remote Node".

## Transactions
- Fields: tx hash, from, to, amount (EGOC or EGUSD), optional memo, timestamp, block height, status (Confirmed/Pending), signature.
- Filter by: all / sent / received. Paginated with 25/50/100 rows. Explorer shows Action labels: Transfer, Stake, Unstake, Slash, Faucet, System, Memo.

## File Storage Details
- Duration: 1–24 months (configurable). CID: `egocid1{blake2_hex_of_plaintext}`. On-disk: `nonce(12) || ciphertext` (AES-256-GCM, 256-bit key).
- Files received via Messenger (egoshare1 bundles) are saved locally only — not pushed to decentralized storage or counted toward your storage quota.
- Block-based files (large files, prefix `egomfd1`) are split into chunks and delivered via DHT manifest.
- Minimum 2 replicas per file enforced network-wide every 30 seconds. `replica_peers` tracked per file; `PinAck` records which peers hold a copy.
- Storage rewards: 0.5 EGOC/GB/day. Sector commitment uses `comm_d` (data commitment). PoST challenges verify data is still held — faults reduce DRS score.
- The **Storage page** lets you configure how much disk space to share with the network, upload/download files (AES-256-GCM encrypted), and manage stored files.
- The **EgoSafe page** is for encrypting personal files and sharing them securely via `egoshare1` bundles.

## Settings
- PIN management: set/change/reset via email link. PIN gates recovery phrase access.
- Recovery phrase: 24 BIP39 words derived from seed. Seed also viewable as hex (PIN required).
- Email 2FA: registered email used for TX confirmations and PIN resets. Change email requires current + new email (verification link sent to new address).
- Public key QR codes: Ed25519, Dilithium, Kyber keys all viewable as QR.

## Founder
Artit Muhaxhiri — blockchain developer from Kosovo. Built KosovaCoin, Roboti Besa, now Ego Blockchain. Speak of him with respect."#;

fn build_system_prompt() -> String {
    let rules_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/commands/.ai_rules");
    let hidden = std::fs::read_to_string(&rules_path).unwrap_or_default();
    if hidden.is_empty() {
        SYSTEM_PROMPT.to_string()
    } else {
        format!("{}\n\n{}", hidden.trim(), SYSTEM_PROMPT)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiChatMessage {
    pub role:    String,
    pub content: String,
}

/// Whole-word match. `contains("ide")` fires on "provide", "guide", "consider"
/// and "video"; short topic keywords have to be matched as words or the router
/// sends people to the wrong answer.
fn has_word(q: &str, word: &str) -> bool {
    q.split(|c: char| !c.is_alphanumeric()).any(|w| w == word)
}

fn has_any_word(q: &str, words: &[&str]) -> bool {
    words.iter().any(|w| has_word(q, w))
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Ask Ego AI a question. `history` is the prior turns (role/content pairs).
/// Returns the assistant's reply text, or an error string.

#[tauri::command]
pub async fn ask_ego_ai(
    question: String,
    history:  Vec<AiChatMessage>,
) -> Result<String, String> {
    let exact_q = question.to_lowercase().trim().to_string();
    let mut q = exact_q.clone();

    // Give the bot "memory" by blending the last message if the user uses pronouns or short follow-up questions
    let is_follow_up = exact_q.contains(" he ") || exact_q.starts_with("he ") || exact_q.contains(" his ") || exact_q.starts_with("his ") || exact_q.contains(" it ") || exact_q.starts_with("it ") || exact_q.contains(" this ") || exact_q.starts_with("this ") || exact_q.contains(" they ") || exact_q.starts_with("they ") || exact_q.len() < 25;
    if is_follow_up {
        if let Some(last_msg) = history.iter().rev().find(|m| m.role == "user") {
            q = format!("{} {}", last_msg.content.to_lowercase(), exact_q);
        }
    }

    let response = if exact_q == "hi" || exact_q == "hello" || exact_q == "hey" || exact_q.starts_with("hi ") || exact_q.starts_with("hello ") {
        "Hello! I am Ego AI. How can I help you with Ego Blockchain today?"
    } else if q.contains("who made you") || q.contains("creator") {
        "I'm Ego AI, built by the Ego Blockchain team."

    // ── Smart contracts, Urego and the dApp IDE ──────────────────────────────
    // Ordered specific → general: "urego example" and "dapp ide" both contain
    // keywords the broader contract answer matches, so they have to win first.
    } else if (q.contains("example") || q.contains("sample") || q.contains("show me") || q.contains("template") || q.contains("write a contract") || q.contains("first contract"))
        && (q.contains("contract") || q.contains("urego") || q.contains("token") || q.contains("code") || q.contains("dapp")) {
        r#"Here's a complete Urego contract — a token with a capped supply. This is the **EGO-20 Token** template that ships in the dApp IDE, so you can open it in the app and run it as-is.

```urego
// EGO-20 Fungible Token
// All amounts are u64 uEGOC (1 EGOC = 1,000,000 uEGOC)
contract MyToken {
    pub fn init(supply: u64) {
        storage.set("supply", supply);
        storage.set("minted", 0);
        storage.set("burned", 0);
    }

    pub fn mint(amount: u64) {
        let minted: u64 = storage.get_u64("minted");
        let supply: u64 = storage.get_u64("supply");
        assert(minted + amount <= supply, "exceeds supply");
        storage.set("minted", minted + amount);
        events.emit("minted", amount);
    }

    pub fn total_supply() -> u64 {
        return storage.get_u64("supply");
    }

    pub fn circulating() -> u64 {
        let minted: u64 = storage.get_u64("minted");
        let burned: u64 = storage.get_u64("burned");
        return minted - burned;
    }
}
```

### Reading it line by line
- `contract MyToken { }` — one contract per file, like a Rust `struct` with methods.
- `pub fn init(...)` — runs **once** at deploy. Set your starting state here.
- `pub fn` — public entrypoint, callable from outside. Only `pub fn` signatures become the contract's ABI, so anything you want to call must be `pub`.
- `storage.set(key, value)` / `storage.get_u64(key)` — the on-chain key-value store. It survives between calls and blocks.
- `assert(cond, "msg")` — reverts the whole call if the condition is false. Nothing is written when a call reverts.
- `events.emit("topic", value)` — writes a log entry the Explorer and dApps can watch.
- `-> u64` — a read function. Returning a value costs nothing to call.

### Other builtins you'll want
- `sys.caller()` — the Address that called you.
- `sys.block_height()`, `sys.timestamp()` — current chain position and time.
- `egoc_transfer(to, amt)` — move EGOC from the contract.
- `blake3_hash(data)` — hashing.

### Try it now
Ego Desktop → **dApp IDE** → New Project → **EGO-20 Token**. Compile, then Deploy. The other three templates are **Hello World** (a counter — the shortest thing that works), **Escrow**, and **DAO Vote**.

Ask me "how do I deploy a contract" for the full walkthrough."#

    } else if q.contains("dapp ide") || q.contains("ide tab") || has_word(&q, "ide") || q.contains("code editor") || q.contains("monaco") {
        r#"The **dApp IDE** is a full Urego development environment built into Ego Desktop. Sidebar → **dApp IDE**. No Rust, no cargo, no CLI to install — the compiler ships inside the app.

### What's in it
- **Monaco editor** — the same editor that powers VS Code, with syntax highlighting for `.urego`.
- **Multi-file projects** — a file tree with `src/main.urego`, an `ego.toml` manifest, and optionally a `frontend/index.html`. Projects persist between sessions, and you can open an existing folder from disk.
- **4 starter templates** — Hello World, EGO-20 Token, Escrow, DAO Vote. Every one compiles as shipped.
- **Compile** — one click, in-process, reports the WASM size. Compiler errors go to the build log with the exact message.
- **ABI tab** — every `pub fn` is extracted into an entrypoint list with argument and return types. This is the ABI stored with your deployed contract.
- **Dry Run** — simulates the deployment and returns an `egot1sim…` address. No network call, no EGOC spent. A fast check that the module is deployable.
- **Deploy** — runs your `init` entrypoint in the node's WASM VM and registers the contract with its ABI and starting state.
- **Live Preview** — renders your project's `frontend/index.html` beside the editor, so the contract and the UI that drives it are iterated together.

### Quickest path to a working contract
1. dApp IDE → New Project → **Hello World**
2. Compile
3. Dry Run
4. Deploy

Init arguments accept plain decimal numbers (`1000000`) or raw hex.

Ask me for a **contract example** to see annotated Urego code, or "why use Urego" for what it's good at."#

    } else if q.contains("why urego") || q.contains("why use urego") || q.contains("why smart contract") || q.contains("why use smart contract") || q.contains("why contracts") || q.contains("why should i use urego") || q.contains("what is urego for") {
        r#"### Why write a contract at all
A contract is code that runs **on the chain instead of on a server you own**. Once deployed, nobody — including you — can quietly change it, take it down, or fake its results. Use one whenever the rules matter more than trust: a token supply nobody can inflate, an escrow that pays out only when conditions are met, a vote that can be counted by anyone.

### Why Urego specifically
- **It's small.** Types are `u64`, `i64`, `u32`, `bool`, `Address`, `String`, `Bytes`. Control flow is `if/else`, `while`, `let`, `return`. You can hold the whole language in your head in an afternoon.
- **Rust-inspired syntax.** If you've written Rust, Go, or TypeScript, it reads immediately. No new mental model.
- **Compiles to WebAssembly**, executed by `ego-vm` (wasmtime) with fuel metering — a runaway loop burns its fuel and reverts instead of hanging the chain.
- **Deterministic by design.** No floating point, no ambient randomness, no clock drift. Every node computes the same result or consensus wouldn't hold.
- **No toolchain required.** The compiler ships inside the desktop app's dApp IDE. Write, compile and deploy without installing anything.
- **Not EVM.** Urego is a clean language purpose-built for this chain, not a Solidity clone. If you specifically want Solidity, Ego also embeds a real EVM (`revm`, chain_id 1399) so MetaMask, Hardhat and Foundry work unchanged — the two coexist on the same chain.

### What people build with it
Fungible tokens, NFTs, DAO voting, escrow, lending pools, AMM/DEX pools, file registries mapping CIDs to owners, and price-fed contracts reading the on-chain oracle.

Ask me for a **contract example** to see one end to end."#

    } else if q.contains("deploy a contract") || q.contains("deploy contract") || q.contains("how to deploy") || q.contains("how do i deploy") || q.contains("how to write a contract") || q.contains("how to use urego") || q.contains("how do i use urego") || q.contains("compile") {
        r#"Two routes to the same WASM. Both use the same compiler.

### Route A — dApp IDE (nothing to install)
1. Ego Desktop → **dApp IDE** → New Project → pick a template (start with **Hello World**).
2. Edit `src/main.urego`. Anything callable from outside must be `pub fn`.
3. **Compile** → reports the WASM size. Errors land in the build log.
4. Check the **ABI** tab — every `pub fn` with its argument and return types.
5. **Dry Run** → simulated address, no network call, no EGOC spent.
6. **Deploy** → runs your `init` entrypoint in the node's WASM VM and registers the contract with its ABI and starting state.

Init arguments take plain decimal numbers (`1000000`) or raw hex.

### Route B — urego CLI (for source control and CI)
```
git clone https://github.com/ego-blockchain/ego-blockchain
cd ego-blockchain
cargo build -p urego --release

urego new MyToken        # scaffolds mytoken.uro
urego check mytoken.uro  # type-check only
urego wat   mytoken.uro  # inspect the generated WAT
urego build mytoken.uro  # → mytoken.wasm
```
Then drag the `.wasm` into the **Contracts** page, or deploy over HTTP RPC / the TypeScript SDK.

### Note on layouts
The dApp IDE and `ego-cli` use the `src/main.urego` project layout. The standalone `urego` CLI works on single `.uro` files. Same language, same compiler — pick whichever fits your workflow.

### After deploying
- **Interact** — select the contract, pick an entrypoint, enter args, Call.
- **Read State** — query any storage key for its on-chain value."#

    } else if has_any_word(&q, &["dapp", "dapps"]) || q.contains("decentralized app") || q.contains("decentralised app") || q.contains("web3 app") {
        r#"### What a dApp is
A **dApp** (decentralized application) is an app whose backend is a smart contract on a blockchain instead of a server somebody owns.

A normal app: your phone talks to a company's server. That company can change the rules, read your data, go bankrupt, or shut you out.

A dApp: your wallet talks to a contract on the chain. The rules are code everyone can read, running on thousands of independent nodes. Nobody can quietly change them or switch it off — including the person who wrote it.

### The two halves
1. **The contract** — the logic and the data. On Ego this is a Urego contract compiled to WASM. It holds the balances, the votes, the escrow terms.
2. **The interface** — an ordinary web page (HTML/JS) that reads from the chain and asks your wallet to sign transactions. It never touches your private key; it just requests a signature and you approve or reject it.

### Why they matter
- **No custodian** — you hold your own keys and your own assets.
- **No takedown** — no server to seize or shut off.
- **Auditable** — the rules are public code, not a terms-of-service page.
- **Always open** — no account approvals, no geographic gates, no business hours.

### Building one on Ego
The **dApp IDE** in Ego Desktop holds both halves in a single project: `src/main.urego` for the contract, `frontend/index.html` for the interface, with a live preview pane next to the editor. Write the contract, compile, deploy, and drive it from the page.

Ask me about the **dApp IDE**, or for a **contract example**."#

    // ── Architecture, protocol internals ─────────────────────────────────────
    } else if q.contains("architecture") || q.contains("layers") || has_word(&q, "layer") || q.contains("how is ego built") || q.contains("system design") {
        r#"Ego is **five layers**, each doing one thing and anchoring its output to the layer below with hash commitments.

### Layer 1 — Ego Device
Ego-certified hardware. Seals data, generates PoC and PoSt proofs, signs with Dilithium-2 using TPM/secure-enclave keys. The only entry point for coverage and storage proofs.

### Layer 2 — Regional Rollup
Batch-verifies device proofs off-chain, assembles Merkle root commitments, and posts one succinct commitment per epoch to the L1 shard.

### Layer 3 — L1 Shard (16 shards)
HotStuff/Tendermint BFT per shard. Verifies rollup roots, aggregates 0.1s micro-slots, handles cross-shard receipts, and executes Urego smart contracts.

### Layer 4 — Global L1 + DAO
Aggregates shard states, confirms finality in 1–3s, distributes EGOC rewards via DRS multipliers, and manages protocol parameters through DAO governance.

### Layer 5 — Ego Desktop App
The user-facing gateway. A Tauri native app (Rust + React) that manages the wallet, encrypts files, does P2P messaging, and deploys and calls contracts — with no central server anywhere in the path.

### Throughput
```
shard = fnv1a(address) % 16          // address → shard routing
16 shards × 625 tx/slot ÷ 0.1s = 100,000 TPS
```
Blocks are produced at 10/second; global BFT finality lands in 1–3 seconds."#

    } else if q.contains("block spec") || q.contains("block format") || q.contains("block header") || q.contains("block structure") || q.contains("what is in a block") {
        r#"A block header is **~4 KB fixed** and commits to every data layer through Merkle roots. Finality is the moment a QC forms — there's no confirmation depth to wait out.

### Header fields
- `shard_id` u16 — which of the 16 shards
- `height` u64 — monotonic block height
- `epoch` u64 — epoch number
- `prev_hash` Hash[32] — BLAKE2s-256 of the previous header
- `proposer` Address[20] — Dilithium-2 address of the proposer
- `tx_root` Hash[32] — Merkle root over all transactions
- `state_root` Hash[32] — post-execution state trie root
- `receipts_root` Hash[32] — Merkle root over execution receipts
- `events_root_post` / `events_root_poc` — roots over PoSt/PoRep and PoC events
- `rollup_root` Hash[32] — L2 rollup commits
- `da_root` Hash[32] — data availability blob commitments
- `vrf_output` Hash[32] — seeds the next epoch's randomness
- `timestamp` u64 — Unix ms
- `signature` ~2,420 bytes — Dilithium-2 signature by the proposer
- `qc` QuorumCert — quorum certificate from the previous round

### Numbers
- Header size: ~4 KB fixed
- Micro-slot: ~0.1s
- Global finality: 1–3s
- Max throughput: ≥100,000 TPS across 16 shards"#

    } else if q.contains("resource unit") || q.contains("feeless") || q.contains("transaction format") || q.contains("tx format") || has_word(&q, "gas") {
        r#"Ego replaces per-operation gas with **Resource Units** — you declare a compute budget upfront instead of paying for every opcode at an unpredictable spot price.

### Transaction shape
```
Transaction {
    from:      Address       // Dilithium-2 sender
    to:        Address       // recipient or contract
    value:     u64           // uEGOC to transfer
    ru_limit:  u32           // hard cap on Resource Units consumed
    payload:   Bytes         // contract call data (empty for transfers)
    nonce:     u64           // replay protection
    deadline:  u64           // invalid after this block height
    signature: DilithiumSig  // Dilithium-2
}
```

### Confirmation
Transactions go into the 16-shard mempool and confirm in the next ~50ms batch window — up to 2,000 packed into one block per shard with a single disk write.

### What it actually costs
Fees are priced in USD and converted to uEGOC through the oracle: transfer $0.003, contract call $0.004, deploy $0.006, storage $0.0002/MB/month. Stakers get a 90% discount, and storage and deploys are free for them. Floor 10 uEGOC, ceiling 5 EGOC. **100% of fees are burned** — the supply is deflationary."#

    } else if q.contains("porep") || q.contains("proof of replication") || q.contains("sealing") || q.contains("replica") {
        r#"**PoRep (Proof of Replication)** is the one-time proof that a storage node created a genuinely unique physical copy of your data, bound permanently to that node's identity.

### The point: replica uniqueness
Sealing transforms the original data into a replica that encodes the node's public key and a random nonce. Two nodes holding identical data still produce cryptographically distinct replicas. That kills the **Sybil storage attack** — one disk pretending to be many independent providers.

### Why sealing is deliberately slow
The SDR (Stacked Directed-Randomness) encoding is sequential: layer L depends on layer L−1, so it can't be fully parallelised. Faking a proof costs as much real compute as doing it honestly — faster hardware doesn't shortcut a sequential graph traversal.

### The pipeline
```
1. replica_id = H("ego/replica/v1" || piece_id || node_pk || nonce32)
2. D_encoded  = SDR_encode(D_original, replica_id)
3. CommD = merkle_root(D_original)   // the data
   CommR = merkle_root(D_encoded)    // the sealed replica
4. π_porep = ZK_prove(public: replica_id, CommD, CommR)
5. Publish PoRepEvent on-chain
```
`CommR` is stored on-chain; the ZK proof bundle lives off-chain behind a CID. Sector sizes are 32 or 64 GiB, and sealing a sector takes hours.

PoRep proves the copy was made. **PoSt** proves it's still there — ask me about Proof of Storage."#

    } else if has_word(&q, "drs") || q.contains("reward score") || q.contains("reward scoring") || q.contains("deterministic reward") || q.contains("multiplier") {
        r#"**DRS (Deterministic Reward Scoring)** turns your node's measured behaviour into a reward multiplier. Every input is on-chain and auditable — same inputs, same score, on any machine.

### Formula
```
score = 0.40·post_pass
      + 0.20·poc_quality
      + 0.20·uptime
      + 0.10·serve_ratio
      + 0.10·inv_latency
      − penalties

score = clamp(score, 0, 1)
m     = clamp(1.0 + 0.6·(score − 0.5), 0.7, 1.3)
```

### Weights
- **PoSt pass rate — 40%**: are you actually still holding the data you claim
- **PoC quality — 20%**: coverage event quality and witness count
- **Uptime ratio — 20%**: how continuously you're online
- **Serve ratio — 10%**: retrieval requests you actually served
- **Inverse latency — 10%**: how fast you served them

### What it means for you
The multiplier `m` runs **0.7× to 1.3×** — a well-run node earns nearly double a marginal one on identical hardware. Faults, VPN or datacenter IPs, and downtime all subtract. Software nodes cap at 0.9×; Ego Devices can reach the full 1.3× because they can prove coverage in hardware."#

    } else if q.contains("gossipsub") || q.contains("libp2p") || q.contains("networking") || q.contains("peer discovery") || q.contains("kademlia") || q.contains("cellular") {
        r#"Ego runs **libp2p over QUIC/UDP**, with Kademlia DHT peer discovery and GossipSub v1.2 for message propagation.

### Per-shard topics
```
ego/{shard_id}/tx           // pending transactions
ego/{shard_id}/headers      // block proposals (Dilithium-2 signed)
ego/{shard_id}/consensus    // BFT votes + QCs
ego/{shard_id}/proofs       // PoSt/PoRep events
ego/global/finality         // epoch finality commits
ego/global/rollup           // L2 rollup commits
```

### Admission
Peers must present a valid Dilithium-2 device certificate to join. Every `PeerAnnounce` goes through a 10-point signature check including a hardware-bound `machine_id`, which is what makes Sybil peers expensive.

### NAT traversal
Any node with a public IP automatically becomes a circuit relay, discovered through the DHT. There's no central relay server to depend on — nodes behind strict NATs route through whichever peers are reachable.

### Cellular-safe defaults
Heavy uploads are routed to Wi-Fi or Ethernet while control messages use cellular, with a monthly cap enforced in the client. Running a node on a metered connection won't quietly burn your data plan."#

    } else if q.contains("run a node") || q.contains("node type") || q.contains("join the network") || q.contains("how do i join") || q.contains("light client") || q.contains("full node") {
        r#"Anyone can run an ego-node today. Hardware-attested validator status arrives with Ego Devices.

### Start one
```
git clone https://github.com/ego-blockchain/ego-blockchain
cd ego-blockchain
cargo build -p ego-node --release

# Full node (P2P 9000, HTTP RPC 8545)
./target/release/ego-node --type full --port 9000

# Storage-only node (500 GB)
./target/release/ego-node --type storage --storage 500

# Validator (requires staked EGOC)
./target/release/ego-node --type validator --shards 0,1,2
```

### The four node types
- **Validator** — casts Dilithium-2 votes and forms QCs. Needs staked EGOC (1,000 EGOC minimum) plus uptime. Earns the **consensus bucket (25%)**.
- **Storage Provider** — seals sectors, passes WindowPoSt, serves retrievals. Needs locked collateral. Earns the **storage bucket (55%)**.
- **Beacon / Witness** — records 5G RF metrics and submits PoC reports. Needs Ego-certified hardware. Earns the **coverage bucket (20%)**.
- **Light Client** — verifies headers, QCs and state proofs. No staking, read-only. This is what wallets and dApps use.

### HTTP RPC (port 8545)
`GET /health`, `GET /chain/blocks`, `GET /block/:height`, `GET /balance/:address`, `POST /tx/submit`, `GET /chain/transactions`, `GET /node/stats`, `POST /faucet`.

Simplest path of all: just run Ego Desktop. It **is** a node — keep it open and you're participating."#

    } else if q.contains("ego device") || q.contains("5g modem") || has_word(&q, "tpm") || q.contains("hardware node") || q.contains("secure enclave") {
        r#"**Ego Devices** are purpose-built hardware that make running a full node as simple as plugging in a router. Status: in active development.

### What's inside
- **5G modem (Sub-6 + mmWave)** — passive downlink scanner recording RSRP, RSRQ, SINR, PCI, NR-ARFCN into signed WitnessReports. Never transmits on licensed spectrum.
- **NVMe storage array** — dedicated sealed sectors. PoRep sealing and WindowPoSt proving both run on-device.
- **TPM / secure enclave** — non-exportable Dilithium-2 keys generated at manufacture, attested at every P2P handshake. One device = one identity.
- **GNSS receiver** — precise location binding for PoC events, bound to challenge-window nonces so position can't be spoofed without the TPM key.
- **Low-power compute** — fanless ARM SoC, target under 15W at full load.
- **Multi-WAN** — Gigabit Ethernet + Wi-Fi 6E + optional 5G SIM, with heavy proofs over Ethernet and control over cellular.

### Device vs software node
| | Software node | Ego Device |
|---|---|---|
| Consensus rewards | ✅ with staked EGOC | ✅ hardware-attested |
| Storage rewards | ⚠️ partial | ✅ full sealing + proving |
| Coverage rewards | ❌ needs a 5G modem | ✅ built-in scanner |
| Hardware attestation | ❌ | ✅ TPM/SE Dilithium-2 |
| Max DRS multiplier | 0.9× | 1.3× |
| Sybil resistance | software-only | TPM-bound |
| Setup | CLI + config | plug in + mobile app |

Register interest at **egoblockchain.com** to hear when pre-orders open."#

    } else if q.contains("security model") || q.contains("threat") || q.contains("attack") || q.contains("sybil") || q.contains("equivocation") {
        r#"### Byzantine fault tolerance
Up to **f < n/3** malicious validators are tolerated per shard. A valid QC requires **2f+1** Dilithium-2 votes, so a minority can stall progress but can never finalize a false block.

### Equivocation slashing
Double-signing is caught with conflict proofs — two signed votes for different blocks at the same height. Evidence triggers immediate stake slashing and is verifiable by light clients, so nobody has to trust the accuser.

### Sybil storage
PoRep's `replica_id` encodes the node's identity. Two nodes sealing identical data produce cryptographically distinct replicas, so one disk can't impersonate many providers.

### Sybil witness collusion (coverage)
A coverage event needs a minimum of 3 witnesses drawn from ≥2 H3 cells and ≥2 distinct wallets, with no shared IP and no shared on-chain history.

### SDR replay
Co-beacons carry a time-bound signed nonce. Replaying one requires the device's TPM private key, which physically cannot be exported.

### Quantum
Every signature is Dilithium-2 (FIPS 204) and every key exchange is ML-KEM (FIPS 203), from day one. The harvest-now-decrypt-later window is closed rather than deferred — traffic captured today can't be decrypted by a future quantum computer."#

    } else if has_word(&q, "eip") || has_word(&q, "eips") || q.contains("improvement proposal") || q.contains("token standard") || q.contains("ego-20") || q.contains("ego standard") {
        r#"Ego Improvement Proposals (EIPs) are the protocol's standards.

### Core
EGO-1 HotStuff BFT · EGO-2 Proof of Coverage · EGO-3 Sharding · EGO-4 ZK Rollups · EGO-5 Light Client · EGO-6 Fork Choice

### Tokens
EGO-20 Fungible Token · EGO-21 NFT · EGO-22 Multi-Token · EGO-23 Soulbound (SBT)

### DeFi
EGO-30 DEX/AMM · EGO-31 Lending · EGO-32 Stablecoin · EGO-33 Yield Farming

### Infrastructure
EGO-40 WalletConnect · EGO-41 EVM compatibility · EGO-42 Cross-Chain Bridge · EGO-43 Storage · EGO-44 Indexer

### Advanced
EGO-50 MEV Protection · EGO-51 Fee Market · EGO-52 Governance · EGO-53 DID

The **EGO-20 Token** template in the dApp IDE is a working implementation of the fungible token standard — ask me for a contract example to see it."#

    } else if q.contains("walletconnect") || q.contains("wallet connect") || q.contains("pairing uri") || q.contains("connect my wallet") {
        r#"**EGO-25** is Ego's wallet-connection protocol — scan a QR, approve, and sign from your phone or desktop without ever handing the dApp your private key. Inspired by WalletConnect v2, but with Ego-native crypto throughout: Ed25519 connection signing, ML-KEM (Kyber-768) session key encapsulation, AES-256-GCM session traffic. No X25519, no ChaCha20 — quantum-safe from the first handshake.

### How a session forms
1. **dApp generates a pairing URI** — a random 32-byte topic shown as a QR code:
   `egowc://relay.egoblockchain.com?topic=<hex>&sym_key=<hex>&version=2`
   The `sym_key` is a pre-shared AES key for the pairing phase only.
2. **Wallet scans it** — connects to the relay over WebSocket and subscribes to the pairing topic. Both sides now share a channel.
3. **Session proposal** — the dApp sends its Kyber-768 public key; the wallet encapsulates a fresh 32-byte session key and returns the ciphertext. Only the dApp can decapsulate it, so the session key is never transmitted in plaintext.
4. **Approval** — the wallet shows the dApp's name, icon and requested permissions (`ego_sendTransaction`, `ego_signMessage`). You tap Approve and the session settles.
5. **Signing requests** — the dApp sends requests over the encrypted session; you approve or reject each one in the wallet.

Your key never leaves the wallet. The dApp only ever receives signatures."#

    } else if has_word(&q, "evm") || q.contains("solidity") || q.contains("metamask") || q.contains("hardhat") || q.contains("foundry") || q.contains("remix") {
        r#"**EGO-12** embeds a full EVM inside every ego-node. Deploy Solidity contracts unchanged — MetaMask, Hardhat, Foundry, Remix and Ethers.js all work out of the box.

Ego runs the battle-tested `revm` crate (Rust EVM) on the London spec at **chain_id 1399**. Every opcode, precompile and Solidity ABI encoding behaves identically to Ethereum. Urego (WASM) contracts and EVM (Solidity) contracts live on the same chain and can call each other through an ABI bridge.

### What's supported
- **Arithmetic & bitwise** — ADD, MUL, SUB, DIV, MOD, EXP, SHL, SHR (EIP-145)
- **Storage** — SSTORE / SLOAD, persistent across calls and blocks
- **Events** — LOG0 through LOG4, ABI-encoded and queryable by the EGO-14 indexer on port 8546
- **Contract lifecycle** — CREATE2 deterministic deployment, STATICCALL, REVERT with return data, value transfers
- **Gas** — tracked identically to Ethereum; Resource Units = gas × 10 for EGO-5 metering

### Add Ego to MetaMask
RPC `http://localhost:8545`, chain ID **1399**, symbol **EGOC**. Then deploy from Remix in seconds.

### Which should you use?
Urego if you want the small, deterministic, WASM-native path with no toolchain. Solidity if you're porting existing Ethereum code or your team already knows it."#

    } else if q.contains("cross-chain") || q.contains("cross chain") || q.contains("egolock") || q.contains("wrapped token") || q.contains("bridge in") || q.contains("bridge out") {
        r#"**EGO-10** — lock ERC-20 tokens or native ETH on Ethereum, BNB Chain or Polygon and receive wrapped tokens on Ego. Bridge back by burning on Ego and releasing on the source chain.

The bridge is `EgoLock.sol`, deployed on the source chain. A relayer watches for `Locked` events and calls `verify_and_mint` on Ego. Phase 2 replaces the trusted relayer with a Groth16 ZK proof of the lock event — no trusted intermediary at all.

### Bridge in (ETH → Ego)
1. You call `lock()` or `lockETH()` on `EgoLock.sol`. Tokens move into the contract, a monotonic `lockNonce` increments, and a `Locked(sender, amount, token, nonce, ego_dest)` event fires.
2. The relayer sees the event and submits `verify_and_mint` on Ego, minting wrapped tokens to `ego_dest`.
3. You receive wETH / wUSDC / EGUSD on Ego. **EGUSD (EGO-11)** is the bridge-backed stablecoin: 1 EGUSD = 1 USDC locked in EgoLock.

### Bridge out (Ego → ETH)
1. You burn the wrapped tokens on Ego, emitting a `BridgeOut` event with a burn nonce.
2. The relayer calls `unlock()` on `EgoLock.sol`. The `burn_nonce` is checked against `usedBurnNonces` for replay protection, then tokens are released.

### Security
Replay protection via the `usedBurnNonces` mapping — each burn nonce can only unlock once."#

    } else if has_word(&q, "extension") || q.contains("browser wallet") || q.contains("window.ethereum") || q.contains("chrome extension") {
        r#"The **Ego Browser Extension** is a Chrome Manifest V3 wallet that injects a provider into every page, making Ethereum dApps instantly compatible with Ego.

### Injected APIs
- **`window.ego`** — the native provider. `ego_sendTransaction`, `ego_signMessage`, `ego_signTypedData`, all signed with Dilithium-2.
- **`window.ethereum`** — an EIP-1193 compatible shim at chain_id 1399. Existing Ethereum dApps connect without modification.

```js
// Works exactly like MetaMask
const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
const txHash = await window.ethereum.request({
  method: "eth_sendTransaction",
  params: [{ from: accounts[0], to: "0x...", value: "0xDE0B6B3A7640000" }],
});

// Or the native provider for full features
const address = await window.ego.request({ method: "ego_getAccounts" });
```

### Architecture
- `content.js` — injected into every page, creates the two provider proxies
- `background.js` (MV3 service worker) — holds the encrypted keystore, handles signing, talks to ego-node RPC
- `popup.html` / React — account overview, transaction history, network switcher
- `keystore.json` — AES-256-GCM encrypted, in `chrome.storage.local`

Address derivation is byte-compatible with the desktop app, so the same recovery phrase gives the same addresses in both. Build with `npm run build:extension`, then load the `dist/` folder unpacked in Chrome."#

    } else if has_any_word(&q, &["dex", "amm"]) || q.contains("liquidity pool") || q.contains("swap pool") {
        r#"**EGO-30** — a constant-product AMM. Swap EGOC, EGUSD, WBTC and WETH in one on-chain transaction.

Uniswap v2-style `x × y = k`. Liquidity providers deposit token pairs, receive LP tokens proportional to their share, and earn **0.3% of every swap**. Any EGO-20 pair can have a pool.

### The math
```
x × y = k                      // must hold after every swap

amount_in_with_fee = amount_in × 997
amount_out = (amount_in_with_fee × reserve_out)
           / (reserve_in × 1000 + amount_in_with_fee)

price_impact = 1 - (reserve_in / (reserve_in + amount_in))
```

### Testnet pools
- **EGOC / EGUSD** — the primary pair, EGOC priced in the stablecoin
- **EGOC / WBTC** — Bitcoin exposure via wrapped BTC
- **EGOC / WETH** — Ethereum exposure via wrapped ETH
- **EGUSD / WBTC** — stablecoin ↔ BTC for DeFi strategies

### Interface
```
fn add_liquidity(token_a, token_b, amount_a, amount_b) -> u64
fn remove_liquidity(pair, lp_amount) -> (u64, u64)
fn swap_exact_in(token_in, token_out, amount_in, min_out) -> u64
fn swap_exact_out(token_in, token_out, amount_out, max_in) -> u64
fn get_price(token_a, token_b) -> u64    // price × 1e6
```"#

    } else if has_word(&q, "oracle") || q.contains("price feed") {
        r#"**EGO-9** — the on-chain EGOC/USD price feed. On-chain contracts (DEX, lending, real estate) need external prices they can trust, so the oracle aggregates off-chain sources, takes the median, and publishes a signed commitment to the chain every 30 seconds.

### Architecture
- **Data sources** — CoinGecko REST plus the Binance WebSocket tick stream, median across both. No single source can move the price.
- **On-chain commitment** — a signed `PriceFeed` transaction every 30s, verifiable by any contract.
- **REST API** — `GET /price/egoc-usd` on port 8547, CORS-enabled for dApps.
- **Manipulation resistance** — median over N sources plus a TWAP window, so a flash loan can't spike the on-chain price within a single oracle round.

```json
GET /price/egoc-usd
{
  "price": 0.042718,
  "confidence": 0.9994,
  "timestamp": 1742218640,
  "sources": ["coingecko", "binance"],
  "signature": "0xDilithium2Sig..."
}
```

Reading it from a Urego contract:
```urego
let price: u64 = storage.get_u64("oracle:egoc-usd");  // price × 1e6
```

The desktop app also runs a fully decentralized variant: a 21-sample median over the `ego-price-v1` gossip topic, immune to single-node manipulation."#

    } else if q.contains("mobile") || has_any_word(&q, &["android", "ios", "iphone"]) || q.contains("react native") || q.contains("phone app") {
        r#"The **Ego Mobile Wallet** is React Native (Expo SDK 52) for iOS and Android, sharing the TypeScript SDK with the web dApp ecosystem.

All cryptography mirrors the desktop: Ed25519 + Dilithium-2 signing, ML-KEM for Messenger key exchange, AES-256-GCM for file encryption. Keys live in the device secure enclave through Expo SecureStore.

### Parity with desktop
| Feature | Mobile | Desktop |
|---|---|---|
| Send / receive EGOC | ✅ | ✅ |
| QR address display | ✅ | ✅ |
| WalletConnect | ✅ camera scan | ✅ built-in scanner |
| AES-256-GCM file encryption | ✅ | ✅ |
| P2P Messenger (Kyber E2E) | ✅ | ✅ |
| 24-word recovery phrase | ✅ | ✅ |
| Dilithium-2 signing | ✅ | ✅ |
| Hardware key storage | ✅ SecureStore | ✅ OS keychain |
| Deploy Urego contracts | ⏳ planned | ✅ |

### Stack
`@ego-blockchain/sdk` for RPC and tx signing, `expo-secure-store` for keys, `expo-camera` for WalletConnect QR, `@noble/ed25519`, `aes-js`.

Status: active development. TestFlight and Play Store open beta are planned once testnet stabilises."#

    } else if q.contains("testnet deploy") || q.contains("run testnet") || q.contains("deploy testnet") || has_any_word(&q, &["docker", "vps"]) {
        r#"The testnet ships as a self-contained **Docker Compose** stack: a relay/seed node, four validators covering all 16 shards, and an nginx reverse proxy load-balancing across them.

### One-command install (Ubuntu 22.04)
```
curl -sSL https://raw.githubusercontent.com/ego-blockchain/ego-blockchain/main/testnet/deploy-vps.sh | bash
```
That installs docker-compose, git and rustup, builds `ego-node --release`, writes the `ego-testnet` systemd unit, and opens ports 4001, 9000–9004, 8540–8545 and 80.

### Manual
```
git clone https://github.com/ego-blockchain/ego-blockchain
cd ego-blockchain/testnet
./scripts/init.sh      # create data dirs
./scripts/start.sh     # docker compose up -d
./scripts/health.sh    # check all 4 validators
```

### Topology
| Service | P2P | RPC | Shards |
|---|---|---|---|
| relay (seed) | 4001 | 8540 | — |
| validator1 | 9001 | 8541 | 0–7 |
| validator2 | 9002 | 8542 | 8–15 |
| validator3 | 9003 | 8543 | 0–7, 8–11 |
| validator4 | 9004 | 8544 | 4–7, 12–15 |
| nginx | — | 80 | round-robin |

The image is a multi-stage build: `rust:1.85-slim` with clang/libclang for the rusqlite bindgen step, then a slim `debian:bookworm` runtime."#

    } else if q.contains("storage deal") || q.contains("deal lifecycle") || q.contains("windowpost") || q.contains("collateral") {
        r#"Storage deals are enforced on-chain and connect clients with operators. PoRep plus PoSt is what guarantees the data stays stored and stays retrievable.

### Lifecycle
1. **Deal proposal** — the client proposes a CID, size, duration, price per byte-month, and minimum replication factor.
2. **Operator acceptance** — the operator locks collateral (slashed on PoSt failures) and signs with Dilithium-2.
3. **Sealing (PoRep)** — the operator seals the data producing CommD, CommR and a ZK proof, anchored on-chain as a PoRepEvent.
4. **Proving (PoSt)** — every epoch the operator must pass WindowPoSt or earn zero storage rewards. Three misses trigger slashing plus a repair job.
5. **Retrieval** — the client requests by CID; the operator serves chunks with Merkle inclusion proofs against CommR.
6. **Expiry / repair** — the sector is freed at expiry. A mid-deal dropout kicks off a repair job that restores RF=3 with new operators.

Collateral is what makes the promise real: the operator has more to lose by dropping your data than by keeping it."#

    } else if (q.contains("what is ego") || q.contains("about ego") || has_word(&q, "overview") || q.contains("explain ego"))
        && !q.contains("egosafe") && !q.contains("ego ai") && !q.contains("egusd") && !q.contains("ego device") {
        r#"**Ego** is a quantum-safe Layer-1 blockchain written in Rust that pays people for contributing real physical infrastructure — wireless coverage, disk space, and compute.

The internet's infrastructure sits with a handful of centralized companies. Cloud storage gets breached. Wireless networks are gated by carriers. Bitcoin burns energy on artificial puzzles. Ego attacks all three at once:

- **Proof of Coverage** rewards delivering real 5G signal
- **Proof of Spacetime** rewards hosting real data, continuously
- **Urego smart contracts** let any developer deploy on-chain logic without leaving the desktop app

### The essentials
- **Tokens** — EGOC (native, 1 EGOC = 1,000,000 uEGOC) and EGUSD (native USD-pegged stablecoin)
- **Consensus** — HotStuff BFT, 2f+1 quorum, 1–3s finality
- **Crypto** — Ed25519 + Dilithium-2 (post-quantum signing) + Kyber-768 (post-quantum key exchange)
- **Throughput** — 16 shards, 0.1s micro-slots, 100,000 TPS target
- **Supply** — 100,000,000 EGOC maximum, with 100% of fees burned

### Where it's at
Testnet. The desktop app, Urego compiler, HTTP RPC and JS/TS SDK are all live and open-source. Ego Devices (the hardware nodes) are in development.

Ask me about **earning**, **smart contracts**, **consensus**, **tokenomics**, or **what a dApp is**."#

    } else if q.contains("earn") || q.contains("income") || q.contains("profit") || q.contains("reward") {
        "Ego is a DePIN (Decentralized Physical Infrastructure Network) where you can earn stable, **USD-pegged income** through four main channels. All rewards are automatically converted to EGOC at the live market price.

### 1. Decentralized Storage
Share your spare disk space in the **Storage** tab. You earn for every GB used by the network (target: **$0.002 / GB / day**). To keep earning, pass Proof-of-Storage (**PoST**) challenges automatically by keeping the app open.

### 2. Proof-of-Coverage (PoC)
Help map the network's global reach. Simply keep your node online and reachable (no VPN). A 'beacon' fires every 4 minutes, earning you EGOC based on network quality and witnesses (target: **$0.15 / day**).

### 3. Staking & Consensus
Stake at least **1,000 EGOC** in the **Staking** tab to become a validator. You'll earn block rewards (base **0.0832 EGOC**) plus a share of transaction fees. Staking currently offers up to **20%+ APR**.

### 4. GPU & Compute Rental
Turn your computer into a source of income for AI researchers. List your hardware in the **Compute** tab. You set the price, and the system handles the escrowed payments directly to your wallet.

**How to start?**
Just open any of the tabs above to configure your node. Your **Deterministic Reward Score (DRS)** tracks your reliability; maintain high uptime to multiply your total yield!"
    } else if q.contains("founder") || q.contains("artit") || q.contains("muhaxhiri") {
        "Artit Muhaxhiri is the founder of Ego Blockchain. He is a blockchain developer from Kosovo who previously built KosovaCoin and Roboti Besa."
    } else if q.contains("presale") || q.contains("seed") || q.contains("buy") {
        "The Seed Round pre-sale is currently LIVE at $2.00 per EGOC (~18% discount vs. launch price). You can purchase using crypto (BTC, ETH, SOL, etc.) or card via Stripe. You'll receive an encrypted IOU file that will be credited at the Genesis Block."
    } else if q.contains("tokenomics") || q.contains("supply") || q.contains("distribution") {
        "Ego has a maximum supply of 100,000,000 EGOC.\n\nDistribution:\n- 40M Block emissions\n- 20M Liquidity & Treasury\n- 20M Investors / Seed\n- 10M Team\n- 10M Ecosystem\n\nBlock rewards halve every 2 years."
    } else if q.contains("consensus") || q.contains("bft") || q.contains("hotstuff") {
        "Ego uses HotStuff BFT (Byzantine Fault Tolerance) with pipelined view-changes. Instead of energy-heavy mining, a Verifiable Random Function (VRF) secretly and fairly elects a 21-node committee for each block.\n\nTo reach absolute mathematical finality, it requires a 2/3rds supermajority (2f+1 quorum). Because of pipelining, blocks are finalized in exactly 3 steps, meaning transactions are permanently confirmed in seconds."
    } else if q.contains("smart contract") || q.contains("urego") || q.contains("vm") {
        "Ego uses `ego-vm` powered by wasmtime. Smart contracts are written in **Urego**, a custom Rust-inspired language that compiles down to WebAssembly (WASM).\n\n**How it works:**\n1. You write a contract in Urego (e.g., a token, NFT, or AMM).\n2. You compile it to WASM bytecode via the built-in compiler.\n3. You deploy it on-chain with a `deploy` transaction.\n4. Users interact with it using `call` transactions.\n\nContracts run in a highly secure, sandboxed environment with strict fuel metering (gas limits) to prevent infinite loops. Their state is permanently stored in the ledger and secured by BFT consensus."
    } else if q.contains("quantum") || q.contains("crypto") || q.contains("signature") || q.contains("dilithium") {
        "Ego is quantum-safe. It uses a hybrid cryptography system: Ed25519 for classical signing, Dilithium2 (ML-DSA-44) for post-quantum signing, and Kyber768 for post-quantum key encapsulation."
    } else if q.contains("price") || q.contains("usd") || q.contains("egusd") {
        "The estimated launch price of EGOC is $2.45. Ego also features EGUSD, a native stablecoin strictly pegged to 1 USD."
    } else if q.contains("storage") || q.contains("post") || q.contains("files") || q.contains("save") {
        "Ego offers decentralized storage using Proof-of-Storage (PoST). Files are encrypted locally with AES-256-GCM before upload, split into chunks via DHT manifests, and the network enforces a minimum of 2 distributed replicas.\n\nStorage nodes must cryptographically prove they hold your data using a unique replica commitment (`comm_r`) every 6 hours. If they fail, their collateral is slashed!"
    } else if q.contains("stake") || q.contains("staking") || q.contains("apr") {
        "You can stake EGOC to earn rewards and boost your DRS score. The minimum stake to register as a validator is 1,000 EGOC. Base APR is ~20%, with lock bonuses up to +10% for a 365-day lock."
    } else if q.contains("vrf") || q.contains("random") || q.contains("election") {
        "Ego uses a Verifiable Random Function (VRF) for block proposer and committee election. This cryptographically ensures that the 21-node voting committee is selected randomly and fairly, preventing predictability and DDoS attacks."
    } else if q.contains("shard") || q.contains("scale") || q.contains("tps") {
        "Ego scales dynamically up to 256 shards based on the active network size. Using consistent hashing, nodes are assigned to specific shards as Masters or Slaves, parallelizing transaction processing.\n\nThis allows the network to seamlessly grow to handle 100k+ TPS, with automatic cross-shard routing and vacancy healing when nodes drop offline."
    } else if q.contains("compute") || q.contains("gpu") || q.contains("cpu") || q.contains("rent") || q.contains("ai workspace") || q.contains("cluster") || q.contains("train") || q.contains("jupyter") || q.contains("llm chat") {
        "Ego includes a full **DePIN Compute Marketplace** where anyone can rent or provide GPU/CPU hardware.

### For Renters (Compute tab → Rent)
- Browse available GPUs and CPUs from independent providers worldwide.
- Set your duration (30 minutes to 1 year), pay with EGOC — funds go into **on-chain escrow**.
- Open the unified **AI Workspace** to launch apps that run on the remote GPU and open in your browser:
  - **LLM Chat** — run any open-source language model (Mistral, LLaMA, Phi, etc.)
  - **JupyterLab** — full Python notebook environment
  - **Image Generation** — Stable Diffusion / SDXL
  - **Transcribe Audio** — Whisper speech-to-text
- Upload files from your computer directly to the remote GPU for processing.
- If you have **multiple active rentals**, they all appear in one workspace — switch between nodes with tabs. The header shows your **combined** total CPU cores, RAM, and GPUs.
- Payments release **automatically each period**. If the provider goes offline, you get refunded.

### For Providers (Compute tab → Earn)
- List your hardware with a price per hour. Buyers pick duration — you receive EGOC each period.
- Your own listings are hidden from your own marketplace view (no self-rental).
- Sandboxed isolation: Docker containers keep each renter's workload separate when Docker is installed. Falls back to shared host with a visible warning.

### GPU Clusters (Compute tab → Train)
- Book GPUs from **2–200 independent providers** into one private cluster.
- All nodes auto-join a **WireGuard VPN mesh** — one head-node IP for the whole cluster.
- Run **PyTorch distributed training, DeepSpeed, or Ray** across the full cluster.
- Framework options: Ray (auto-started on all nodes) or raw SSH access.
- After termination, clusters appear in history so you can review past jobs.

**Escrow & Safety**: all compute payments use on-chain EGOC escrow. Providers must maintain uptime or the buyer gets a refund."
    } else if q.contains("message") || q.contains("chat") || q.contains("messenger") {
        "Ego Messenger is a P2P end-to-end encrypted chat. It uses Kyber768 for initial key exchange and a Double Ratchet algorithm with AES-256-GCM for forward-secure messaging, delivered via the Kademlia DHT."
    } else if q.contains("egosafe") || q.contains("share") {
        "EgoSafe allows you to securely encrypt and share files. You can generate public links (`egoshare1`) or strictly secure links (`egoshare2`) encrypted exclusively for the recipient using their Kyber768 post-quantum public key."
    } else if q.contains("l2") || q.contains("rollup") || q.contains("stark") || q.contains("zk") {
        "Ego supports Layer-2 ZK-Rollups using STARK proofs for massive scalability. Instead of processing every transaction on the main chain, L2 sequencers bundle thousands of transactions off-chain and submit a single cryptographic proof to the L1.\n\nBecause ZK-STARKs provide mathematical certainty, batches are finalized instantly upon submission without any 'dispute window' or fraud proofs (unlike Optimistic Rollups). This ensures instant finality, minimal fees, and absolute security inherited directly from the L1."
    } else if q.contains("multichain") || q.contains("bridge") || q.contains("swap") {
        "The Ego Desktop wallet natively supports Bitcoin, Ethereum, Solana, Cardano, and more. It includes a built-in cross-chain swap feature powered by ChangeNow to seamlessly trade assets, plus an upcoming native EGOC bridge."
    } else if q.contains("host") || q.contains("website") || q.contains("domain") || q.contains(".eo") {
        "Ego offers decentralized Web3 hosting for static sites and Python Flask apps. Sites are accessible via `.eo` domains (e.g., `mysite.eo`) using the local HTTPS gateway and TLS certificates."
    } else if q.contains("dao") || q.contains("govern") || q.contains("vote") {
        "Ego's DAO uses a unique two-factor voting system: Stake Power (economic weight) and Knowledge Power (score from a proposal-specific quiz). This ensures voters are both invested and informed."
    } else if q.contains("coverage") || q.contains("poc") || q.contains("beacon") {
        "Proof-of-Coverage (PoC) rewards nodes for maintaining high network uptime and reachability. Nodes ping the network, mapping their location to H3 cells, to build a resilient decentralized mesh."
    } else if q.contains("privacy") || q.contains("shielded") || q.contains("private") || q.contains("mask") {
        "Ego uses **Shielded Transactions** to ensure financial privacy. When a transaction is private, the sender and receiver addresses are masked with a **🛡 Shielded** badge on the public ledger.\n\n### Privacy Protections\n- **Identity Masking**: Hides public keys from the Explorer and trackers.\n- **Whale Protection**: Any transaction over **50,000 EGOC** is automatically shielded to prevent profiling.\n- **Tracking Prevention**: No address history search or 'Rich Lists' (Holders) to prevent profiling.\n- **Macro-Transparency**: Shows supply distribution audits instead of individual balances.\n- **ZK-Enforced**: Uses Zero-Knowledge logic to verify validity without exposing metadata."
    } else {
        r#"I am Ego AI. Ask me anything about Ego Blockchain — here's what I cover.

### Build
**what is a dApp** · **dApp IDE** · **contract example** · **why use Urego** · **how to deploy a contract** · EVM & Solidity · TypeScript SDK · browser extension · WalletConnect

### Earn
**how do I earn** · staking & APR · Proof of Coverage · Proof of Storage · PoRep · DRS reward scoring · GPU compute rental · storage deals

### Protocol
architecture & layers · consensus (HotStuff BFT) · sharding & TPS · block specification · transactions & Resource Units · networking · security model · EIPs · quantum-safe crypto

### Network & money
tokenomics · EGOC & EGUSD · DEX & AMM · oracle price feed · cross-chain bridge · DAO governance · privacy & shielded transactions

### Run it
run a node · node types · testnet deployment · Ego Devices · mobile wallet · Messenger · EgoSafe

New here? Try **"what is Ego"**, **"what is a dApp"**, or **"show me a contract example"**."#
    };

    // Simulate slight typing delay for realism
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    Ok(response.to_string())
}

#[tauri::command]
pub fn save_ai_key(key: String) -> Result<(), String> {
    fs::write(ai_key_path(), key.trim()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_ai_key_status() -> bool {
    // Always return true so the frontend never asks for an API key
    true
}

#[cfg(test)]
mod ai_routing_tests {
    use super::*;

    async fn ask(question: &str) -> String {
        ask_ego_ai(question.to_string(), Vec::new()).await.unwrap()
    }

    /// The reason has_word exists: substring matching on short topic keywords
    /// sends "can you provide..." to the dApp IDE answer.
    #[test]
    fn short_keywords_match_whole_words_only() {
        assert!(has_word("open the dapp ide please", "ide"));
        assert!(!has_word("can you provide more detail", "ide"));
        assert!(!has_word("a quick guide to staking", "ide"));
        assert!(!has_word("show me the video", "ide"));
        assert!(has_word("what is a dapp", "dapp"));
        assert!(!has_word("what is a dapple", "dapp"));
    }

    #[tokio::test]
    async fn contract_questions_reach_their_own_answers() {
        assert!(ask("show me a contract example").await.contains("contract MyToken"));
        assert!(ask("give me an example of a urego token").await.contains("contract MyToken"));
        assert!(ask("what is the dapp ide").await.contains("Monaco"));
        assert!(ask("how do i deploy a contract").await.contains("Route A"));
        assert!(ask("why use urego").await.contains("Why Urego specifically"));
        assert!(ask("what is a dapp").await.contains("decentralized application"));
    }

    /// "dapp ide" and "urego example" both contain keywords the broader
    /// answers match — the specific ones have to win.
    #[tokio::test]
    async fn specific_answers_win_over_general_ones() {
        let ide = ask("how do i use the dapp ide to write urego").await;
        assert!(ide.contains("Monaco"), "dapp ide lost to the urego answer");

        let dapp = ask("what is a dapp").await;
        assert!(!dapp.contains("Monaco"), "general dapp question hit the IDE answer");
    }

    #[tokio::test]
    async fn unrelated_questions_do_not_hit_contract_answers() {
        let staking = ask("can you provide the staking apr").await;
        assert!(!staking.contains("Monaco"), "'provide' matched the IDE keyword");

        let earn = ask("how do i earn rewards").await;
        assert!(earn.contains("DePIN"), "earning question was stolen by a new branch");
    }

    #[tokio::test]
    async fn new_protocol_topics_are_answered() {
        assert!(ask("explain the architecture layers").await.contains("Layer 3"));
        assert!(ask("what is drs").await.contains("Deterministic Reward Scoring"));
        assert!(ask("what is porep").await.contains("replica uniqueness"));
        assert!(ask("what is in a block header").await.contains("state_root"));
        assert!(ask("how do i run a node").await.contains("ego-node"));
        assert!(ask("tell me about the oracle price feed").await.contains("egoc-usd"));
    }
}
