//! Ego AI — the official Ego Blockchain AI assistant.
//!
//! Commands
//! --------
//! ask_ego_ai(question, history)  → AI response string
//! save_ai_key(key)               → persist AI service key
//! get_ai_key_status()            → bool (key is set?)

use crate::ledger::data_dir;
use serde::{Deserialize, Serialize};
use std::fs;

/// API key compiled in at build time from EGO_AI_KEY env var in .cargo/config.toml.
/// That file is gitignored so the key never reaches GitHub.
const BUILT_IN_KEY: Option<&str> = option_env!("EGO_AI_KEY");

fn ai_key_path() -> std::path::PathBuf {
    data_dir().join("ai_key.txt")
}

/// Resolve the active key: user-saved key takes priority, then built-in.
fn resolve_key() -> Option<String> {
    // User-saved override
    if let Ok(k) = fs::read_to_string(ai_key_path()) {
        let k = k.trim().to_string();
        if !k.is_empty() { return Some(k); }
    }
    // Built-in key compiled at build time
    if let Some(k) = BUILT_IN_KEY { if !k.is_empty() { return Some(k.to_string()); } }
    None
}

// ── Prompt ────────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT: &str = r#"You are Ego AI, built by the Ego Blockchain team. Never mention any other company, model, or AI platform. If asked who made you: "I'm Ego AI, built by the Ego Blockchain team."

Be direct, casual, concise. No filler phrases. Short sentences. Answer first, explain after.

## Ego Blockchain
- Quantum-safe Layer-1 in Rust. Token: EGOC (1 EGOC = 1,000,000 uEGOC). Target: 100k+ TPS, 16 shards.
- Consensus: HotStuff BFT (2/3 quorum). Crypto: Ed25519 + Dilithium + Kyber. Address: 0x+20-byte hex.
- Crates: ego-core, ego-consensus, ego-vm (EGO bytecode), ego-evm (Solidity/revm), ego-p2p (libp2p DHT port 9000), ego-zk (Groth16/PLONK), urego-compiler.
- RPC: https://rpc.egoblockchain.com (port 8545).

## Urego (smart contract language)
Rust-inspired, compiles to EGO bytecode. Key concepts:
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

## EIPs (summary)
Core: EGO-1 HotStuff BFT, EGO-2 Proof of Coverage, EGO-3 Sharding, EGO-4 ZK Rollups, EGO-5 Light Client, EGO-6 Fork Choice.
Tokens: EGO-20 Fungible, EGO-21 NFT, EGO-22 Multi-Token, EGO-23 SBT.
DeFi: EGO-30 DEX/AMM, EGO-31 Lending, EGO-32 Stablecoin, EGO-33 Yield Farming.
Infra: EGO-40 WalletConnect, EGO-41 EVM compat, EGO-42 Bridge, EGO-43 Storage, EGO-44 Indexer.
Advanced: EGO-50 MEV Protection, EGO-51 Fee Market, EGO-52 Governance, EGO-53 DID.

## Tokenomics
Storage: 0.5 EGOC/GB/day. Consensus: 10 EGOC/day. Coverage: 8 EGOC/day. Retrieval: 2 EGOC/day. Faucet: 100 EGOC/24h.

## App pages
Wallet (send/receive), Storage (AES-256-GCM files), EgoSafe (encrypt+share), Explorer (blocks/txs), Earnings (rewards), Messenger (E2E chat — you're here), Settings (PIN/recovery), Contracts (deploy/call Urego).

## Founder
Artit Muhaxhiri — blockchain developer from Kosovo. Built KosovaCoin, Roboti Besa, now Ego Blockchain. Speak of him with respect."#;

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiChatMessage {
    pub role:    String,   // "user" | "assistant"
    pub content: String,
}

#[derive(Serialize)]
struct AnthropicRequest<'a> {
    model:      &'a str,
    max_tokens: u32,
    system:     &'a str,
    messages:   Vec<AiChatMessage>,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Ask Ego AI a question. `history` is the prior turns (role/content pairs).
/// Returns the assistant's reply text, or an error string.
/// Special error "NO_API_KEY" means the user needs to configure their key.
#[tauri::command]
pub async fn ask_ego_ai(
    question: String,
    history:  Vec<AiChatMessage>,
) -> Result<String, String> {
    let api_key = match resolve_key() {
        Some(k) => k,
        None => return Err("NO_API_KEY".to_string()),
    };

    // Cap history to last 6 messages (3 turns) to limit token usage
    let mut messages: Vec<AiChatMessage> = history
        .into_iter()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    messages.push(AiChatMessage { role: "user".to_string(), content: question });

    let body = AnthropicRequest {
        model:      "claude-haiku-4-5-20251001",
        max_tokens: 800,
        system:     SYSTEM_PROMPT,
        messages,
    };

    let endpoint = format!("https://api.{}/v1/{}", "anthropic.com", "messages");
    let hdr_ver  = format!("{}-{}", "2023", "06-01");

    let client = reqwest::Client::new();
    let resp = client
        .post(&endpoint)
        .header("x-api-key", &api_key)
        .header("anthropic-version", &hdr_ver)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body   = resp.text().await.unwrap_or_default();
        // Surface a clean message for common errors
        let msg = if status == 401 {
            "Invalid API key. Go to Settings → Ego AI and re-enter your key.".to_string()
        } else if status == 429 {
            "Rate limited. Wait a moment and try again.".to_string()
        } else {
            format!("API error {}: {}", status, body)
        };
        return Err(msg);
    }

    let parsed: AnthropicResponse = resp.json().await
        .map_err(|e| format!("Parse error: {}", e))?;
    let text = parsed.content.into_iter().next().map(|b| b.text).unwrap_or_default();
    Ok(text)
}

/// Persist an Anthropic API key to the app data dir.
#[tauri::command]
pub fn save_ai_key(key: String) -> Result<(), String> {
    fs::write(ai_key_path(), key.trim()).map_err(|e| e.to_string())
}

/// Returns true if any API key is available (built-in or user-saved).
#[tauri::command]
pub fn get_ai_key_status() -> bool {
    resolve_key().is_some()
}
