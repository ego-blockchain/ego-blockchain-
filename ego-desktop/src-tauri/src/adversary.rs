use crate::ledger::{LedgerBlock, LedgerTx};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehaviour {
    TamperMerkleRoot,
    InflateCoinbase,
    ForgeSystemTransfer,
    ForgeSignature,
    Equivocate,
    DoubleVote,
    WithholdVotes,
    MalformedGossip,
}

impl Misbehaviour {
    fn parse(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "tamper-merkle-root" => Self::TamperMerkleRoot,
            "inflate-coinbase" => Self::InflateCoinbase,
            "forge-system-transfer" => Self::ForgeSystemTransfer,
            "forge-signature" => Self::ForgeSignature,
            "equivocate" => Self::Equivocate,
            "double-vote" => Self::DoubleVote,
            "withhold-votes" => Self::WithholdVotes,
            "malformed-gossip" => Self::MalformedGossip,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::TamperMerkleRoot => "tamper-merkle-root",
            Self::InflateCoinbase => "inflate-coinbase",
            Self::ForgeSystemTransfer => "forge-system-transfer",
            Self::ForgeSignature => "forge-signature",
            Self::Equivocate => "equivocate",
            Self::DoubleVote => "double-vote",
            Self::WithholdVotes => "withhold-votes",
            Self::MalformedGossip => "malformed-gossip",
        }
    }

    pub fn all() -> &'static [Misbehaviour] {
        &[
            Self::TamperMerkleRoot,
            Self::InflateCoinbase,
            Self::ForgeSystemTransfer,
            Self::ForgeSignature,
            Self::Equivocate,
            Self::DoubleVote,
            Self::WithholdVotes,
            Self::MalformedGossip,
        ]
    }
}

fn configured() -> &'static Vec<Misbehaviour> {
    static CONFIG: OnceLock<Vec<Misbehaviour>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let Ok(raw) = std::env::var("EGO_ADVERSARY") else { return Vec::new() };
        let chosen: Vec<Misbehaviour> = raw.split(',').filter_map(Misbehaviour::parse).collect();
        if !chosen.is_empty() {
            let names: Vec<&str> = chosen.iter().map(|m| m.name()).collect();
            eprintln!(
                "[Adversary] THIS NODE IS DELIBERATELY DISHONEST: {}. Never run this on a chain that matters.",
                names.join(", ")
            );
            tracing::error!("[Adversary] misbehaving on purpose: {}", names.join(", "));
        }
        chosen
    })
}

pub fn enabled() -> bool {
    !configured().is_empty()
}

pub fn is_active(m: Misbehaviour) -> bool {
    configured().contains(&m)
}

pub fn tamper_merkle_root(block: &mut LedgerBlock) {
    let mut root = block.tx_merkle_root.clone();
    if root.is_empty() {
        root = "0".repeat(64);
    }
    let mut chars: Vec<char> = root.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    block.tx_merkle_root = chars.into_iter().collect();
}

pub fn inflate_coinbase(coinbase: &mut LedgerTx, to: &str, amount_uegoc: u64) {
    coinbase.to = to.to_string();
    coinbase.amount = amount_uegoc;
}

pub fn forged_system_transfer(to: &str, amount_uegoc: u64) -> LedgerTx {
    LedgerTx {
        hash: format!("0x{}", "ad".repeat(32)),
        from: crate::chain_db::NODE_POOL_ADDR.to_string(),
        to: to.to_string(),
        amount: amount_uegoc,
        tx_type: "transfer".into(),
        fee_uegoc: 0,
        timestamp: chrono::Utc::now().timestamp(),
        ..LedgerTx::default()
    }
}

pub fn forge_signature(tx: &mut LedgerTx, new_amount: u64) {
    tx.amount = new_amount;
}

pub fn equivocating_twin(block: &LedgerBlock) -> LedgerBlock {
    let mut twin = block.clone();
    twin.timestamp = block.timestamp.wrapping_add(1);
    twin.hash = format!("{}f", &block.hash[..block.hash.len().saturating_sub(1)]);
    twin
}

pub fn malformed_gossip() -> Vec<u8> {
    let mut v = b"{\"TxBroadcast\":{\"tx\":".to_vec();
    v.extend_from_slice(&[0xff, 0xfe, 0x00, 0x01]);
    v.extend_from_slice(b"\"unterminated");
    v
}

pub fn corrupt_proposal(block: &mut LedgerBlock, txs: &mut Vec<LedgerTx>) -> bool {
    if !enabled() {
        return false;
    }
    let mut touched = false;
    if is_active(Misbehaviour::TamperMerkleRoot) {
        tamper_merkle_root(block);
        touched = true;
    }
    if is_active(Misbehaviour::InflateCoinbase) {
        if let Some(hash) = block.coinbase_tx.clone() {
            if let Some(cb) = txs.iter_mut().find(|t| t.hash == hash) {
                let me = cb.to.clone();
                inflate_coinbase(cb, &me, u64::MAX / 2);
                block.reward = cb.amount;
                touched = true;
            }
        }
    }
    if is_active(Misbehaviour::ForgeSystemTransfer) {
        let me = block.miner.clone();
        txs.push(forged_system_transfer(&me, 1_000_000_000_000));
        touched = true;
    }
    if is_active(Misbehaviour::ForgeSignature) {
        if let Some(tx) = txs.iter_mut().find(|t| Some(&t.hash) != block.coinbase_tx.as_ref()) {
            forge_signature(tx, tx.amount.saturating_add(1_000_000));
            touched = true;
        }
    }
    if touched {
        eprintln!("[Adversary] proposing a deliberately invalid block #{}", block.height);
    }
    touched
}

pub fn should_withhold_vote() -> bool {
    enabled() && is_active(Misbehaviour::WithholdVotes)
}

pub fn should_double_vote() -> bool {
    enabled() && is_active(Misbehaviour::DoubleVote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_is_off_unless_the_environment_asks_for_it() {
        assert!(!enabled(), "a node must never attack unless explicitly told to");
        for m in Misbehaviour::all() {
            assert!(!is_active(*m));
        }
        assert!(!should_withhold_vote());
        assert!(!should_double_vote());
    }

    #[test]
    fn every_behaviour_round_trips_through_its_name() {
        for m in Misbehaviour::all() {
            assert_eq!(Misbehaviour::parse(m.name()), Some(*m), "{}", m.name());
        }
        assert_eq!(Misbehaviour::parse("be-nice"), None);
        assert_eq!(Misbehaviour::parse(""), None);
    }

    #[test]
    fn a_tampered_merkle_root_fails_block_hash_verification() {
        let mut block = LedgerBlock {
            height: 5,
            prev_hash: "aa".repeat(32),
            miner: "egot1miner".into(),
            timestamp: 1_700_000_000,
            tx_merkle_root: "bb".repeat(32),
            poc_ticket: "ticket".into(),
            state_root: "cc".repeat(32),
            ..LedgerBlock::default()
        };
        block.hash = crate::chain_db::block_hash_for(
            &block.prev_hash,
            block.height,
            &block.miner,
            block.timestamp,
            &block.tx_merkle_root,
            &block.poc_ticket,
        );
        assert!(crate::chain_db::verify_block_hash(&block, &[]), "the honest block verifies");

        tamper_merkle_root(&mut block);
        assert!(
            !crate::chain_db::verify_block_hash(&block, &[]),
            "a block whose contents were swapped after hashing must be refused"
        );
    }

    #[test]
    fn a_forged_system_transfer_is_refused() {
        let tx = forged_system_transfer("egot1attacker", 1_000_000_000_000);
        assert!(crate::ledger::is_reserved_system_source(&tx.from));
        assert!(
            !crate::ledger::is_protocol_system_tx(&tx),
            "a plain transfer from the node pool is not a protocol transaction"
        );
        let err = crate::ledger::verify_incoming_tx(&tx).unwrap_err();
        assert!(
            err.contains("system-source") || err.contains("block-context"),
            "expected the system-source rule to refuse it, got: {err}"
        );
    }

    #[test]
    fn a_transaction_altered_after_signing_is_refused() {
        let mut tx = LedgerTx {
            hash: format!("0x{}", "ab".repeat(32)),
            from: "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k".into(),
            to: "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7l".into(),
            amount: 1_000,
            fee_uegoc: 1_000,
            nonce: 1,
            tx_version: 2,
            chain_id: 1,
            public_key_ed25519: "cd".repeat(32),
            signature: "ef".repeat(64),
            ..LedgerTx::default()
        };
        forge_signature(&mut tx, 999_999_999);
        assert!(
            crate::ledger::verify_incoming_tx(&tx).is_err(),
            "a transaction whose amount changed after signing must not verify"
        );
    }

    #[test]
    fn an_equivocating_twin_is_a_different_block_at_the_same_height() {
        let block = LedgerBlock {
            height: 9,
            hash: "aa".repeat(32),
            prev_hash: "bb".repeat(32),
            miner: "egot1miner".into(),
            timestamp: 1_700_000_000,
            ..LedgerBlock::default()
        };
        let twin = equivocating_twin(&block);
        assert_eq!(twin.height, block.height);
        assert_ne!(twin.hash, block.hash, "the twin must be a distinct block");
    }

    #[test]
    fn an_inflated_coinbase_changes_what_the_block_pays_out() {
        let mut cb = LedgerTx {
            hash: "0xcb".into(),
            from: crate::chain_db::NODE_POOL_ADDR.into(),
            to: "egot1honestminer".into(),
            amount: 50_000,
            signature: "coinbase".into(),
            tx_type: "coinbase".into(),
            ..LedgerTx::default()
        };
        inflate_coinbase(&mut cb, "egot1attacker", u64::MAX / 2);
        assert_eq!(cb.to, "egot1attacker");
        assert!(cb.amount > 50_000);
        assert!(crate::ledger::is_protocol_system_tx(&cb));
    }

    #[test]
    fn malformed_gossip_is_not_a_message_this_network_speaks() {
        let bytes = malformed_gossip();
        assert!(serde_json::from_slice::<crate::p2p::P2PMessage>(&bytes).is_err());
    }

    #[test]
    fn an_honest_node_proposes_exactly_what_it_built() {
        let mut block = LedgerBlock { height: 3, ..LedgerBlock::default() };
        let before = block.clone();
        let mut txs = vec![LedgerTx { hash: "0x1".into(), amount: 5, ..LedgerTx::default() }];
        assert!(!corrupt_proposal(&mut block, &mut txs));
        assert_eq!(block.height, before.height);
        assert_eq!(block.tx_merkle_root, before.tx_merkle_root);
        assert_eq!(block.reward, before.reward);
        assert_eq!(txs.len(), 1, "no transaction may be added to an honest proposal");
        assert_eq!(txs[0].amount, 5, "nor altered");
        assert_eq!(txs[0].hash, "0x1");
    }
}
