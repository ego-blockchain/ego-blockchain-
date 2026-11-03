use crate::dao_chain::Fit;
use crate::drs::Ov;
use crate::ledger::{LedgerBlock, LedgerTx};
use std::collections::BTreeMap;

#[cfg(not(test))]
pub const PIN_FROM: Option<u64> = Some(70623);
#[cfg(not(test))]
pub const REQUIRE_PINNED_FROM: Option<u64> = None;
#[cfg(test)]
pub const PIN_FROM: Option<u64> = Some(1);
#[cfg(test)]
pub const REQUIRE_PINNED_FROM: Option<u64> = Some(1_000);

fn active(from: Option<u64>, height: u64) -> bool {
    from.is_some_and(|h| height >= h)
}

pub fn pin_active(height: u64) -> bool {
    active(PIN_FROM, height)
}

pub fn require_pinned_active(height: u64) -> bool {
    pin_active(height) && active(REQUIRE_PINNED_FROM, height)
}

fn pin_key(addr: &str) -> Vec<u8> {
    format!("pq:{addr}").into_bytes()
}

pub fn key_hash(pubkey_hex: &str) -> Option<[u8; 32]> {
    let pk = hex::decode(pubkey_hex).ok()?;
    (!pk.is_empty()).then(|| *blake3::hash(&pk).as_bytes())
}

pub fn pinned(ov: &Ov, addr: &str) -> Option<[u8; 32]> {
    ov.get(&pin_key(addr)).and_then(|v| v.as_slice().try_into().ok())
}

fn subject(tx: &LedgerTx) -> bool {
    !tx.from.is_empty()
        && !crate::ledger::is_reserved_system_source(&tx.from)
        && tx.signature != "coinbase"
        && !crate::hold_chain::is_settle(tx)
        && !crate::drs::is_batch_tx(tx)
}

fn carries_dilithium(tx: &LedgerTx) -> bool {
    !tx.dilithium_pubkey.is_empty() || !tx.dilithium_signature.is_empty()
}

fn dilithium_valid(tx: &LedgerTx) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(&tx.dilithium_pubkey), hex::decode(&tx.dilithium_signature)) else { return false };
    ego_core::dilithium_verify(&pk, &crate::ledger::tx_signing_bytes_for(tx), &sig).unwrap_or(false)
}

pub fn check(pin: Option<[u8; 32]>, tx: &LedgerTx, height: u64) -> Result<Option<[u8; 32]>, String> {
    if !subject(tx) {
        return Ok(None);
    }
    if carries_dilithium(tx) {
        if !dilithium_valid(tx) {
            return Err("its Dilithium signature does not verify".into());
        }
        let h = key_hash(&tx.dilithium_pubkey).ok_or("its Dilithium key is unreadable")?;
        return match pin {
            Some(p) if p != h => Err("it is signed with a Dilithium key that is not this wallet's pinned key".into()),
            Some(_) => Ok(None),
            None => Ok(Some(h)),
        };
    }
    if pin.is_some() && require_pinned_active(height) {
        return Err("this wallet's Dilithium key is pinned, so its transactions need a Dilithium signature".into());
    }
    Ok(None)
}

pub struct Planner {
    height: u64,
    pins: BTreeMap<String, [u8; 32]>,
}

impl Planner {
    pub fn new(height: u64) -> Self {
        Self { height, pins: BTreeMap::new() }
    }

    pub fn fit(&mut self, ov: &Ov, tx: &LedgerTx) -> Fit {
        if !pin_active(self.height) {
            return Fit::Yes;
        }
        self.judge(ov, tx)
    }

    fn judge(&mut self, ov: &Ov, tx: &LedgerTx) -> Fit {
        let pin = self.pins.get(&tx.from).copied().or_else(|| pinned(ov, &tx.from));
        match check(pin, tx, self.height) {
            Ok(Some(h)) => {
                self.pins.insert(tx.from.clone(), h);
                Fit::Yes
            }
            Ok(None) => Fit::Yes,
            Err(e) => Fit::Never(e),
        }
    }
}

pub fn validate(ov: &Ov, block: &LedgerBlock, txs: &[LedgerTx]) -> Result<(), String> {
    let mut plan = Planner::new(block.height);
    for tx in txs {
        if let Fit::Never(e) | Fit::Later(e) = plan.fit(ov, tx) {
            return Err(format!("tx {} refused: {e}", tx.hash));
        }
    }
    Ok(())
}

pub fn apply_block(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx]) {
    if pin_active(block.height) {
        apply_effects(ov, block, txs);
    }
}

pub(crate) fn apply_effects(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx]) {
    let mut plan = Planner::new(block.height);
    for tx in txs {
        let _ = plan.judge(ov, tx);
    }
    for (addr, h) in plan.pins {
        if pinned(ov, &addr).is_none() {
            ov.put(pin_key(&addr), h.to_vec());
        }
    }
}

pub fn admit(tx: &LedgerTx) -> Result<(), String> {
    let height = crate::chain_db::local_chain_height().saturating_add(1);
    if !pin_active(height) {
        return Ok(());
    }
    let ov = Ov::new(crate::chain_db::global_db());
    check(pinned(&ov, &tx.from), tx, height).map(|_| ()).map_err(|e| format!("PQ_KEY: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(kp: &ego_core::KeyPair, nonce: u64, with_dilithium: bool) -> LedgerTx {
        let from = crate::vault_chain::address_of(kp.ed25519_public_key().as_bytes().try_into().unwrap(), 1);
        let mut tx = LedgerTx {
            from: from.clone(),
            to: "egot1someoneelsesomeoneelsesomeoneelsesomeone".into(),
            amount: 5,
            nonce,
            timestamp: 1_800_000_000,
            fee_uegoc: 1_000,
            chain_id: 1,
            tx_type: "transfer".into(),
            tx_version: 3,
            ..LedgerTx::default()
        };
        crate::ledger::seal_tx(&mut tx, kp, with_dilithium);
        tx
    }

    fn with_foreign_dilithium(mut tx: LedgerTx, other: &ego_core::KeyPair) -> LedgerTx {
        let msg = crate::ledger::tx_signing_bytes_for(&tx);
        tx.dilithium_pubkey = hex::encode(&other.dilithium_public_key().key_data);
        tx.dilithium_signature = hex::encode(&other.sign_dilithium(&msg).signature_data);
        tx
    }

    fn run(ov: &mut Ov<'static>, txs: &[LedgerTx]) {
        let refs: Vec<&LedgerTx> = txs.iter().collect();
        apply_effects(ov, &LedgerBlock { height: 10, ..LedgerBlock::default() }, &refs);
        ov.commit_memory();
    }

    fn judge(ov: &Ov, txs: &[LedgerTx]) -> Result<(), String> {
        let mut plan = Planner::new(10);
        for tx in txs {
            if let Fit::Never(e) | Fit::Later(e) = plan.judge(ov, tx) {
                return Err(e);
            }
        }
        Ok(())
    }

    #[test]
    fn the_first_dilithium_signature_pins_the_wallets_key() {
        let owner = ego_core::KeyPair::from_bytes(&[11u8; 32]).unwrap();
        let mut ov = Ov::memory();
        let first = signed(&owner, 1, true);
        assert!(judge(&ov, std::slice::from_ref(&first)).is_ok());
        run(&mut ov, std::slice::from_ref(&first));
        assert_eq!(pinned(&ov, &first.from), key_hash(&first.dilithium_pubkey));
        assert!(judge(&ov, &[signed(&owner, 2, true)]).is_ok(), "the same key keeps working");
    }

    #[test]
    fn a_foreign_dilithium_key_is_refused_once_the_wallet_is_pinned() {
        let owner = ego_core::KeyPair::from_bytes(&[11u8; 32]).unwrap();
        let attacker = ego_core::KeyPair::from_bytes(&[12u8; 32]).unwrap();
        let mut ov = Ov::memory();
        run(&mut ov, &[signed(&owner, 1, true)]);
        let forged = with_foreign_dilithium(signed(&owner, 2, true), &attacker);
        assert!(judge(&ov, &[forged]).is_err(), "a valid signature from another Dilithium key does not count");
    }

    #[test]
    fn two_keys_for_one_wallet_in_one_block_are_refused() {
        let owner = ego_core::KeyPair::from_bytes(&[11u8; 32]).unwrap();
        let attacker = ego_core::KeyPair::from_bytes(&[12u8; 32]).unwrap();
        let ov = Ov::memory();
        let a = signed(&owner, 1, true);
        let b = with_foreign_dilithium(signed(&owner, 2, true), &attacker);
        assert!(judge(&ov, &[a, b]).is_err());
    }

    #[test]
    fn a_dilithium_signature_that_does_not_verify_is_refused() {
        let owner = ego_core::KeyPair::from_bytes(&[11u8; 32]).unwrap();
        let mut tx = signed(&owner, 1, true);
        tx.amount = 6;
        tx.signature = hex::encode(owner.sign_ed25519(&crate::ledger::tx_signing_bytes_for(&tx)).as_bytes());
        assert!(judge(&Ov::memory(), &[tx]).is_err());
    }

    #[test]
    fn ed25519_alone_still_works_until_pinned_wallets_must_sign_with_dilithium() {
        let owner = ego_core::KeyPair::from_bytes(&[11u8; 32]).unwrap();
        let mut ov = Ov::memory();
        assert!(judge(&ov, &[signed(&owner, 1, false)]).is_ok(), "an unpinned wallet may sign with Ed25519 alone");
        run(&mut ov, &[signed(&owner, 1, true)]);
        assert!(judge(&ov, &[signed(&owner, 2, false)]).is_ok(), "the second rule is still off");
        let plain = signed(&owner, 2, false);
        assert!(check(pinned(&ov, &plain.from), &plain, 1_000).is_err(), "from the second rule a pinned wallet must sign with Dilithium");
        let stranger = signed(&ego_core::KeyPair::from_bytes(&[13u8; 32]).unwrap(), 1, false);
        assert!(check(pinned(&ov, &stranger.from), &stranger, 1_000).is_ok(), "an unpinned wallet still may sign with Ed25519 alone");
    }
}
