#[path = "../../../../ego-desktop/src-tauri/src/escrow/solana.rs"]
#[allow(dead_code)]
mod tx;

use ed25519_dalek::SigningKey;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_transaction::Transaction;
use tx::*;

const SOL: u64 = 1_000_000_000;
const DAY: u64 = 86_400;
const FALLBACK: u64 = 30 * DAY;

type Sent = Result<TransactionMetadata, FailedTransactionMetadata>;

fn addr(k: &Key) -> Address {
    Address::new_from_array(*k)
}

fn pk(sk: &SigningKey) -> Key {
    sk.verifying_key().to_bytes()
}

fn so_path() -> String {
    std::env::var("EGO_ESCROW_SO")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/ego_escrow.so").to_string())
}

fn mint_data(authority: &Key, decimals: u8, supply: u64) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[0..4].copy_from_slice(&1u32.to_le_bytes());
    d[4..36].copy_from_slice(authority);
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = decimals;
    d[45] = 1;
    d
}

fn token_data(mint: &Key, owner: &Key, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
    d[0..32].copy_from_slice(mint);
    d[32..64].copy_from_slice(owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

fn code(r: &Sent) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("{:?}", e.err),
    }
}

fn custom(r: &Sent, n: u32) -> bool {
    code(r).contains(&format!("Custom({n})"))
}

struct World {
    svm: LiteSVM,
    program: Key,
    seller: SigningKey,
    buyer: SigningKey,
    arbiter: SigningKey,
    fee: SigningKey,
    stranger: SigningKey,
    mint: Key,
    next_trade: u8,
}

impl World {
    fn new() -> World {
        let mut svm = LiteSVM::new();
        let program = [0x42; 32];
        svm.add_program(addr(&program), &std::fs::read(so_path()).expect("build the program first"))
            .unwrap();
        let w = |b: u8| SigningKey::from_bytes(&[b; 32]);
        let mut world = World {
            svm,
            program,
            seller: w(1),
            buyer: w(2),
            arbiter: w(3),
            fee: w(4),
            stranger: w(5),
            mint: [0x77; 32],
            next_trade: 0,
        };
        for k in [&world.seller, &world.buyer, &world.arbiter, &world.fee, &world.stranger] {
            world.svm.airdrop(&addr(&pk(k)), 10 * SOL).unwrap();
        }
        let mint = world.mint;
        world.set(mint, TOKEN_PROGRAM, mint_data(&pk(&world.stranger), 6, 1_000_000_000_000));
        let seller = pk(&world.seller);
        world.set_token(&seller, 1_000_000_000);
        world
    }

    fn set(&mut self, at: Key, owner: Key, data: Vec<u8>) {
        let lamports = self.svm.minimum_balance_for_rent_exemption(data.len());
        self.svm
            .set_account(addr(&at), Account { lamports, data, owner: addr(&owner), executable: false, rent_epoch: 0 })
            .unwrap();
    }

    fn set_token(&mut self, owner: &Key, amount: u64) {
        let mint = self.mint;
        self.set(token_account_address(owner, &mint), TOKEN_PROGRAM, token_data(&mint, owner, amount));
    }

    fn trade(&mut self) -> [u8; 32] {
        self.next_trade += 1;
        [self.next_trade; 32]
    }

    fn send(&mut self, payer: &SigningKey, ixs: Vec<Ix>, extra: &[&SigningKey]) -> Sent {
        let bh: Key = self.svm.latest_blockhash().to_bytes();
        let compiled = compile(&pk(payer), &ixs, &bh).unwrap();
        let mut keys = vec![payer];
        keys.extend_from_slice(extra);
        let bytes = sign(&compiled, &keys).unwrap();
        let tx: Transaction = bincode::deserialize(&bytes).unwrap();
        let r = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        r
    }

    fn args(&self, trade: [u8; 32], mint: Option<Key>, total: u64) -> OpenArgs {
        OpenArgs {
            trade_id: trade,
            buyer: pk(&self.buyer),
            arbiter: pk(&self.arbiter),
            fee_receiver: pk(&self.fee),
            mint,
            total,
            fee: total / 101,
            fallback_delay: FALLBACK,
        }
    }

    fn open(&mut self, a: &OpenArgs) -> Sent {
        let seller = self.seller.clone();
        let ix = open_ix(&self.program, &pk(&seller), a);
        self.send(&seller, vec![ix], &[])
    }

    fn escrow(&self, trade: &[u8; 32]) -> Option<EscrowAccount> {
        let (at, _) = escrow_address(&self.program, trade, &pk(&self.seller));
        let acc = self.svm.get_account(&addr(&at))?;
        if acc.data.is_empty() {
            return None;
        }
        Some(decode_escrow(&at, &acc.data).unwrap())
    }

    fn lamports(&self, k: &Key) -> u64 {
        self.svm.get_account(&addr(k)).map(|a| a.lamports).unwrap_or(0)
    }

    fn tokens(&self, owner: &Key) -> u64 {
        self.svm
            .get_account(&addr(&token_account_address(owner, &self.mint)))
            .and_then(|a| token_account_amount(&a.data))
            .map(|(_, _, amount)| amount)
            .unwrap_or(0)
    }

    fn exists(&self, k: &Key) -> bool {
        self.svm.get_account(&addr(k)).is_some_and(|a| a.lamports > 0)
    }

    fn set_time(&mut self, unix: i64) {
        let mut c: Clock = self.svm.get_sysvar();
        c.unix_timestamp = unix;
        self.svm.set_sysvar(&c);
    }
}

#[test]
fn the_desktop_derives_the_same_escrow_the_program_opens() {
    let mut w = World::new();
    let t = w.trade();
    let a = w.args(t, None, 2 * SOL);
    assert_eq!(code(&w.open(&a)), "ok");
    let e = w.escrow(&t).expect("the escrow exists at the derived address");
    assert_eq!(e.state, STATE_FUNDED);
    assert_eq!(e.trade_id, t);
    assert_eq!(e.seller, pk(&w.seller));
    assert_eq!(e.buyer, pk(&w.buyer));
    assert_eq!(e.arbiter, pk(&w.arbiter));
    assert_eq!(e.fee_receiver, pk(&w.fee));
    assert_eq!(e.mint, None);
    assert_eq!((e.total, e.fee), (2 * SOL, a.fee));
    assert_eq!(e.fallback_at - e.opened_at, FALLBACK as i64);
    assert!(!e.frozen);
    let rent = w.svm.minimum_balance_for_rent_exemption(ESCROW_LEN);
    assert_eq!(w.lamports(&e.address), rent + 2 * SOL);
}

#[test]
fn a_native_release_pays_the_buyer_and_the_fee_and_closes_the_escrow() {
    let mut w = World::new();
    let t = w.trade();
    let a = w.args(t, None, 2 * SOL);
    w.open(&a).unwrap();
    let e = w.escrow(&t).unwrap();
    let (buyer0, fee0, seller0) = (w.lamports(&e.buyer), w.lamports(&e.fee_receiver), w.lamports(&e.seller));
    let seller = w.seller.clone();
    let r = w.send(&seller, vec![release_ix(&w.program, &e)], &[]);
    assert_eq!(code(&r), "ok");
    assert_eq!(w.lamports(&e.buyer) - buyer0, 2 * SOL - a.fee);
    assert_eq!(w.lamports(&e.fee_receiver) - fee0, a.fee);
    let rent = w.svm.minimum_balance_for_rent_exemption(ESCROW_LEN);
    assert_eq!(w.lamports(&e.seller) + 5_000, seller0 + rent, "the seller gets the rent back and pays the network fee");
    assert!(!w.exists(&e.address));
    assert!(w.escrow(&t).is_none());
    let again = w.send(&seller, vec![release_ix(&w.program, &e)], &[]);
    assert!(custom(&again, 0), "{}", code(&again));
}

#[test]
fn the_buyer_cancels_and_the_seller_gets_everything_back() {
    let mut w = World::new();
    let t = w.trade();
    w.open(&w.args(t, None, SOL)).unwrap();
    let e = w.escrow(&t).unwrap();
    let seller0 = w.lamports(&e.seller);
    let buyer = w.buyer.clone();
    assert_eq!(code(&w.send(&buyer, vec![cancel_ix(&w.program, &e)], &[])), "ok");
    let rent = w.svm.minimum_balance_for_rent_exemption(ESCROW_LEN);
    assert_eq!(w.lamports(&e.seller), seller0 + SOL + rent);
    assert!(w.escrow(&t).is_none());
}

#[test]
fn the_arbiter_resolves_either_way() {
    let mut w = World::new();
    let arbiter = w.arbiter.clone();
    let t1 = w.trade();
    let a1 = w.args(t1, None, SOL);
    w.open(&a1).unwrap();
    let e1 = w.escrow(&t1).unwrap();
    let buyer0 = w.lamports(&e1.buyer);
    let ix = resolve_ix(&w.program, &e1, &pk(&arbiter), true);
    assert_eq!(code(&w.send(&arbiter, vec![ix], &[])), "ok");
    assert_eq!(w.lamports(&e1.buyer) - buyer0, SOL - a1.fee);

    let t2 = w.trade();
    w.open(&w.args(t2, None, SOL)).unwrap();
    let e2 = w.escrow(&t2).unwrap();
    let seller0 = w.lamports(&e2.seller);
    let ix = resolve_ix(&w.program, &e2, &pk(&arbiter), false);
    assert_eq!(code(&w.send(&arbiter, vec![ix], &[])), "ok");
    let rent = w.svm.minimum_balance_for_rent_exemption(ESCROW_LEN);
    assert_eq!(w.lamports(&e2.seller), seller0 + SOL + rent);
}

#[test]
fn only_the_right_party_can_act() {
    let mut w = World::new();
    let t = w.trade();
    w.open(&w.args(t, None, SOL)).unwrap();
    let e = w.escrow(&t).unwrap();
    let (buyer, seller, stranger) = (w.buyer.clone(), w.seller.clone(), w.stranger.clone());
    let p = w.program;

    let mut forged = release_ix(&p, &e);
    forged.accounts[0] = Meta::sr(pk(&buyer));
    assert!(custom(&w.send(&buyer, vec![forged], &[]), 6), "the buyer cannot release");

    let mut seller_cancel = cancel_ix(&p, &e);
    seller_cancel.accounts[0] = Meta::sr(pk(&seller));
    assert!(custom(&w.send(&seller, vec![seller_cancel], &[]), 6), "the seller cannot cancel");

    let r = w.send(&stranger, vec![resolve_ix(&p, &e, &pk(&stranger), true)], &[]);
    assert!(custom(&r, 6), "a stranger cannot resolve");

    let mut buyer_reclaim = reclaim_ix(&p, &e);
    buyer_reclaim.accounts[0] = Meta::sw(pk(&buyer));
    assert!(custom(&w.send(&buyer, vec![buyer_reclaim], &[]), 6), "the buyer cannot reclaim");

    let mut unsigned = release_ix(&p, &e);
    unsigned.accounts[0] = Meta::r(pk(&seller));
    assert!(custom(&w.send(&stranger, vec![unsigned], &[]), 6), "a release needs the seller's signature");
    assert!(w.escrow(&t).is_some());
}

#[test]
fn payouts_go_only_to_the_escrows_parties() {
    let mut w = World::new();
    let t = w.trade();
    w.open(&w.args(t, None, SOL)).unwrap();
    let e = w.escrow(&t).unwrap();
    let seller = w.seller.clone();
    let p = w.program;
    let stranger = pk(&w.stranger);

    let mut to_stranger = release_ix(&p, &e);
    to_stranger.accounts[3] = Meta::w(stranger);
    assert!(custom(&w.send(&seller, vec![to_stranger], &[]), 9));

    let mut fee_to_stranger = release_ix(&p, &e);
    fee_to_stranger.accounts[4] = Meta::w(stranger);
    assert!(custom(&w.send(&seller, vec![fee_to_stranger], &[]), 9));

    let mut rent_to_stranger = release_ix(&p, &e);
    rent_to_stranger.accounts[2] = Meta::w(stranger);
    assert!(custom(&w.send(&seller, vec![rent_to_stranger], &[]), 9));
    assert!(w.escrow(&t).is_some());
}

#[test]
fn open_rejects_bad_terms_and_a_second_open() {
    let mut w = World::new();
    let t = w.trade();
    let base = w.args(t, None, SOL);
    let seller = pk(&w.seller);
    let cases: Vec<(OpenArgs, u32)> = vec![
        (OpenArgs { buyer: seller, ..base.clone() }, 3),
        (OpenArgs { arbiter: seller, ..base.clone() }, 3),
        (OpenArgs { arbiter: base.buyer, ..base.clone() }, 3),
        (OpenArgs { buyer: [0; 32], ..base.clone() }, 3),
        (OpenArgs { fee_receiver: [0; 32], ..base.clone() }, 3),
        (OpenArgs { total: 0, fee: 0, ..base.clone() }, 4),
        (OpenArgs { fee: SOL / 10 + 1, ..base.clone() }, 4),
        (OpenArgs { fallback_delay: FALLBACK - 1, ..base.clone() }, 5),
        (OpenArgs { fallback_delay: 365 * DAY + 1, ..base.clone() }, 5),
    ];
    for (a, err) in cases {
        let r = w.open(&a);
        assert!(custom(&r, err), "{a:?} gave {}", code(&r));
    }
    assert_eq!(code(&w.open(&OpenArgs { fee: SOL / 10, ..base.clone() })), "ok");
    assert!(custom(&w.open(&base), 2), "the same trade cannot be opened twice");
}

#[test]
fn reclaim_waits_for_the_fallback_and_a_freeze_blocks_it() {
    let mut w = World::new();
    let seller = w.seller.clone();
    let p = w.program;
    let t1 = w.trade();
    w.open(&w.args(t1, None, SOL)).unwrap();
    let e1 = w.escrow(&t1).unwrap();
    assert!(custom(&w.send(&seller, vec![reclaim_ix(&p, &e1)], &[]), 7));
    w.set_time(e1.fallback_at);
    assert_eq!(code(&w.send(&seller, vec![reclaim_ix(&p, &e1)], &[])), "ok");

    let t2 = w.trade();
    w.open(&w.args(t2, None, SOL)).unwrap();
    let e2 = w.escrow(&t2).unwrap();
    let buyer = w.buyer.clone();
    assert_eq!(code(&w.send(&buyer, vec![freeze_ix(&p, &e2, &pk(&buyer))], &[])), "ok");
    assert!(w.escrow(&t2).unwrap().frozen);
    assert!(custom(&w.send(&buyer, vec![freeze_ix(&p, &e2, &pk(&buyer))], &[]), 6), "frozen once");
    let stranger = w.stranger.clone();
    assert!(custom(&w.send(&stranger, vec![freeze_ix(&p, &e2, &pk(&stranger))], &[]), 6));
    w.set_time(e2.fallback_at + 1);
    assert!(custom(&w.send(&seller, vec![reclaim_ix(&p, &e2)], &[]), 6));
    let arbiter = w.arbiter.clone();
    let ix = resolve_ix(&p, &e2, &pk(&arbiter), false);
    assert_eq!(code(&w.send(&arbiter, vec![ix], &[])), "ok", "the arbiter still settles a frozen escrow");
}

#[test]
fn a_token_release_creates_the_buyers_account_and_closes_the_vault() {
    let mut w = World::new();
    let t = w.trade();
    let a = OpenArgs { fee: 2_500_000, ..w.args(t, Some(w.mint), 252_500_000) };
    assert_eq!(code(&w.open(&a)), "ok");
    let e = w.escrow(&t).unwrap();
    let (vault, _) = vault_address(&w.program, &e.address);
    assert_eq!(w.tokens(&e.seller), 1_000_000_000 - 252_500_000);
    let vault_acc = w.svm.get_account(&addr(&vault)).unwrap();
    let (vmint, vowner, vamount) = token_account_amount(&vault_acc.data).unwrap();
    assert_eq!((vmint, vowner, vamount), (w.mint, e.address, 252_500_000));
    assert!(!w.exists(&token_account_address(&e.buyer, &w.mint)));

    let seller = w.seller.clone();
    let seller0 = w.lamports(&e.seller);
    let mut ixs = payout_token_accounts(&pk(&seller), &e, true);
    assert_eq!(ixs.len(), 2);
    ixs.push(release_ix(&w.program, &e));
    let r = w.send(&seller, ixs, &[]);
    assert_eq!(code(&r), "ok");
    assert_eq!(w.tokens(&e.buyer), 250_000_000);
    assert_eq!(w.tokens(&e.fee_receiver), 2_500_000);
    assert!(!w.exists(&vault));
    assert!(w.escrow(&t).is_none());
    let rent = w.svm.minimum_balance_for_rent_exemption(ESCROW_LEN)
        + w.svm.minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN);
    let ata_rent = 2 * w.svm.minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN);
    assert_eq!(w.lamports(&e.seller) + 5_000 + ata_rent, seller0 + rent);
}

#[test]
fn a_relayed_cancel_needs_the_buyers_signature_for_this_escrow() {
    let mut w = World::new();
    let p = w.program;
    let t = w.trade();
    w.open(&w.args(t, Some(w.mint), 100_000_000)).unwrap();
    let e = w.escrow(&t).unwrap();
    let other_t = w.trade();
    w.open(&w.args(other_t, Some(w.mint), 1_000_000)).unwrap();
    let other = w.escrow(&other_t).unwrap();
    let relayer = w.stranger.clone();
    let buyer = w.buyer.clone();

    let by_stranger = buyer_signature(&relayer, &p, &e.address, ACTION_CANCEL);
    let mut ixs = cancel_for_ixs(&p, &e, &by_stranger);
    ixs[0] = ed25519_ix(&pk(&relayer), &by_stranger, &auth_message(&p, &e.address, ACTION_CANCEL));
    assert!(custom(&w.send(&relayer, ixs, &[]), 8), "a stranger's signature is not the buyer's");

    let for_other = buyer_signature(&buyer, &p, &other.address, ACTION_CANCEL);
    let mut ixs = cancel_for_ixs(&p, &e, &for_other);
    ixs[0] = ed25519_ix(&e.buyer, &for_other, &auth_message(&p, &other.address, ACTION_CANCEL));
    assert!(custom(&w.send(&relayer, ixs, &[]), 8), "a signature for another escrow");

    let freeze_sig = buyer_signature(&buyer, &p, &e.address, ACTION_FREEZE);
    let mut ixs = cancel_for_ixs(&p, &e, &freeze_sig);
    ixs[0] = ed25519_ix(&e.buyer, &freeze_sig, &auth_message(&p, &e.address, ACTION_FREEZE));
    assert!(custom(&w.send(&relayer, ixs, &[]), 8), "a freeze signature cannot cancel");

    let good = buyer_signature(&buyer, &p, &e.address, ACTION_CANCEL);
    let mut no_proof = cancel_for_ixs(&p, &e, &good);
    no_proof.remove(0);
    assert!(custom(&w.send(&relayer, no_proof, &[]), 8), "the signature check must come first");

    let mut forged = cancel_for_ixs(&p, &e, &[7u8; 64]);
    forged.remove(0);
    forged.insert(0, ed25519_ix(&e.buyer, &[7u8; 64], &auth_message(&p, &e.address, ACTION_CANCEL)));
    assert!(code(&w.send(&relayer, forged, &[])) != "ok", "the runtime rejects a bad signature");

    assert!(verify_buyer_signature(&p, &e.address, &e.buyer, ACTION_CANCEL, &good));
    assert!(!verify_buyer_signature(&p, &other.address, &e.buyer, ACTION_CANCEL, &good));
    let seller_tokens = w.tokens(&e.seller);
    let mut ixs = payout_token_accounts(&pk(&relayer), &e, false);
    ixs.extend(cancel_for_ixs(&p, &e, &good));
    assert_eq!(code(&w.send(&relayer, ixs, &[])), "ok");
    assert_eq!(w.tokens(&e.seller), seller_tokens + 100_000_000);
    assert!(w.escrow(&t).is_none());
    assert!(w.escrow(&other_t).is_some());
}

#[test]
fn a_signed_freeze_from_the_buyer_blocks_the_fallback() {
    let mut w = World::new();
    let p = w.program;
    let t = w.trade();
    w.open(&w.args(t, None, SOL)).unwrap();
    let e = w.escrow(&t).unwrap();
    let sig = buyer_signature(&w.buyer, &p, &e.address, ACTION_FREEZE);
    let relayer = w.stranger.clone();
    assert_eq!(code(&w.send(&relayer, freeze_for_ixs(&p, &e, &sig), &[])), "ok");
    assert!(w.escrow(&t).unwrap().frozen);
    w.set_time(e.fallback_at + DAY as i64);
    let seller = w.seller.clone();
    assert!(custom(&w.send(&seller, vec![reclaim_ix(&p, &e)], &[]), 6));
}

#[test]
fn token_payouts_must_reach_the_parties_token_accounts() {
    let mut w = World::new();
    let p = w.program;
    let t = w.trade();
    w.open(&w.args(t, Some(w.mint), 50_000_000)).unwrap();
    let e = w.escrow(&t).unwrap();
    let stranger = pk(&w.stranger);
    w.set_token(&stranger, 0);
    let buyer = pk(&w.buyer);
    w.set_token(&buyer, 0);
    let fee = pk(&w.fee);
    w.set_token(&fee, 0);
    let seller = w.seller.clone();

    let mut wrong_owner = release_ix(&p, &e);
    wrong_owner.accounts[3] = Meta::w(token_account_address(&stranger, &w.mint));
    assert!(custom(&w.send(&seller, vec![wrong_owner], &[]), 9));

    let mut wrong_fee = release_ix(&p, &e);
    wrong_fee.accounts[4] = Meta::w(token_account_address(&stranger, &w.mint));
    assert!(custom(&w.send(&seller, vec![wrong_fee], &[]), 9));

    let mut wrong_vault = release_ix(&p, &e);
    wrong_vault.accounts[5] = Meta::w(token_account_address(&stranger, &w.mint));
    assert!(custom(&w.send(&seller, vec![wrong_vault], &[]), 9));

    let other_mint = [0x99; 32];
    w.set(other_mint, TOKEN_PROGRAM, mint_data(&stranger, 6, 0));
    let mut wrong_mint = release_ix(&p, &e);
    wrong_mint.accounts[6] = Meta::r(other_mint);
    assert!(custom(&w.send(&seller, vec![wrong_mint], &[]), 9));

    assert_eq!(code(&w.send(&seller, vec![release_ix(&p, &e)], &[])), "ok");
    assert_eq!(w.tokens(&buyer), 50_000_000 - e.fee);
}

#[test]
fn griefing_deposits_do_not_stop_an_escrow() {
    let mut w = World::new();
    let p = w.program;
    let t = w.trade();
    let seller_key = pk(&w.seller);
    let (escrow_at, _) = escrow_address(&p, &t, &seller_key);
    let (vault_at, _) = vault_address(&p, &escrow_at);
    let stranger = w.stranger.clone();
    let transfer = |to: Key, lamports: u64| {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&lamports.to_le_bytes());
        Ix { program: SYSTEM_PROGRAM, accounts: vec![Meta::sw(pk(&stranger)), Meta::w(to)], data }
    };
    let r = w.send(&stranger, vec![transfer(escrow_at, 1_000_000), transfer(vault_at, 3_000_000)], &[]);
    assert_eq!(code(&r), "ok");
    assert_eq!(code(&w.open(&w.args(t, Some(w.mint), 10_000_000))), "ok");
    let e = w.escrow(&t).unwrap();

    let mut donate = vec![12u8];
    donate.extend_from_slice(&7u64.to_le_bytes());
    donate.push(6);
    let mint = w.mint;
    let seller = w.seller.clone();
    let gift = Ix {
        program: TOKEN_PROGRAM,
        accounts: vec![
            Meta::w(token_account_address(&seller_key, &mint)),
            Meta::r(mint),
            Meta::w(vault_at),
            Meta::sr(seller_key),
        ],
        data: donate,
    };
    assert_eq!(code(&w.send(&seller, vec![gift], &[])), "ok");
    let mut ixs = payout_token_accounts(&seller_key, &e, true);
    ixs.push(release_ix(&p, &e));
    assert_eq!(code(&w.send(&seller, ixs, &[])), "ok");
    assert_eq!(w.tokens(&e.buyer), 10_000_000 - e.fee + 7, "the surplus goes to the payee");
    assert!(!w.exists(&vault_at));
}

#[test]
fn a_fake_escrow_account_is_refused() {
    let mut w = World::new();
    let p = w.program;
    let t = w.trade();
    w.open(&w.args(t, None, SOL)).unwrap();
    let real = w.escrow(&t).unwrap();
    let real_data = w.svm.get_account(&addr(&real.address)).unwrap().data;
    let fake_at = [0x55; 32];
    w.set(fake_at, p, real_data.clone());
    let fake = EscrowAccount { address: fake_at, ..real.clone() };
    let seller = w.seller.clone();
    assert!(custom(&w.send(&seller, vec![release_ix(&p, &fake)], &[]), 0));

    let foreign_at = [0x56; 32];
    w.set(foreign_at, SYSTEM_PROGRAM, real_data);
    let foreign = EscrowAccount { address: foreign_at, ..real };
    assert!(custom(&w.send(&seller, vec![release_ix(&p, &foreign)], &[]), 0));
}

#[test]
fn every_operation_fits_the_default_compute_budget() {
    let mut w = World::new();
    let p = w.program;
    let t = w.trade();
    let opened = w.open(&w.args(t, Some(w.mint), 10_000_000)).unwrap();
    let e = w.escrow(&t).unwrap();
    let sig = buyer_signature(&w.buyer, &p, &e.address, ACTION_CANCEL);
    let relayer = w.stranger.clone();
    let mut ixs = payout_token_accounts(&pk(&relayer), &e, false);
    ixs.extend(cancel_for_ixs(&p, &e, &sig));
    let cancelled = w.send(&relayer, ixs, &[]).unwrap();
    println!("open {} cu, relayed cancel {} cu", opened.compute_units_consumed, cancelled.compute_units_consumed);
    assert!(opened.compute_units_consumed < 100_000);
    assert!(cancelled.compute_units_consumed < 100_000);
}
