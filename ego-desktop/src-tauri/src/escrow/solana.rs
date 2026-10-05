use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub type Key = [u8; 32];

pub const SYSTEM_PROGRAM: Key = [0; 32];
pub const TOKEN_PROGRAM: Key = [6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169];
pub const ATA_PROGRAM: Key = [140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89];
pub const ED25519_PROGRAM: Key = [3, 125, 70, 214, 124, 147, 251, 190, 18, 249, 66, 143, 131, 141, 64, 255, 5, 112, 116, 73, 39, 244, 138, 100, 252, 202, 112, 68, 128, 0, 0, 0];
pub const INSTRUCTIONS_SYSVAR: Key = [6, 167, 213, 23, 24, 123, 209, 102, 53, 218, 212, 4, 85, 253, 194, 192, 193, 36, 198, 143, 33, 86, 117, 165, 219, 186, 203, 95, 8, 0, 0, 0];
pub const COMPUTE_BUDGET_PROGRAM: Key = [3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187, 197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0];

pub const ESCROW_SEED: &[u8] = b"escrow";
pub const VAULT_SEED: &[u8] = b"vault";
pub const AUTH_DOMAIN: &[u8] = b"ego-escrow/solana/v1";
pub const ESCROW_LEN: usize = 232;
pub const TOKEN_ACCOUNT_LEN: usize = 165;
pub const STATE_FUNDED: u8 = 1;

pub const IX_OPEN: u8 = 0;
pub const IX_RELEASE: u8 = 1;
pub const IX_CANCEL: u8 = 2;
pub const IX_RESOLVE: u8 = 3;
pub const IX_FREEZE: u8 = 4;
pub const IX_RECLAIM: u8 = 5;
pub const IX_CANCEL_FOR: u8 = 6;
pub const IX_FREEZE_FOR: u8 = 7;

pub const ACTION_CANCEL: u8 = 2;
pub const ACTION_FREEZE: u8 = 5;

pub const ESCROW_ERRORS: [&str; 11] = [
    "UnknownEscrow",
    "NotFunded",
    "AlreadyUsed",
    "BadParty",
    "BadAmount",
    "BadFallback",
    "NotAllowed",
    "TooEarly",
    "BadSignature",
    "BadAccount",
    "BadInstruction",
];

pub fn parse_key(s: &str) -> Result<Key, String> {
    bs58::decode(s.trim())
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("{s:.48} is not a Solana address"))
}

pub fn b58(k: &Key) -> String {
    bs58::encode(k).into_string()
}

pub fn on_curve(k: &Key) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*k).decompress().is_some()
}

pub fn create_program_address(seeds: &[&[u8]], program: &Key) -> Option<Key> {
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    h.update(program);
    h.update(b"ProgramDerivedAddress");
    let out: Key = h.finalize().into();
    if on_curve(&out) {
        None
    } else {
        Some(out)
    }
}

pub fn find_program_address(seeds: &[&[u8]], program: &Key) -> (Key, u8) {
    for bump in (0..=255u8).rev() {
        let b = [bump];
        let mut all = seeds.to_vec();
        all.push(&b);
        if let Some(k) = create_program_address(&all, program) {
            return (k, bump);
        }
    }
    ([0; 32], 0)
}

pub fn escrow_address(program: &Key, trade_id: &[u8; 32], seller: &Key) -> (Key, u8) {
    find_program_address(&[ESCROW_SEED, trade_id, seller], program)
}

pub fn vault_address(program: &Key, escrow: &Key) -> (Key, u8) {
    find_program_address(&[VAULT_SEED, escrow], program)
}

pub fn token_account_address(owner: &Key, mint: &Key) -> Key {
    find_program_address(&[owner, &TOKEN_PROGRAM, mint], &ATA_PROGRAM).0
}

pub fn auth_message(program: &Key, escrow: &Key, action: u8) -> Vec<u8> {
    let mut m = AUTH_DOMAIN.to_vec();
    m.extend_from_slice(program);
    m.extend_from_slice(escrow);
    m.push(action);
    m
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub key: Key,
    pub signer: bool,
    pub writable: bool,
}

impl Meta {
    pub fn w(key: Key) -> Meta {
        Meta { key, signer: false, writable: true }
    }

    pub fn r(key: Key) -> Meta {
        Meta { key, signer: false, writable: false }
    }

    pub fn sw(key: Key) -> Meta {
        Meta { key, signer: true, writable: true }
    }

    pub fn sr(key: Key) -> Meta {
        Meta { key, signer: true, writable: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ix {
    pub program: Key,
    pub accounts: Vec<Meta>,
    pub data: Vec<u8>,
}

pub fn compact_u16(n: usize, out: &mut Vec<u8>) {
    let mut v = n;
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

pub struct Compiled {
    pub message: Vec<u8>,
    pub signers: Vec<Key>,
}

pub fn compile(payer: &Key, ixs: &[Ix], blockhash: &Key) -> Result<Compiled, String> {
    let mut keys: Vec<Meta> = vec![Meta::sw(*payer)];
    let mut merge = |m: &Meta| match keys.iter_mut().find(|k| k.key == m.key) {
        Some(k) => {
            k.signer |= m.signer;
            k.writable |= m.writable;
        }
        None => keys.push(m.clone()),
    };
    for ix in ixs {
        for m in &ix.accounts {
            merge(m);
        }
        merge(&Meta::r(ix.program));
    }
    let payer_meta = keys.remove(0);
    let group = |signer: bool, writable: bool| {
        keys.iter().filter(move |k| k.signer == signer && k.writable == writable).cloned()
    };
    let mut ordered = vec![payer_meta];
    ordered.extend(group(true, true));
    ordered.extend(group(true, false));
    ordered.extend(group(false, true));
    ordered.extend(group(false, false));
    if ordered.len() > 256 {
        return Err("the transaction names more than 256 accounts".into());
    }
    let signers: Vec<Key> = ordered.iter().filter(|k| k.signer).map(|k| k.key).collect();
    let readonly_signed = ordered.iter().filter(|k| k.signer && !k.writable).count();
    let readonly_unsigned = ordered.iter().filter(|k| !k.signer && !k.writable).count();
    let index = |k: &Key| ordered.iter().position(|m| &m.key == k).map(|i| i as u8);

    let mut msg = vec![signers.len() as u8, readonly_signed as u8, readonly_unsigned as u8];
    compact_u16(ordered.len(), &mut msg);
    for k in &ordered {
        msg.extend_from_slice(&k.key);
    }
    msg.extend_from_slice(blockhash);
    compact_u16(ixs.len(), &mut msg);
    for ix in ixs {
        msg.push(index(&ix.program).ok_or("a program is missing from the account list")?);
        compact_u16(ix.accounts.len(), &mut msg);
        for m in &ix.accounts {
            msg.push(index(&m.key).ok_or("an account is missing from the account list")?);
        }
        compact_u16(ix.data.len(), &mut msg);
        msg.extend_from_slice(&ix.data);
    }
    Ok(Compiled { message: msg, signers })
}

pub fn sign(compiled: &Compiled, keys: &[&SigningKey]) -> Result<Vec<u8>, String> {
    let mut tx = Vec::with_capacity(1 + 64 * compiled.signers.len() + compiled.message.len());
    compact_u16(compiled.signers.len(), &mut tx);
    for signer in &compiled.signers {
        let key = keys
            .iter()
            .find(|k| &k.verifying_key().to_bytes() == signer)
            .ok_or_else(|| format!("no key to sign for {}", b58(signer)))?;
        tx.extend_from_slice(&key.sign(&compiled.message).to_bytes());
    }
    tx.extend_from_slice(&compiled.message);
    Ok(tx)
}

pub fn first_signature(tx: &[u8]) -> Option<String> {
    tx.get(1..65).map(|s| bs58::encode(s).into_string())
}

pub fn compute_unit_limit_ix(units: u32) -> Ix {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Ix { program: COMPUTE_BUDGET_PROGRAM, accounts: vec![], data }
}

pub fn compute_unit_price_ix(micro_lamports: u64) -> Ix {
    let mut data = vec![3u8];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Ix { program: COMPUTE_BUDGET_PROGRAM, accounts: vec![], data }
}

pub fn create_token_account_ix(payer: &Key, owner: &Key, mint: &Key) -> Ix {
    Ix {
        program: ATA_PROGRAM,
        accounts: vec![
            Meta::sw(*payer),
            Meta::w(token_account_address(owner, mint)),
            Meta::r(*owner),
            Meta::r(*mint),
            Meta::r(SYSTEM_PROGRAM),
            Meta::r(TOKEN_PROGRAM),
        ],
        data: vec![1],
    }
}

pub fn ed25519_ix(pubkey: &Key, signature: &[u8; 64], message: &[u8]) -> Ix {
    let pk_off: u16 = 16;
    let sig_off: u16 = pk_off + 32;
    let msg_off: u16 = sig_off + 64;
    let mut data = vec![1u8, 0];
    for v in [sig_off, u16::MAX, pk_off, u16::MAX, msg_off, message.len() as u16, u16::MAX] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    Ix { program: ED25519_PROGRAM, accounts: vec![], data }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenArgs {
    pub trade_id: [u8; 32],
    pub buyer: Key,
    pub arbiter: Key,
    pub fee_receiver: Key,
    pub mint: Option<Key>,
    pub total: u64,
    pub fee: u64,
    pub fallback_delay: u64,
}

pub fn open_ix(program: &Key, seller: &Key, a: &OpenArgs) -> Ix {
    let (escrow, _) = escrow_address(program, &a.trade_id, seller);
    let mut data = vec![IX_OPEN];
    data.extend_from_slice(&a.trade_id);
    data.extend_from_slice(&a.buyer);
    data.extend_from_slice(&a.arbiter);
    data.extend_from_slice(&a.fee_receiver);
    data.extend_from_slice(&a.mint.unwrap_or([0; 32]));
    data.extend_from_slice(&a.total.to_le_bytes());
    data.extend_from_slice(&a.fee.to_le_bytes());
    data.extend_from_slice(&a.fallback_delay.to_le_bytes());
    let mut accounts = vec![Meta::sw(*seller), Meta::w(escrow), Meta::r(SYSTEM_PROGRAM)];
    if let Some(mint) = a.mint {
        accounts.push(Meta::r(mint));
        accounts.push(Meta::w(token_account_address(seller, &mint)));
        accounts.push(Meta::w(vault_address(program, &escrow).0));
        accounts.push(Meta::r(TOKEN_PROGRAM));
    }
    Ix { program: *program, accounts, data }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowAccount {
    pub address: Key,
    pub state: u8,
    pub frozen: bool,
    pub bump: u8,
    pub vault_bump: u8,
    pub trade_id: [u8; 32],
    pub seller: Key,
    pub buyer: Key,
    pub arbiter: Key,
    pub fee_receiver: Key,
    pub mint: Option<Key>,
    pub total: u64,
    pub fee: u64,
    pub opened_at: i64,
    pub fallback_at: i64,
}

pub fn decode_escrow(address: &Key, d: &[u8]) -> Result<EscrowAccount, String> {
    if d.len() != ESCROW_LEN || d[0] != 1 {
        return Err("the account is not an Ego escrow".into());
    }
    let key = |at: usize| -> Key { d[at..at + 32].try_into().unwrap_or([0; 32]) };
    let u64_at = |at: usize| u64::from_le_bytes(d[at..at + 8].try_into().unwrap_or([0; 8]));
    let mint = key(168);
    Ok(EscrowAccount {
        address: *address,
        state: d[1],
        frozen: d[2] != 0,
        bump: d[3],
        vault_bump: d[4],
        trade_id: key(8),
        seller: key(40),
        buyer: key(72),
        arbiter: key(104),
        fee_receiver: key(136),
        mint: if mint == [0; 32] { None } else { Some(mint) },
        total: u64_at(200),
        fee: u64_at(208),
        opened_at: u64_at(216) as i64,
        fallback_at: u64_at(224) as i64,
    })
}

fn settle_accounts(program: &Key, e: &EscrowAccount, actor: Meta, to_buyer: bool) -> Vec<Meta> {
    let mut accounts = vec![actor, Meta::w(e.address), Meta::w(e.seller)];
    match e.mint {
        None => {
            accounts.push(Meta::w(if to_buyer { e.buyer } else { e.seller }));
            if to_buyer {
                accounts.push(Meta::w(e.fee_receiver));
            }
        }
        Some(mint) => {
            let payee = if to_buyer { e.buyer } else { e.seller };
            accounts.push(Meta::w(token_account_address(&payee, &mint)));
            if to_buyer {
                accounts.push(Meta::w(token_account_address(&e.fee_receiver, &mint)));
            }
            accounts.push(Meta::w(vault_address(program, &e.address).0));
            accounts.push(Meta::r(mint));
            accounts.push(Meta::r(TOKEN_PROGRAM));
        }
    }
    accounts
}

pub fn payout_token_accounts(payer: &Key, e: &EscrowAccount, to_buyer: bool) -> Vec<Ix> {
    let Some(mint) = e.mint else { return vec![] };
    let mut ixs = vec![create_token_account_ix(payer, if to_buyer { &e.buyer } else { &e.seller }, &mint)];
    if to_buyer && e.fee > 0 {
        ixs.push(create_token_account_ix(payer, &e.fee_receiver, &mint));
    }
    ixs
}

pub fn release_ix(program: &Key, e: &EscrowAccount) -> Ix {
    Ix { program: *program, accounts: settle_accounts(program, e, Meta::sw(e.seller), true), data: vec![IX_RELEASE] }
}

pub fn cancel_ix(program: &Key, e: &EscrowAccount) -> Ix {
    Ix { program: *program, accounts: settle_accounts(program, e, Meta::sr(e.buyer), false), data: vec![IX_CANCEL] }
}

pub fn resolve_ix(program: &Key, e: &EscrowAccount, arbiter: &Key, to_buyer: bool) -> Ix {
    Ix {
        program: *program,
        accounts: settle_accounts(program, e, Meta::sr(*arbiter), to_buyer),
        data: vec![IX_RESOLVE, to_buyer as u8],
    }
}

pub fn reclaim_ix(program: &Key, e: &EscrowAccount) -> Ix {
    Ix { program: *program, accounts: settle_accounts(program, e, Meta::sw(e.seller), false), data: vec![IX_RECLAIM] }
}

pub fn freeze_ix(program: &Key, e: &EscrowAccount, by: &Key) -> Ix {
    Ix { program: *program, accounts: vec![Meta::sr(*by), Meta::w(e.address)], data: vec![IX_FREEZE] }
}

pub fn buyer_signature(buyer: &SigningKey, program: &Key, escrow: &Key, action: u8) -> [u8; 64] {
    buyer.sign(&auth_message(program, escrow, action)).to_bytes()
}

pub fn cancel_for_ixs(program: &Key, e: &EscrowAccount, signature: &[u8; 64]) -> Vec<Ix> {
    vec![
        ed25519_ix(&e.buyer, signature, &auth_message(program, &e.address, ACTION_CANCEL)),
        Ix {
            program: *program,
            accounts: settle_accounts(program, e, Meta::r(INSTRUCTIONS_SYSVAR), false),
            data: vec![IX_CANCEL_FOR],
        },
    ]
}

pub fn freeze_for_ixs(program: &Key, e: &EscrowAccount, signature: &[u8; 64]) -> Vec<Ix> {
    vec![
        ed25519_ix(&e.buyer, signature, &auth_message(program, &e.address, ACTION_FREEZE)),
        Ix {
            program: *program,
            accounts: vec![Meta::r(INSTRUCTIONS_SYSVAR), Meta::w(e.address)],
            data: vec![IX_FREEZE_FOR],
        },
    ]
}

pub fn verify_buyer_signature(program: &Key, escrow: &Key, buyer: &Key, action: u8, signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(buyer) else { return false };
    vk.verify(&auth_message(program, escrow, action), &Signature::from_bytes(signature)).is_ok()
}

pub fn token_account_amount(data: &[u8]) -> Option<(Key, Key, u64)> {
    if data.len() != TOKEN_ACCOUNT_LEN {
        return None;
    }
    Some((
        data[0..32].try_into().ok()?,
        data[32..64].try_into().ok()?,
        u64::from_le_bytes(data[64..72].try_into().ok()?),
    ))
}
