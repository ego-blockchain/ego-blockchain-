#![allow(deprecated)]

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::{instructions as ix_sysvar, Sysvar},
};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub const SYSTEM_PROGRAM_ID: Pubkey = pubkey!("11111111111111111111111111111111");
pub const TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey = pubkey!("Sysvar1nstructions1111111111111111111111111");

pub const ESCROW_SEED: &[u8] = b"escrow";
pub const VAULT_SEED: &[u8] = b"vault";
pub const AUTH_DOMAIN: &[u8] = b"ego-escrow/solana/v1";
pub const ESCROW_LEN: usize = 232;
pub const TOKEN_ACCOUNT_LEN: usize = 165;
pub const MINT_LEN: usize = 82;
pub const VERSION: u8 = 1;
pub const STATE_FUNDED: u8 = 1;
pub const MIN_FALLBACK: i64 = 30 * 24 * 60 * 60;
pub const MAX_FALLBACK: i64 = 365 * 24 * 60 * 60;
pub const MAX_FEE_BPS: u128 = 1_000;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EscrowError {
    UnknownEscrow = 0,
    NotFunded = 1,
    AlreadyUsed = 2,
    BadParty = 3,
    BadAmount = 4,
    BadFallback = 5,
    NotAllowed = 6,
    TooEarly = 7,
    BadSignature = 8,
    BadAccount = 9,
    BadInstruction = 10,
}

impl From<EscrowError> for ProgramError {
    fn from(e: EscrowError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

fn fail<T>(e: EscrowError) -> Result<T, ProgramError> {
    Err(e.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Escrow {
    pub state: u8,
    pub frozen: bool,
    pub bump: u8,
    pub vault_bump: u8,
    pub trade_id: [u8; 32],
    pub seller: Pubkey,
    pub buyer: Pubkey,
    pub arbiter: Pubkey,
    pub fee_receiver: Pubkey,
    pub mint: Pubkey,
    pub total: u64,
    pub fee: u64,
    pub opened_at: i64,
    pub fallback_at: i64,
}

impl Escrow {
    pub fn is_native(&self) -> bool {
        self.mint == Pubkey::default()
    }

    pub fn pack(&self, out: &mut [u8]) {
        out[0] = VERSION;
        out[1] = self.state;
        out[2] = self.frozen as u8;
        out[3] = self.bump;
        out[4] = self.vault_bump;
        out[5..8].fill(0);
        out[8..40].copy_from_slice(&self.trade_id);
        out[40..72].copy_from_slice(self.seller.as_ref());
        out[72..104].copy_from_slice(self.buyer.as_ref());
        out[104..136].copy_from_slice(self.arbiter.as_ref());
        out[136..168].copy_from_slice(self.fee_receiver.as_ref());
        out[168..200].copy_from_slice(self.mint.as_ref());
        out[200..208].copy_from_slice(&self.total.to_le_bytes());
        out[208..216].copy_from_slice(&self.fee.to_le_bytes());
        out[216..224].copy_from_slice(&self.opened_at.to_le_bytes());
        out[224..232].copy_from_slice(&self.fallback_at.to_le_bytes());
    }

    pub fn unpack(d: &[u8]) -> Result<Escrow, ProgramError> {
        if d.len() != ESCROW_LEN || d[0] != VERSION {
            return fail(EscrowError::UnknownEscrow);
        }
        let key = |at: usize| Pubkey::new_from_array(d[at..at + 32].try_into().unwrap());
        let u64_at = |at: usize| u64::from_le_bytes(d[at..at + 8].try_into().unwrap());
        Ok(Escrow {
            state: d[1],
            frozen: d[2] != 0,
            bump: d[3],
            vault_bump: d[4],
            trade_id: d[8..40].try_into().unwrap(),
            seller: key(40),
            buyer: key(72),
            arbiter: key(104),
            fee_receiver: key(136),
            mint: key(168),
            total: u64_at(200),
            fee: u64_at(208),
            opened_at: u64_at(216) as i64,
            fallback_at: u64_at(224) as i64,
        })
    }
}

pub fn auth_message(program_id: &Pubkey, escrow: &Pubkey, action: u8) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_DOMAIN.len() + 65);
    m.extend_from_slice(AUTH_DOMAIN);
    m.extend_from_slice(program_id.as_ref());
    m.extend_from_slice(escrow.as_ref());
    m.push(action);
    m
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let end = self.at.checked_add(n).ok_or(EscrowError::BadInstruction)?;
        let s = self.data.get(self.at..end).ok_or(EscrowError::BadInstruction)?;
        self.at = end;
        Ok(s)
    }

    fn key(&mut self) -> Result<Pubkey, ProgramError> {
        Ok(Pubkey::new_from_array(self.take(32)?.try_into().unwrap()))
    }

    fn bytes32(&mut self) -> Result<[u8; 32], ProgramError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }

    fn done(&self) -> ProgramResult {
        if self.at == self.data.len() {
            Ok(())
        } else {
            fail(EscrowError::BadInstruction)
        }
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&tag, rest) = data.split_first().ok_or(EscrowError::BadInstruction)?;
    let mut r = Reader { data: rest, at: 0 };
    match tag {
        IX_OPEN => open(program_id, accounts, &mut r),
        IX_RELEASE => {
            r.done()?;
            act(program_id, accounts, Act::Release)
        }
        IX_CANCEL => {
            r.done()?;
            act(program_id, accounts, Act::Cancel)
        }
        IX_RESOLVE => {
            let to_buyer = match r.u8()? {
                0 => false,
                1 => true,
                _ => return fail(EscrowError::BadInstruction),
            };
            r.done()?;
            act(program_id, accounts, Act::Resolve(to_buyer))
        }
        IX_FREEZE => {
            r.done()?;
            freeze(program_id, accounts, false)
        }
        IX_RECLAIM => {
            r.done()?;
            act(program_id, accounts, Act::Reclaim)
        }
        IX_CANCEL_FOR => {
            r.done()?;
            act(program_id, accounts, Act::CancelFor)
        }
        IX_FREEZE_FOR => {
            r.done()?;
            freeze(program_id, accounts, true)
        }
        _ => fail(EscrowError::BadInstruction),
    }
}

fn system_ix(tag: u32, body: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = tag.to_le_bytes().to_vec();
    data.extend_from_slice(body);
    Instruction { program_id: SYSTEM_PROGRAM_ID, accounts, data }
}

fn create_pda<'a>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    lamports: u64,
    space: usize,
    owner: &Pubkey,
    seeds: &[&[u8]],
) -> ProgramResult {
    let current = target.lamports();
    if current == 0 {
        let mut body = lamports.to_le_bytes().to_vec();
        body.extend_from_slice(&(space as u64).to_le_bytes());
        body.extend_from_slice(owner.as_ref());
        let ix = system_ix(0, &body, vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*target.key, true)]);
        return invoke_signed(&ix, &[payer.clone(), target.clone(), system.clone()], &[seeds]);
    }
    if lamports > current {
        let ix = system_ix(
            2,
            &(lamports - current).to_le_bytes(),
            vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*target.key, false)],
        );
        invoke(&ix, &[payer.clone(), target.clone(), system.clone()])?;
    }
    let allocate = system_ix(8, &(space as u64).to_le_bytes(), vec![AccountMeta::new(*target.key, true)]);
    invoke_signed(&allocate, &[target.clone(), system.clone()], &[seeds])?;
    let assign = system_ix(1, owner.as_ref(), vec![AccountMeta::new(*target.key, true)]);
    invoke_signed(&assign, &[target.clone(), system.clone()], &[seeds])
}

fn token_ix(data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction { program_id: TOKEN_PROGRAM_ID, accounts, data }
}

fn transfer_checked<'a>(
    token_program: &AccountInfo<'a>,
    source: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    dest: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    decimals: u8,
    seeds: Option<&[&[u8]]>,
) -> ProgramResult {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let ix = token_ix(
        data,
        vec![
            AccountMeta::new(*source.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*dest.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
    );
    let infos = [source.clone(), mint.clone(), dest.clone(), authority.clone(), token_program.clone()];
    match seeds {
        Some(s) => invoke_signed(&ix, &infos, &[s]),
        None => invoke(&ix, &infos),
    }
}

struct TokenAccount {
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
}

fn token_account(info: &AccountInfo) -> Result<TokenAccount, ProgramError> {
    if *info.owner != TOKEN_PROGRAM_ID || info.data_len() != TOKEN_ACCOUNT_LEN {
        return fail(EscrowError::BadAccount);
    }
    let d = info.try_borrow_data()?;
    if d[108] != 1 {
        return fail(EscrowError::BadAccount);
    }
    Ok(TokenAccount {
        mint: Pubkey::new_from_array(d[0..32].try_into().unwrap()),
        owner: Pubkey::new_from_array(d[32..64].try_into().unwrap()),
        amount: u64::from_le_bytes(d[64..72].try_into().unwrap()),
    })
}

fn mint_decimals(info: &AccountInfo) -> Result<u8, ProgramError> {
    if *info.owner != TOKEN_PROGRAM_ID || info.data_len() != MINT_LEN {
        return fail(EscrowError::BadAccount);
    }
    let d = info.try_borrow_data()?;
    if d[45] != 1 {
        return fail(EscrowError::BadAccount);
    }
    Ok(d[44])
}

fn open(program_id: &Pubkey, accounts: &[AccountInfo], r: &mut Reader) -> ProgramResult {
    let trade_id = r.bytes32()?;
    let buyer = r.key()?;
    let arbiter = r.key()?;
    let fee_receiver = r.key()?;
    let mint = r.key()?;
    let total = r.u64()?;
    let fee = r.u64()?;
    let fallback_delay = r.u64()? as i64;
    r.done()?;

    let it = &mut accounts.iter();
    let seller = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let system = next_account_info(it)?;
    if !seller.is_signer || !seller.is_writable || !escrow.is_writable {
        return fail(EscrowError::BadAccount);
    }
    if *system.key != SYSTEM_PROGRAM_ID {
        return fail(EscrowError::BadAccount);
    }
    let none = Pubkey::default();
    if buyer == none || arbiter == none || fee_receiver == none {
        return fail(EscrowError::BadParty);
    }
    if buyer == *seller.key || arbiter == *seller.key || arbiter == buyer {
        return fail(EscrowError::BadParty);
    }
    if total == 0 || (fee as u128) * 10_000 > (total as u128) * MAX_FEE_BPS {
        return fail(EscrowError::BadAmount);
    }
    if !(MIN_FALLBACK..=MAX_FALLBACK).contains(&fallback_delay) {
        return fail(EscrowError::BadFallback);
    }
    let (escrow_key, bump) = Pubkey::find_program_address(&[ESCROW_SEED, &trade_id, seller.key.as_ref()], program_id);
    if *escrow.key != escrow_key {
        return fail(EscrowError::BadAccount);
    }
    if *escrow.owner != SYSTEM_PROGRAM_ID || !escrow.data_is_empty() {
        return fail(EscrowError::AlreadyUsed);
    }
    let rent = Rent::get()?;
    let native = mint == none;
    let escrow_lamports = rent
        .minimum_balance(ESCROW_LEN)
        .checked_add(if native { total } else { 0 })
        .ok_or(EscrowError::BadAmount)?;
    let escrow_seeds: &[&[u8]] = &[ESCROW_SEED, &trade_id, seller.key.as_ref(), &[bump]];
    create_pda(seller, escrow, system, escrow_lamports, ESCROW_LEN, program_id, escrow_seeds)?;

    let mut vault_bump = 0u8;
    if !native {
        let mint_info = next_account_info(it)?;
        let seller_token = next_account_info(it)?;
        let vault = next_account_info(it)?;
        let token_program = next_account_info(it)?;
        if *token_program.key != TOKEN_PROGRAM_ID || *mint_info.key != mint || !vault.is_writable {
            return fail(EscrowError::BadAccount);
        }
        let decimals = mint_decimals(mint_info)?;
        let (vault_key, vb) = Pubkey::find_program_address(&[VAULT_SEED, escrow_key.as_ref()], program_id);
        if *vault.key != vault_key {
            return fail(EscrowError::BadAccount);
        }
        if *vault.owner != SYSTEM_PROGRAM_ID || !vault.data_is_empty() {
            return fail(EscrowError::AlreadyUsed);
        }
        vault_bump = vb;
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, escrow_key.as_ref(), &[vb]];
        create_pda(
            seller,
            vault,
            system,
            rent.minimum_balance(TOKEN_ACCOUNT_LEN),
            TOKEN_ACCOUNT_LEN,
            &TOKEN_PROGRAM_ID,
            vault_seeds,
        )?;
        let mut init = vec![18u8];
        init.extend_from_slice(escrow_key.as_ref());
        let init_ix = token_ix(
            init,
            vec![AccountMeta::new(vault_key, false), AccountMeta::new_readonly(mint, false)],
        );
        invoke(&init_ix, &[vault.clone(), mint_info.clone(), token_program.clone()])?;
        transfer_checked(token_program, seller_token, mint_info, vault, seller, total, decimals, None)?;
        let held = token_account(vault)?;
        if held.amount != total || held.mint != mint || held.owner != escrow_key {
            return fail(EscrowError::BadAmount);
        }
    }

    let now = Clock::get()?.unix_timestamp;
    let e = Escrow {
        state: STATE_FUNDED,
        frozen: false,
        bump,
        vault_bump,
        trade_id,
        seller: *seller.key,
        buyer,
        arbiter,
        fee_receiver,
        mint,
        total,
        fee,
        opened_at: now,
        fallback_at: now.checked_add(fallback_delay).ok_or(EscrowError::BadFallback)?,
    };
    e.pack(&mut escrow.try_borrow_mut_data()?);
    msg!("ego-escrow open total={} fee={} fallback_at={}", total, fee, e.fallback_at);
    Ok(())
}

fn load_escrow(program_id: &Pubkey, info: &AccountInfo) -> Result<Escrow, ProgramError> {
    if *info.owner != *program_id {
        return fail(EscrowError::UnknownEscrow);
    }
    let e = Escrow::unpack(&info.try_borrow_data()?)?;
    let expected = Pubkey::create_program_address(&[ESCROW_SEED, &e.trade_id, e.seller.as_ref(), &[e.bump]], program_id)
        .map_err(|_| EscrowError::UnknownEscrow)?;
    if expected != *info.key {
        return fail(EscrowError::UnknownEscrow);
    }
    if e.state != STATE_FUNDED {
        return fail(EscrowError::NotFunded);
    }
    if !info.is_writable {
        return fail(EscrowError::BadAccount);
    }
    Ok(e)
}

fn require_signed_by(program_id: &Pubkey, sysvar: &AccountInfo, escrow: &Pubkey, signer: &Pubkey, action: u8) -> ProgramResult {
    if *sysvar.key != INSTRUCTIONS_SYSVAR_ID {
        return fail(EscrowError::BadAccount);
    }
    let current = ix_sysvar::load_current_index_checked(sysvar)?;
    if current == 0 {
        return fail(EscrowError::BadSignature);
    }
    let ix = ix_sysvar::load_instruction_at_checked(current as usize - 1, sysvar)?;
    if ix.program_id != ED25519_PROGRAM_ID {
        return fail(EscrowError::BadSignature);
    }
    let d = &ix.data;
    if d.len() < 16 || d[0] != 1 {
        return fail(EscrowError::BadSignature);
    }
    let field = |i: usize| u16::from_le_bytes([d[2 + 2 * i], d[3 + 2 * i]]);
    let (sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) = (field(1), field(2), field(3), field(4), field(5), field(6));
    if sig_ix != u16::MAX || pk_ix != u16::MAX || msg_ix != u16::MAX {
        return fail(EscrowError::BadSignature);
    }
    let slice = |off: u16, len: usize| d.get(off as usize..off as usize + len).ok_or(EscrowError::BadSignature);
    let pk = slice(pk_off, 32)?;
    let message = slice(msg_off, msg_len as usize)?;
    if pk != signer.as_ref() || message != auth_message(program_id, escrow, action).as_slice() {
        return fail(EscrowError::BadSignature);
    }
    Ok(())
}

fn freeze(program_id: &Pubkey, accounts: &[AccountInfo], by_signature: bool) -> ProgramResult {
    let it = &mut accounts.iter();
    let actor = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let mut e = load_escrow(program_id, escrow)?;
    if by_signature {
        require_signed_by(program_id, actor, escrow.key, &e.buyer, ACTION_FREEZE)?;
    } else if !actor.is_signer || (*actor.key != e.buyer && *actor.key != e.arbiter) {
        return fail(EscrowError::NotAllowed);
    }
    if e.frozen {
        return fail(EscrowError::NotAllowed);
    }
    e.frozen = true;
    e.pack(&mut escrow.try_borrow_mut_data()?);
    msg!("ego-escrow frozen");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Release,
    Cancel,
    Resolve(bool),
    Reclaim,
    CancelFor,
}

fn act(program_id: &Pubkey, accounts: &[AccountInfo], action: Act) -> ProgramResult {
    let it = &mut accounts.iter();
    let actor = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let e = load_escrow(program_id, escrow)?;
    let signed_by = |who: &Pubkey| actor.is_signer && actor.key == who;
    let to_buyer = match action {
        Act::Release if signed_by(&e.seller) => true,
        Act::Cancel if signed_by(&e.buyer) => false,
        Act::Resolve(to_buyer) if signed_by(&e.arbiter) => to_buyer,
        Act::Reclaim if signed_by(&e.seller) => {
            if e.frozen {
                return fail(EscrowError::NotAllowed);
            }
            if Clock::get()?.unix_timestamp < e.fallback_at {
                return fail(EscrowError::TooEarly);
            }
            false
        }
        Act::CancelFor => {
            require_signed_by(program_id, actor, escrow.key, &e.buyer, ACTION_CANCEL)?;
            false
        }
        _ => return fail(EscrowError::NotAllowed),
    };
    let seller = next_account_info(it)?;
    let payee = next_account_info(it)?;
    let fee_payee = if to_buyer { Some(next_account_info(it)?) } else { None };
    if *seller.key != e.seller || !seller.is_writable || !payee.is_writable {
        return fail(EscrowError::BadAccount);
    }
    let fee = if to_buyer { e.fee } else { 0 };

    if e.is_native() {
        let expected_payee = if to_buyer { e.buyer } else { e.seller };
        if *payee.key != expected_payee {
            return fail(EscrowError::BadAccount);
        }
        if let Some(f) = fee_payee {
            if *f.key != e.fee_receiver || !f.is_writable {
                return fail(EscrowError::BadAccount);
            }
        }
        let to_payee = e.total - fee;
        move_lamports(escrow, payee, to_payee)?;
        if let (Some(f), true) = (fee_payee, fee > 0) {
            move_lamports(escrow, f, fee)?;
        }
    } else {
        let vault = next_account_info(it)?;
        let mint_info = next_account_info(it)?;
        let token_program = next_account_info(it)?;
        if *token_program.key != TOKEN_PROGRAM_ID || *mint_info.key != e.mint || !vault.is_writable {
            return fail(EscrowError::BadAccount);
        }
        let vault_key = Pubkey::create_program_address(&[VAULT_SEED, escrow.key.as_ref(), &[e.vault_bump]], program_id)
            .map_err(|_| EscrowError::BadAccount)?;
        if *vault.key != vault_key {
            return fail(EscrowError::BadAccount);
        }
        let decimals = mint_decimals(mint_info)?;
        let held = token_account(vault)?.amount;
        if held < e.total {
            return fail(EscrowError::BadAmount);
        }
        let dest = token_account(payee)?;
        let expected_owner = if to_buyer { e.buyer } else { e.seller };
        if dest.owner != expected_owner || dest.mint != e.mint {
            return fail(EscrowError::BadAccount);
        }
        let fee_dest = match (fee_payee, fee > 0) {
            (Some(f), true) => {
                let t = token_account(f)?;
                if t.owner != e.fee_receiver || t.mint != e.mint || !f.is_writable {
                    return fail(EscrowError::BadAccount);
                }
                Some(f)
            }
            _ => None,
        };
        let seeds: &[&[u8]] = &[ESCROW_SEED, &e.trade_id, e.seller.as_ref(), &[e.bump]];
        transfer_checked(token_program, vault, mint_info, payee, escrow, held - fee, decimals, Some(seeds))?;
        if let Some(f) = fee_dest {
            transfer_checked(token_program, vault, mint_info, f, escrow, fee, decimals, Some(seeds))?;
        }
        let close = token_ix(
            vec![9u8],
            vec![
                AccountMeta::new(vault_key, false),
                AccountMeta::new(*seller.key, false),
                AccountMeta::new_readonly(*escrow.key, true),
            ],
        );
        invoke_signed(&close, &[vault.clone(), seller.clone(), escrow.clone(), token_program.clone()], &[seeds])?;
    }

    let rest = escrow.lamports();
    move_lamports(escrow, seller, rest)?;
    escrow.try_borrow_mut_data()?.fill(0);
    escrow.resize(0)?;
    escrow.assign(&SYSTEM_PROGRAM_ID);
    if to_buyer {
        msg!("ego-escrow released to_buyer={} fee={}", e.total - fee, fee);
    } else {
        msg!("ego-escrow refunded to_seller={}", e.total);
    }
    Ok(())
}

fn move_lamports(from: &AccountInfo, to: &AccountInfo, amount: u64) -> ProgramResult {
    if amount == 0 || from.key == to.key {
        return Ok(());
    }
    let mut src = from.try_borrow_mut_lamports()?;
    let mut dst = to.try_borrow_mut_lamports()?;
    **src = src.checked_sub(amount).ok_or(EscrowError::BadAmount)?;
    **dst = dst.checked_add(amount).ok_or(EscrowError::BadAmount)?;
    Ok(())
}
