/// TPS benchmark — measures the three main bottlenecks:
///   1. Signature verification throughput (ed25519 + dilithium)
///   2. StateManager transfer execution throughput
///   3. End-to-end: build 1 000 signed transfers and execute them all
///
/// Run with:
///   cargo bench -p ego-core --bench tps
///
/// Results land in target/criterion/tps/*/report/index.html
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ego_core::{
    Account, Address, Balance, KeyPair, ShardId, StateManager, Transaction,
    TransactionPayload,
};

fn make_keypair_and_account() -> (KeyPair, Address, Account) {
    let kp = KeyPair::generate();
    let addr = Address::from_public_key(&kp.dilithium_public_key());
    let mut acct = Account::new_eoa(
        addr,
        kp.dilithium_public_key().key_data.clone(),
        kp.kyber_public_key().key_data.clone(),
    );
    acct.balance = Balance::new(u128::MAX / 2);
    acct.nonce = 0;
    (kp, addr, acct)
}

fn make_signed_transfer(kp: &KeyPair, from: Address, to: Address, nonce: u64) -> Transaction {
    let mut tx = Transaction::new(
        from,
        nonce,
        TransactionPayload::Transfer {
            to,
            amount: Balance::new(1),
            stealth_mode: false,
            memo: None,
        },
        ShardId::new(0).unwrap(),
        None,
        1,
    );
    tx.sign(kp, false).expect("sign");
    tx
}

fn bench_sig_verify(c: &mut Criterion) {
    let (kp, from, _) = make_keypair_and_account();
    let (_, to, _) = make_keypair_and_account();
    let tx = make_signed_transfer(&kp, from, to, 0);

    let mut g = c.benchmark_group("signature_verify");
    g.throughput(Throughput::Elements(1));
    g.bench_function("dilithium_ed25519", |b| {
        b.iter(|| tx.verify_signature().unwrap())
    });
    g.finish();
}

fn bench_state_execute(c: &mut Criterion) {
    let mut g = c.benchmark_group("state_execute");

    for batch in [100u64, 500, 1_000] {
        // Prepare txs outside the timed section.
        let (kp, from, from_acct) = make_keypair_and_account();
        let (_, to, to_acct) = make_keypair_and_account();

        let txs: Vec<Transaction> = (0..batch)
            .map(|nonce| make_signed_transfer(&kp, from, to, nonce))
            .collect();

        g.throughput(Throughput::Elements(batch));
        g.bench_with_input(BenchmarkId::from_parameter(batch), &batch, |b, _| {
            b.iter(|| {
                // Fresh state each iteration so nonces are valid.
                let mut sm = StateManager::new(1, 1);
                let mut fa = from_acct.clone();
                fa.balance = Balance::new(u128::MAX / 2);
                fa.nonce = 0;
                sm.set_account(fa);
                sm.set_account(to_acct.clone());

                for tx in &txs {
                    let _ = sm.execute_transaction(tx);
                }
            })
        });
    }

    g.finish();
}

fn bench_e2e_tps(c: &mut Criterion) {
    const BLOCK_SIZE: u64 = 1_000;

    let (kp, from, from_acct) = make_keypair_and_account();
    let (_, to, to_acct) = make_keypair_and_account();
    let txs: Vec<Transaction> = (0..BLOCK_SIZE)
        .map(|n| make_signed_transfer(&kp, from, to, n))
        .collect();

    let mut g = c.benchmark_group("e2e_block");
    g.throughput(Throughput::Elements(BLOCK_SIZE));
    g.bench_function("1000_transfers", |b| {
        b.iter(|| {
            let mut sm = StateManager::new(1, 1);
            let mut fa = from_acct.clone();
            fa.balance = Balance::new(u128::MAX / 2);
            fa.nonce = 0;
            sm.set_account(fa);
            sm.set_account(to_acct.clone());

            for tx in &txs {
                let _ = sm.execute_transaction(tx);
            }
        })
    });
    g.finish();
}

criterion_group!(benches, bench_sig_verify, bench_state_execute, bench_e2e_tps);
criterion_main!(benches);
