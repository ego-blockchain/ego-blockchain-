use ego_rollup::*;
use ego_core::{Address, KeyPair, Transaction, TransactionPayload, Balance, ShardId};

#[tokio::test]
async fn test_tx_rollup_transaction_processing() {
    let config = RollupConfig::default();
    let rollup_id = [1u8; 16];
    let region_id = 1;
    let keypair = KeyPair::generate();
    let operator_addr = Address::from_public_key(&keypair.public_key());
    
    let operator = TxRollupOperator::new(config, rollup_id, region_id, operator_addr)
        .expect("Failed to create TxRollupOperator");
    
    // Create test transaction with a keypair that matches the from address
    let tx_keypair = KeyPair::generate();
    let from_addr = Address::from_public_key(&tx_keypair.dilithium_public_key());
    
    let mut inner = Transaction::new(
        from_addr,
        1,
        TransactionPayload::Transfer {
            to: Address::new([2u8; 20]),
            amount: Balance::from_egoc(100),
            memo: None,
            stealth_mode: false,
        },
        ShardId::new(0).unwrap(),
        None,
        1, // chain_id
    );
    
    // Sign the transaction
    inner.sign(&tx_keypair, false)
        .expect("Failed to sign transaction");
    
    let tx = RollupTransaction::new(inner, 1, 1000);
    
    // Submit transaction
    let tx_hash = operator.submit_transaction(tx).await
        .expect("Failed to submit transaction");
    
    println!("Transaction submitted: {}", tx_hash);
    
    let metrics = operator.get_metrics().await;
    assert_eq!(metrics.transactions_received, 1);
    println!("SUCCESS: TxRollup transaction processing test passed");
}
