use ed25519_dalek::{Signer, SigningKey};
use nebula_testnet::{
    runtime::{NebulaRuntime, RuntimeConfig, RuntimeTransaction},
    NBLA_SYMBOL,
};

fn bounded_mempool_config() -> RuntimeConfig {
    let mut config = RuntimeConfig::public_testnet_default();
    config.max_mempool_transactions = 1;
    config
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x33; 32])
}

fn account_id() -> String {
    hex::encode(signing_key().verifying_key().to_bytes())
}

fn sign_root(root: &str) -> String {
    hex::encode(signing_key().sign(root.as_bytes()).to_bytes())
}

fn test_transaction(nonce: u64, to: &str) -> RuntimeTransaction {
    let mut tx = RuntimeTransaction {
        from: account_id(),
        to: to.to_string(),
        amount_nebulai: 1,
        gas_units: 1,
        gas_price_nebulai: 1,
        fee_asset: NBLA_SYMBOL.to_string(),
        nonce,
        signature: String::new(),
        memo: Some(format!("bounded-mempool-{nonce}")),
    };
    tx.signature = sign_root(&tx.signing_root());
    tx
}

#[test]
fn rejects_distinct_transaction_when_mempool_is_full() {
    let mut runtime = NebulaRuntime::new(bounded_mempool_config()).unwrap();

    runtime
        .submit_transaction(test_transaction(0, "bob"))
        .unwrap();

    let status = runtime.status();
    assert_eq!(status.mempool_size, 1);
    assert_eq!(status.max_mempool_transactions, 1);
    assert_eq!(status.mempool_capacity_remaining, 0);
    assert_eq!(status.mempool_full_rejection_count, 0);

    let error = runtime
        .submit_transaction(test_transaction(1, "carol"))
        .unwrap_err();
    assert!(
        error.contains("mempool is full"),
        "unexpected error: {error}"
    );

    let status = runtime.status();
    assert_eq!(status.mempool_size, 1);
    assert_eq!(status.max_mempool_transactions, 1);
    assert_eq!(status.mempool_capacity_remaining, 0);
    assert_eq!(status.mempool_full_rejection_count, 1);
}

#[test]
fn zero_max_mempool_transactions_is_invalid() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.max_mempool_transactions = 0;

    let error = config.validate().unwrap_err();
    assert!(
        error.contains("max_mempool_transactions"),
        "unexpected error: {error}"
    );
}
