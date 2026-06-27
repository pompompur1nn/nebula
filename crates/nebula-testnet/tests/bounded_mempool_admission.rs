use ed25519_dalek::{Signer, SigningKey};
use nebula_testnet::{
    runtime::{NebulaRuntime, RuntimeConfig, RuntimeTransaction},
    NBLA_SYMBOL, NXMR_SYMBOL,
};

fn bounded_mempool_config() -> RuntimeConfig {
    let mut config = RuntimeConfig::public_testnet_default();
    config.max_mempool_transactions = 1;
    config
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn account_id(seed: u8) -> String {
    hex::encode(signing_key(seed).verifying_key().to_bytes())
}

fn sign_root(seed: u8, root: &str) -> String {
    hex::encode(signing_key(seed).sign(root.as_bytes()).to_bytes())
}

fn test_transaction(seed: u8, nonce: u64, to: &str) -> RuntimeTransaction {
    test_transaction_with(seed, nonce, to, 1, 1, NBLA_SYMBOL, "bounded-mempool")
}

fn test_transaction_with(
    seed: u8,
    nonce: u64,
    to: &str,
    amount_nebulai: u128,
    gas_units: u128,
    fee_asset: &str,
    memo: &str,
) -> RuntimeTransaction {
    let mut tx = RuntimeTransaction {
        from: account_id(seed),
        to: to.to_string(),
        amount_nebulai,
        gas_units,
        gas_price_nebulai: 1,
        fee_asset: fee_asset.to_string(),
        nonce,
        signature: String::new(),
        memo: Some(format!("{memo}-{nonce}")),
    };
    tx.signature = sign_root(seed, &tx.signing_root());
    tx
}

#[test]
fn rejects_distinct_transaction_when_mempool_is_full() {
    let mut runtime = NebulaRuntime::new(bounded_mempool_config()).unwrap();
    runtime.faucet(&account_id(0x33)).unwrap();
    runtime.faucet(&account_id(0x44)).unwrap();

    runtime
        .submit_transaction(test_transaction(0x33, 0, "bob"))
        .unwrap();

    let status = runtime.status();
    assert_eq!(status.mempool_size, 1);
    assert_eq!(status.max_mempool_transactions, 1);
    assert_eq!(status.mempool_capacity_remaining, 0);
    assert_eq!(status.mempool_full_rejection_count, 0);
    assert_eq!(status.mempool_admission_rejection_count, 0);

    let error = runtime
        .submit_transaction(test_transaction(0x44, 0, "carol"))
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
    assert_eq!(status.mempool_admission_rejection_count, 0);
}

#[test]
fn rejects_missing_sender_without_consuming_mempool_capacity() {
    let mut runtime = NebulaRuntime::new(bounded_mempool_config()).unwrap();

    let error = runtime
        .submit_transaction(test_transaction(0x33, 0, "bob"))
        .unwrap_err();
    assert!(error.contains("sender"), "unexpected error: {error}");

    let status = runtime.status();
    assert_eq!(status.mempool_size, 0);
    assert_eq!(status.mempool_capacity_remaining, 1);
    assert_eq!(status.mempool_full_rejection_count, 0);
    assert_eq!(status.mempool_admission_rejection_count, 1);

    runtime.faucet(&account_id(0x44)).unwrap();
    runtime
        .submit_transaction(test_transaction(0x44, 0, "carol"))
        .unwrap();

    let status = runtime.status();
    assert_eq!(status.mempool_size, 1);
    assert_eq!(status.mempool_capacity_remaining, 0);
    assert_eq!(status.mempool_admission_rejection_count, 1);
}

#[test]
fn rejects_insufficient_nbla_before_mempool_admission() {
    let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
    runtime.faucet(&account_id(0x33)).unwrap();
    let amount = runtime.config().faucet_nbla_nebulai.checked_add(1).unwrap();

    let error = runtime
        .submit_transaction(test_transaction_with(
            0x33,
            0,
            "bob",
            amount,
            1,
            NBLA_SYMBOL,
            "too-much-nbla",
        ))
        .unwrap_err();
    assert!(
        error.contains("insufficient NBLA"),
        "unexpected error: {error}"
    );

    let status = runtime.status();
    assert_eq!(status.mempool_size, 0);
    assert_eq!(status.mempool_admission_rejection_count, 1);
    assert_eq!(status.mempool_full_rejection_count, 0);
}

#[test]
fn rejects_insufficient_nxmr_fee_before_mempool_admission() {
    let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
    runtime.faucet(&account_id(0x33)).unwrap();
    let gas_units = runtime.config().faucet_nxmr_units.checked_add(1).unwrap();

    let error = runtime
        .submit_transaction(test_transaction_with(
            0x33,
            0,
            "bob",
            1,
            gas_units,
            NXMR_SYMBOL,
            "too-much-nxmr",
        ))
        .unwrap_err();
    assert!(
        error.contains("insufficient nXMR"),
        "unexpected error: {error}"
    );

    let status = runtime.status();
    assert_eq!(status.mempool_size, 0);
    assert_eq!(status.mempool_admission_rejection_count, 1);
    assert_eq!(status.mempool_full_rejection_count, 0);
}

#[test]
fn rejects_duplicate_pending_account_nonce_before_mempool_admission() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.max_mempool_transactions = 2;
    let mut runtime = NebulaRuntime::new(config).unwrap();
    runtime.faucet(&account_id(0x33)).unwrap();

    runtime
        .submit_transaction(test_transaction_with(
            0x33,
            0,
            "bob",
            1,
            1,
            NBLA_SYMBOL,
            "first-pending",
        ))
        .unwrap();

    let error = runtime
        .submit_transaction(test_transaction_with(
            0x33,
            0,
            "carol",
            1,
            1,
            NBLA_SYMBOL,
            "second-pending",
        ))
        .unwrap_err();
    assert!(
        error.contains("pending transaction"),
        "unexpected error: {error}"
    );

    let status = runtime.status();
    assert_eq!(status.mempool_size, 1);
    assert_eq!(status.mempool_capacity_remaining, 1);
    assert_eq!(status.mempool_admission_rejection_count, 1);
    assert_eq!(status.mempool_full_rejection_count, 0);
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
