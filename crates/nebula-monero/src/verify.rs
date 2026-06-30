//! Deposit verification logic for Nebula's partially-trusted bridge.
//!
//! A bridge observer must not credit `nXMR` on the say-so of a signed JSON root; it must confirm
//! the Monero deposit actually happened. This module holds the pure decision function
//! [`verify_deposit`] — given a wallet-rpc payment proof and the transaction's `tx_extra`, it
//! decides whether a claimed deposit is real — plus the [`MoneroRpc`] transport trait the runtime
//! injects (a real monerod/wallet-rpc client, or a stub in tests). The decision logic is fully
//! testable without a live Monero node.

use core::fmt;

use crate::tx_extra::{nebula_account_binding, parse_tx_extra};
use crate::{parse_address, MoneroAddressInfo};

/// A monero-wallet-rpc `check_tx_key` result: proof that a transaction paid a given address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletTxProof {
    /// Atomic units (piconero) the checked address received in this transaction.
    pub received_atomic: u128,
    /// Number of confirmations the transaction has (0 while in the mempool).
    pub confirmations: u64,
    /// Whether the transaction is still unconfirmed in the mempool.
    pub in_pool: bool,
}

/// What an observer claims about a deposit, to be checked against Monero.
#[derive(Debug, Clone)]
pub struct DepositClaim<'a> {
    /// The atomic amount (piconero) the deposit claims to have paid the bridge.
    pub expected_atomic: u128,
    /// The minimum confirmations required before the deposit may be credited.
    pub min_confirmations: u64,
    /// The Monero address the deposit must have paid (the bridge custody address).
    pub bridge_address: &'a str,
    /// If set, the deposit's `tx_extra` must bind exactly this Nebula account id.
    pub required_account_binding: Option<&'a str>,
}

/// Why a claimed deposit failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositRejection {
    /// The configured bridge address is not a valid Monero address.
    InvalidBridgeAddress(String),
    /// The transaction is still in the mempool (unconfirmed).
    StillInPool,
    /// The transaction does not yet have enough confirmations.
    InsufficientConfirmations { have: u64, need: u64 },
    /// The amount paid does not equal the claimed amount.
    AmountMismatch { received: u128, expected: u128 },
    /// The `tx_extra` blob could not be parsed.
    TxExtra(String),
    /// An account binding was required but the `tx_extra` carried none.
    MissingAccountBinding { expected: String },
    /// The `tx_extra` bound a different Nebula account than claimed.
    AccountBindingMismatch { found: String, expected: String },
}

impl fmt::Display for DepositRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DepositRejection::InvalidBridgeAddress(error) => {
                write!(f, "bridge address invalid: {error}")
            }
            DepositRejection::StillInPool => {
                write!(f, "deposit transaction is still in the mempool")
            }
            DepositRejection::InsufficientConfirmations { have, need } => {
                write!(f, "deposit has {have} confirmations, needs {need}")
            }
            DepositRejection::AmountMismatch { received, expected } => {
                write!(
                    f,
                    "deposit paid {received} atomic units, expected {expected}"
                )
            }
            DepositRejection::TxExtra(error) => write!(f, "deposit tx_extra invalid: {error}"),
            DepositRejection::MissingAccountBinding { expected } => {
                write!(
                    f,
                    "deposit tx_extra is missing the required account binding {expected}"
                )
            }
            DepositRejection::AccountBindingMismatch { found, expected } => {
                write!(
                    f,
                    "deposit tx_extra binds account {found}, expected {expected}"
                )
            }
        }
    }
}

impl std::error::Error for DepositRejection {}

/// Decide whether a claimed deposit is real, given the wallet-rpc payment proof and the
/// transaction's `tx_extra`. Returns the validated bridge-address classification on success.
pub fn verify_deposit(
    claim: &DepositClaim,
    proof: &WalletTxProof,
    tx_extra: &[u8],
) -> Result<MoneroAddressInfo, DepositRejection> {
    let bridge_info = parse_address(claim.bridge_address)
        .map_err(|error| DepositRejection::InvalidBridgeAddress(error.to_string()))?;

    if proof.in_pool {
        return Err(DepositRejection::StillInPool);
    }
    if proof.confirmations < claim.min_confirmations {
        return Err(DepositRejection::InsufficientConfirmations {
            have: proof.confirmations,
            need: claim.min_confirmations,
        });
    }
    if proof.received_atomic != claim.expected_atomic {
        return Err(DepositRejection::AmountMismatch {
            received: proof.received_atomic,
            expected: claim.expected_atomic,
        });
    }

    if let Some(expected_account) = claim.required_account_binding {
        let parsed = parse_tx_extra(tx_extra)
            .map_err(|error| DepositRejection::TxExtra(error.to_string()))?;
        let binding = parsed.nonce.as_deref().and_then(nebula_account_binding);
        match binding {
            None => {
                return Err(DepositRejection::MissingAccountBinding {
                    expected: expected_account.to_string(),
                })
            }
            Some(found) if found != expected_account => {
                return Err(DepositRejection::AccountBindingMismatch {
                    found,
                    expected: expected_account.to_string(),
                })
            }
            Some(_) => {}
        }
    }

    Ok(bridge_info)
}

/// Transport an observer uses to fetch deposit evidence from a Monero node. The runtime injects a
/// real monerod/wallet-rpc client; tests inject a stub. Keeping this a trait lets the
/// verification logic stay node-independent and unit-testable.
pub trait MoneroRpc {
    /// Prove, via a transaction secret key, how much `address` received in transaction `txid`.
    /// Mirrors monero-wallet-rpc `check_tx_key`.
    fn check_tx_key(
        &self,
        txid: &str,
        tx_key: &str,
        address: &str,
    ) -> Result<WalletTxProof, String>;

    /// Fetch the raw `tx_extra` bytes of transaction `txid`. Mirrors monerod `get_transactions`.
    fn tx_extra(&self, txid: &str) -> Result<Vec<u8>, String>;
}

/// Verify a deposit by fetching its proof and `tx_extra` through `rpc`, then applying
/// [`verify_deposit`]. Transport errors are surfaced as `Err(String)`; a well-formed but invalid
/// deposit is surfaced as `Ok(Err(DepositRejection))`.
pub fn verify_deposit_via<R: MoneroRpc>(
    rpc: &R,
    txid: &str,
    tx_key: &str,
    claim: &DepositClaim,
) -> Result<Result<MoneroAddressInfo, DepositRejection>, String> {
    let proof = rpc.check_tx_key(txid, tx_key, claim.bridge_address)?;
    let tx_extra = rpc.tx_extra(txid)?;
    Ok(verify_deposit(claim, &proof, &tx_extra))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_extra::encode_nebula_account_binding;

    // A valid testnet bridge address (prefix 53), generated deterministically.
    const BRIDGE: &str =
        "9spAQWBqoTv3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ2vgNZzY";

    fn good_proof() -> WalletTxProof {
        WalletTxProof {
            received_atomic: 1_000_000_000_000,
            confirmations: 12,
            in_pool: false,
        }
    }

    fn claim<'a>(binding: Option<&'a str>) -> DepositClaim<'a> {
        DepositClaim {
            expected_atomic: 1_000_000_000_000,
            min_confirmations: 10,
            bridge_address: BRIDGE,
            required_account_binding: binding,
        }
    }

    fn extra_binding(account: &str) -> Vec<u8> {
        let nonce = encode_nebula_account_binding(account);
        let mut extra = vec![0x02u8, nonce.len() as u8];
        extra.extend_from_slice(&nonce);
        extra
    }

    #[test]
    fn accepts_a_confirmed_matching_deposit() {
        assert!(verify_deposit(&claim(None), &good_proof(), &[]).is_ok());
    }

    #[test]
    fn rejects_mempool_and_unconfirmed() {
        let mut proof = good_proof();
        proof.in_pool = true;
        assert_eq!(
            verify_deposit(&claim(None), &proof, &[]),
            Err(DepositRejection::StillInPool)
        );

        let proof = WalletTxProof {
            confirmations: 3,
            in_pool: false,
            ..good_proof()
        };
        assert_eq!(
            verify_deposit(&claim(None), &proof, &[]),
            Err(DepositRejection::InsufficientConfirmations { have: 3, need: 10 })
        );
    }

    #[test]
    fn rejects_amount_mismatch() {
        let proof = WalletTxProof {
            received_atomic: 999,
            ..good_proof()
        };
        assert_eq!(
            verify_deposit(&claim(None), &proof, &[]),
            Err(DepositRejection::AmountMismatch {
                received: 999,
                expected: 1_000_000_000_000
            })
        );
    }

    #[test]
    fn rejects_invalid_bridge_address() {
        let bad = DepositClaim {
            bridge_address: "not-a-monero-address",
            ..claim(None)
        };
        assert!(matches!(
            verify_deposit(&bad, &good_proof(), &[]),
            Err(DepositRejection::InvalidBridgeAddress(_))
        ));
    }

    #[test]
    fn enforces_account_binding() {
        let account = "nblahybrid-ed25519-mldsa65:abc";
        // Correct binding accepted.
        assert!(verify_deposit(
            &claim(Some(account)),
            &good_proof(),
            &extra_binding(account)
        )
        .is_ok());
        // Missing binding rejected.
        assert_eq!(
            verify_deposit(&claim(Some(account)), &good_proof(), &[]),
            Err(DepositRejection::MissingAccountBinding {
                expected: account.to_string()
            })
        );
        // Wrong binding rejected.
        let other = extra_binding("nblasomeoneelse");
        assert_eq!(
            verify_deposit(&claim(Some(account)), &good_proof(), &other),
            Err(DepositRejection::AccountBindingMismatch {
                found: "nblasomeoneelse".to_string(),
                expected: account.to_string()
            })
        );
    }

    struct StubRpc {
        proof: WalletTxProof,
        tx_extra: Vec<u8>,
    }
    impl MoneroRpc for StubRpc {
        fn check_tx_key(&self, _: &str, _: &str, _: &str) -> Result<WalletTxProof, String> {
            Ok(self.proof.clone())
        }
        fn tx_extra(&self, _: &str) -> Result<Vec<u8>, String> {
            Ok(self.tx_extra.clone())
        }
    }

    #[test]
    fn verifies_through_a_stub_transport() {
        let account = "nblaaccount";
        let rpc = StubRpc {
            proof: good_proof(),
            tx_extra: extra_binding(account),
        };
        let result = verify_deposit_via(&rpc, "txid", "txkey", &claim(Some(account))).unwrap();
        assert!(result.is_ok());
    }
}
