//! Monero protocol helpers for Nebula's partially-trusted bridge.
//!
//! This crate replaces Nebula's previous `len >= 20` Monero-address stub with real validation:
//! Monero Base58 decoding, an original-Keccak-256 checksum check, and recognition of the
//! network/address-kind prefix byte. Later phases extend it with `tx_extra` parsing and
//! view-key amount proofs so bridge observers can verify deposits against a Monero daemon.

pub mod base58;
pub mod client;
pub mod tx_extra;
pub mod verify;

use core::fmt;
use sha3::{Digest, Keccak256};

pub use base58::Base58Error;

const PREFIX_LEN: usize = 1;
const KEY_LEN: usize = 32;
const PAYMENT_ID_LEN: usize = 8;
const CHECKSUM_LEN: usize = 4;

/// Which Monero network an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoneroNetwork {
    Mainnet,
    Testnet,
    Stagenet,
}

/// The kind of Monero address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoneroAddressKind {
    /// A standard primary or subaddress-free address.
    Standard,
    /// A standard address with an embedded 8-byte payment id.
    Integrated,
    /// A subaddress.
    Subaddress,
}

/// The decoded classification of a Monero address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoneroAddressInfo {
    pub network: MoneroNetwork,
    pub kind: MoneroAddressKind,
    pub prefix: u8,
}

/// An error validating a Monero address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoneroAddressError {
    /// The address string was empty.
    Empty,
    /// The Base58 body failed to decode.
    Base58(Base58Error),
    /// The decoded body was shorter than the minimum address length.
    TooShort(usize),
    /// The trailing 4-byte Keccak-256 checksum did not match the body.
    BadChecksum,
    /// The leading network/kind prefix byte is not a recognised Monero prefix.
    UnknownPrefix(u8),
    /// The decoded length does not match the length implied by the prefix.
    WrongLength { expected: usize, actual: usize },
}

impl fmt::Display for MoneroAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MoneroAddressError::Empty => write!(f, "monero address must not be empty"),
            MoneroAddressError::Base58(error) => write!(f, "monero address base58: {error}"),
            MoneroAddressError::TooShort(len) => {
                write!(f, "monero address decodes to only {len} bytes")
            }
            MoneroAddressError::BadChecksum => write!(f, "monero address checksum mismatch"),
            MoneroAddressError::UnknownPrefix(prefix) => {
                write!(f, "monero address has unknown network prefix {prefix}")
            }
            MoneroAddressError::WrongLength { expected, actual } => write!(
                f,
                "monero address length {actual} does not match expected {expected} for its kind"
            ),
        }
    }
}

impl std::error::Error for MoneroAddressError {}

impl From<Base58Error> for MoneroAddressError {
    fn from(error: Base58Error) -> Self {
        MoneroAddressError::Base58(error)
    }
}

fn classify_prefix(prefix: u8) -> Option<(MoneroNetwork, MoneroAddressKind)> {
    use MoneroAddressKind::*;
    use MoneroNetwork::*;
    Some(match prefix {
        18 => (Mainnet, Standard),
        19 => (Mainnet, Integrated),
        42 => (Mainnet, Subaddress),
        53 => (Testnet, Standard),
        54 => (Testnet, Integrated),
        63 => (Testnet, Subaddress),
        24 => (Stagenet, Standard),
        25 => (Stagenet, Integrated),
        36 => (Stagenet, Subaddress),
        _ => return None,
    })
}

fn expected_len(kind: MoneroAddressKind) -> usize {
    match kind {
        MoneroAddressKind::Integrated => PREFIX_LEN + 2 * KEY_LEN + PAYMENT_ID_LEN + CHECKSUM_LEN,
        MoneroAddressKind::Standard | MoneroAddressKind::Subaddress => {
            PREFIX_LEN + 2 * KEY_LEN + CHECKSUM_LEN
        }
    }
}

/// Decode and validate a Monero address, returning its network and kind.
///
/// Validation checks: Base58 decode, the original-Keccak-256 checksum, a recognised network
/// prefix byte, and that the decoded length matches that prefix's address kind.
pub fn parse_address(address: &str) -> Result<MoneroAddressInfo, MoneroAddressError> {
    if address.trim().is_empty() {
        return Err(MoneroAddressError::Empty);
    }
    let data = base58::decode(address)?;
    let minimum = PREFIX_LEN + 2 * KEY_LEN + CHECKSUM_LEN;
    if data.len() < minimum {
        return Err(MoneroAddressError::TooShort(data.len()));
    }
    let (body, checksum) = data.split_at(data.len() - CHECKSUM_LEN);
    let hash = Keccak256::digest(body);
    if checksum != &hash[..CHECKSUM_LEN] {
        return Err(MoneroAddressError::BadChecksum);
    }
    // All recognised Monero prefixes are < 128, so the leading varint is a single byte.
    let prefix = data[0];
    let (network, kind) =
        classify_prefix(prefix).ok_or(MoneroAddressError::UnknownPrefix(prefix))?;
    let expected = expected_len(kind);
    if data.len() != expected {
        return Err(MoneroAddressError::WrongLength {
            expected,
            actual: data.len(),
        });
    }
    Ok(MoneroAddressInfo {
        network,
        kind,
        prefix,
    })
}

/// Returns whether `address` is a well-formed Monero address of any network/kind.
pub fn is_valid_address(address: &str) -> bool {
    parse_address(address).is_ok()
}

/// Validate a Monero address, returning a `String` error to fit Nebula's `Result<_, String>` APIs.
pub fn validate_address(address: &str) -> Result<MoneroAddressInfo, String> {
    parse_address(address).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_address(prefix: u8, keys: &[u8]) -> String {
        let mut body = vec![prefix];
        body.extend_from_slice(keys);
        let checksum = Keccak256::digest(&body);
        body.extend_from_slice(&checksum[..CHECKSUM_LEN]);
        base58::encode(&body)
    }

    #[test]
    fn parses_self_constructed_addresses_for_each_network() {
        let keys = [7u8; 64];
        for (prefix, network, kind) in [
            (18u8, MoneroNetwork::Mainnet, MoneroAddressKind::Standard),
            (42, MoneroNetwork::Mainnet, MoneroAddressKind::Subaddress),
            (53, MoneroNetwork::Testnet, MoneroAddressKind::Standard),
            (24, MoneroNetwork::Stagenet, MoneroAddressKind::Standard),
        ] {
            let address = build_address(prefix, &keys);
            let info = parse_address(&address).unwrap();
            assert_eq!(info.network, network);
            assert_eq!(info.kind, kind);
            assert_eq!(info.prefix, prefix);
        }
    }

    #[test]
    fn parses_integrated_address_length() {
        // Integrated addresses carry an extra 8-byte payment id.
        let keys = [9u8; 64 + PAYMENT_ID_LEN];
        let address = build_address(19, &keys);
        let info = parse_address(&address).unwrap();
        assert_eq!(info.kind, MoneroAddressKind::Integrated);
    }

    #[test]
    fn parses_real_mainnet_donation_address() {
        // The official Monero project donation address (mainnet standard, prefix 18).
        let donation = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
        let info = parse_address(donation).unwrap();
        assert_eq!(info.network, MoneroNetwork::Mainnet);
        assert_eq!(info.kind, MoneroAddressKind::Standard);
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let address = build_address(18, &[7u8; 64]);
        let mut chars: Vec<char> = address.chars().collect();
        let middle = chars.len() / 2;
        chars[middle] = if chars[middle] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        assert!(parse_address(&corrupted).is_err());
    }

    #[test]
    fn rejects_unknown_prefix() {
        let address = build_address(200, &[1u8; 64]);
        // prefix 200 is > 127 so it is not a single-byte varint Monero prefix; it still decodes
        // and checksums, but classification fails.
        assert!(matches!(
            parse_address(&address),
            Err(MoneroAddressError::UnknownPrefix(200))
                | Err(MoneroAddressError::WrongLength { .. })
        ));
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert_eq!(parse_address(""), Err(MoneroAddressError::Empty));
        assert!(parse_address("not-a-real-address").is_err());
        assert!(!is_valid_address("monero-address"));
    }
}
