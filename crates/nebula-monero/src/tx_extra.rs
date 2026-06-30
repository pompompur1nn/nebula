//! Parsing of Monero's `tx_extra` field.
//!
//! `tx_extra` is a flat, tag-prefixed byte blob carried by every Monero transaction. Nebula's
//! bridge reads it for two reasons: to recover the transaction public key(s) needed for view-key
//! amount proofs, and — experimentally — to let a deposit name its destination Nebula account by
//! embedding a binding in the extra-nonce field (see [`nebula_account_binding`]).
//!
//! Tags handled: `0x00` padding, `0x01` tx public key, `0x02` extra nonce, `0x04` additional
//! public keys. Any other tag stops parsing with [`TxExtraError::UnknownTag`], matching Monero's
//! refusal to guess the layout of unknown records.

use core::fmt;

const TAG_PADDING: u8 = 0x00;
const TAG_PUBKEY: u8 = 0x01;
const TAG_NONCE: u8 = 0x02;
const TAG_ADDITIONAL_PUBKEYS: u8 = 0x04;

/// Nonce sub-tag for an unencrypted 32-byte payment id.
const NONCE_PAYMENT_ID: u8 = 0x00;
/// Nonce sub-tag for an encrypted 8-byte payment id.
const NONCE_ENCRYPTED_PAYMENT_ID: u8 = 0x01;
/// Experimental Nebula nonce sub-tag carrying a destination account binding. Chosen outside the
/// range of Monero's defined nonce sub-tags (0x00/0x01) to avoid collisions.
const NEBULA_BINDING_TAG: u8 = 0xCE;

const KEY_LEN: usize = 32;

/// An error parsing a `tx_extra` blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxExtraError {
    /// The blob ended in the middle of a field.
    Truncated,
    /// A record used a tag this parser does not understand.
    UnknownTag(u8),
    /// A varint ran past the end of the blob or overflowed 64 bits.
    BadVarint,
}

impl fmt::Display for TxExtraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxExtraError::Truncated => write!(f, "tx_extra ended mid-field"),
            TxExtraError::UnknownTag(tag) => write!(f, "tx_extra has unknown tag {tag:#04x}"),
            TxExtraError::BadVarint => write!(f, "tx_extra varint is malformed"),
        }
    }
}

impl std::error::Error for TxExtraError {}

/// The decoded contents of a `tx_extra` blob that Nebula cares about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxExtra {
    /// The primary transaction public key, if present (tag `0x01`).
    pub tx_public_key: Option<[u8; KEY_LEN]>,
    /// Per-output additional transaction public keys (tag `0x04`).
    pub additional_public_keys: Vec<[u8; KEY_LEN]>,
    /// The raw extra-nonce payload, if present (tag `0x02`).
    pub nonce: Option<Vec<u8>>,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, TxExtraError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos).ok_or(TxExtraError::BadVarint)?;
        *pos += 1;
        if shift >= 64 {
            return Err(TxExtraError::BadVarint);
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], TxExtraError> {
    let end = pos.checked_add(len).ok_or(TxExtraError::Truncated)?;
    let slice = data.get(*pos..end).ok_or(TxExtraError::Truncated)?;
    *pos = end;
    Ok(slice)
}

fn read_key(data: &[u8], pos: &mut usize) -> Result<[u8; KEY_LEN], TxExtraError> {
    let slice = read_bytes(data, pos, KEY_LEN)?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(slice);
    Ok(key)
}

/// Parse a Monero `tx_extra` blob into the fields Nebula uses.
pub fn parse_tx_extra(extra: &[u8]) -> Result<TxExtra, TxExtraError> {
    let mut out = TxExtra::default();
    let mut pos = 0usize;
    while pos < extra.len() {
        let tag = extra[pos];
        pos += 1;
        match tag {
            TAG_PADDING => {
                // Padding is a run of zero bytes (typically trailing); consume them.
                while pos < extra.len() && extra[pos] == 0 {
                    pos += 1;
                }
            }
            TAG_PUBKEY => {
                let key = read_key(extra, &mut pos)?;
                // Monero keeps the first pubkey as the canonical one.
                if out.tx_public_key.is_none() {
                    out.tx_public_key = Some(key);
                }
            }
            TAG_NONCE => {
                let len = usize::from(*extra.get(pos).ok_or(TxExtraError::Truncated)?);
                pos += 1;
                let nonce = read_bytes(extra, &mut pos, len)?.to_vec();
                out.nonce = Some(nonce);
            }
            TAG_ADDITIONAL_PUBKEYS => {
                let count = read_varint(extra, &mut pos)?;
                for _ in 0..count {
                    let key = read_key(extra, &mut pos)?;
                    out.additional_public_keys.push(key);
                }
            }
            other => return Err(TxExtraError::UnknownTag(other)),
        }
    }
    Ok(out)
}

/// An unencrypted 32-byte payment id carried in the extra nonce, if present.
pub fn payment_id(nonce: &[u8]) -> Option<[u8; 32]> {
    if nonce.len() == 1 + 32 && nonce[0] == NONCE_PAYMENT_ID {
        let mut id = [0u8; 32];
        id.copy_from_slice(&nonce[1..]);
        Some(id)
    } else {
        None
    }
}

/// An encrypted 8-byte payment id carried in the extra nonce, if present.
pub fn encrypted_payment_id(nonce: &[u8]) -> Option<[u8; 8]> {
    if nonce.len() == 1 + 8 && nonce[0] == NONCE_ENCRYPTED_PAYMENT_ID {
        let mut id = [0u8; 8];
        id.copy_from_slice(&nonce[1..]);
        Some(id)
    } else {
        None
    }
}

/// Build an extra-nonce payload that binds a Monero deposit to a Nebula account id (experimental).
pub fn encode_nebula_account_binding(account: &str) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(1 + account.len());
    nonce.push(NEBULA_BINDING_TAG);
    nonce.extend_from_slice(account.as_bytes());
    nonce
}

/// Recover a Nebula account id from an extra-nonce payload, if it carries a Nebula binding.
pub fn nebula_account_binding(nonce: &[u8]) -> Option<String> {
    match nonce.split_first() {
        Some((&NEBULA_BINDING_TAG, rest)) => String::from_utf8(rest.to_vec()).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lone_public_key() {
        let mut extra = vec![TAG_PUBKEY];
        extra.extend_from_slice(&[7u8; 32]);
        let parsed = parse_tx_extra(&extra).unwrap();
        assert_eq!(parsed.tx_public_key, Some([7u8; 32]));
        assert!(parsed.additional_public_keys.is_empty());
        assert!(parsed.nonce.is_none());
    }

    #[test]
    fn parses_pubkey_then_nonce_with_payment_id() {
        let mut nonce = vec![NONCE_PAYMENT_ID];
        nonce.extend_from_slice(&[9u8; 32]);
        let mut extra = vec![TAG_PUBKEY];
        extra.extend_from_slice(&[3u8; 32]);
        extra.push(TAG_NONCE);
        extra.push(nonce.len() as u8);
        extra.extend_from_slice(&nonce);

        let parsed = parse_tx_extra(&extra).unwrap();
        assert_eq!(parsed.tx_public_key, Some([3u8; 32]));
        let parsed_nonce = parsed.nonce.unwrap();
        assert_eq!(payment_id(&parsed_nonce), Some([9u8; 32]));
        assert_eq!(encrypted_payment_id(&parsed_nonce), None);
    }

    #[test]
    fn parses_additional_public_keys() {
        let mut extra = vec![TAG_ADDITIONAL_PUBKEYS, 0x02];
        extra.extend_from_slice(&[1u8; 32]);
        extra.extend_from_slice(&[2u8; 32]);
        let parsed = parse_tx_extra(&extra).unwrap();
        assert_eq!(parsed.additional_public_keys, vec![[1u8; 32], [2u8; 32]]);
    }

    #[test]
    fn ignores_trailing_padding() {
        let mut extra = vec![TAG_PUBKEY];
        extra.extend_from_slice(&[5u8; 32]);
        extra.push(TAG_PADDING);
        extra.extend_from_slice(&[0u8; 4]);
        let parsed = parse_tx_extra(&extra).unwrap();
        assert_eq!(parsed.tx_public_key, Some([5u8; 32]));
    }

    #[test]
    fn round_trips_nebula_account_binding() {
        let account = "nblahybrid-ed25519-mldsa65:abc123";
        let nonce = encode_nebula_account_binding(account);
        // Wrap it in a real tx_extra nonce record and parse it back out.
        let mut extra = vec![TAG_NONCE, nonce.len() as u8];
        extra.extend_from_slice(&nonce);
        let parsed = parse_tx_extra(&extra).unwrap();
        let parsed_nonce = parsed.nonce.unwrap();
        assert_eq!(
            nebula_account_binding(&parsed_nonce).as_deref(),
            Some(account)
        );
        assert_eq!(payment_id(&parsed_nonce), None);
    }

    #[test]
    fn rejects_unknown_tag_and_truncation() {
        assert_eq!(parse_tx_extra(&[0x77]), Err(TxExtraError::UnknownTag(0x77)));
        // Pubkey tag with only 3 trailing bytes.
        assert_eq!(
            parse_tx_extra(&[TAG_PUBKEY, 1, 2, 3]),
            Err(TxExtraError::Truncated)
        );
    }

    #[test]
    fn varint_round_trips_small_and_large() {
        for value in [0u64, 1, 127, 128, 300, 16384, u64::MAX] {
            let mut buf = Vec::new();
            let mut v = value;
            loop {
                let mut byte = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    byte |= 0x80;
                }
                buf.push(byte);
                if v == 0 {
                    break;
                }
            }
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos).unwrap(), value);
            assert_eq!(pos, buf.len());
        }
    }
}
