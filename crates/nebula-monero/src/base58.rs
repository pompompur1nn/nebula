//! Monero's Base58 encoding (a non-standard, block-based variant).
//!
//! Monero encodes in 8-byte blocks, each becoming up to 11 Base58 characters per the
//! `ENCODED_BLOCK_SIZES` table; the final block may be shorter. This differs from Bitcoin's
//! Base58 (which treats the whole input as one big integer), so a dedicated implementation is
//! required. Verified against the Monero project's own `base58.cpp` unit-test vectors.

use core::fmt;

/// The Base58 alphabet (Bitcoin order), as used by Monero.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Bytes per full block.
const FULL_BLOCK_SIZE: usize = 8;
/// Base58 characters per full block.
const FULL_ENCODED_BLOCK_SIZE: usize = 11;
/// Encoded Base58 length for an input block of `index` bytes (index 0..=8).
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/// An error decoding a Monero Base58 string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base58Error {
    /// A character outside the Base58 alphabet was encountered.
    InvalidCharacter(char),
    /// A block had a length that no valid byte-count encodes to.
    InvalidBlockLength(usize),
    /// A block encoded a value too large for its byte width.
    Overflow,
}

impl fmt::Display for Base58Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Base58Error::InvalidCharacter(c) => write!(f, "invalid base58 character '{c}'"),
            Base58Error::InvalidBlockLength(len) => {
                write!(f, "invalid base58 block length {len}")
            }
            Base58Error::Overflow => write!(f, "base58 block value overflows its byte width"),
        }
    }
}

impl std::error::Error for Base58Error {}

fn alphabet_index(c: u8) -> Option<u64> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .map(|index| index as u64)
}

/// Number of bytes a Base58 block of `encoded_len` characters decodes to, if valid.
fn decoded_block_size(encoded_len: usize) -> Option<usize> {
    ENCODED_BLOCK_SIZES
        .iter()
        .position(|&size| size == encoded_len)
}

/// Encode raw bytes into Monero Base58.
pub fn encode(data: &[u8]) -> String {
    let full_blocks = data.len() / FULL_BLOCK_SIZE;
    let mut out = String::new();
    for i in 0..full_blocks {
        encode_block(
            &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE],
            &mut out,
        );
    }
    let remainder = &data[full_blocks * FULL_BLOCK_SIZE..];
    if !remainder.is_empty() {
        encode_block(remainder, &mut out);
    }
    out
}

fn encode_block(block: &[u8], out: &mut String) {
    let encoded_size = ENCODED_BLOCK_SIZES[block.len()];
    let mut num: u64 = 0;
    for &byte in block {
        num = (num << 8) | u64::from(byte);
    }
    // '1' is Base58 zero; unused leading positions stay padded with it.
    let mut buffer = vec![b'1'; encoded_size];
    let mut index = encoded_size;
    while num > 0 {
        index -= 1;
        buffer[index] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    out.push_str(core::str::from_utf8(&buffer).expect("Base58 alphabet is valid ASCII"));
}

/// Decode a Monero Base58 string into raw bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, Base58Error> {
    let data = input.as_bytes();
    let full_blocks = data.len() / FULL_ENCODED_BLOCK_SIZE;
    let mut out = Vec::with_capacity(full_blocks * FULL_BLOCK_SIZE);
    for i in 0..full_blocks {
        decode_block(
            &data[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE],
            &mut out,
        )?;
    }
    let remainder = &data[full_blocks * FULL_ENCODED_BLOCK_SIZE..];
    if !remainder.is_empty() {
        decode_block(remainder, &mut out)?;
    }
    Ok(out)
}

fn decode_block(block: &[u8], out: &mut Vec<u8>) -> Result<(), Base58Error> {
    let out_size =
        decoded_block_size(block.len()).ok_or(Base58Error::InvalidBlockLength(block.len()))?;
    let mut num: u64 = 0;
    let mut order: u64 = 1;
    for (index, &c) in block.iter().enumerate().rev() {
        let digit = alphabet_index(c).ok_or(Base58Error::InvalidCharacter(c as char))?;
        let addend = order.checked_mul(digit).ok_or(Base58Error::Overflow)?;
        num = num.checked_add(addend).ok_or(Base58Error::Overflow)?;
        if index > 0 {
            order = order.checked_mul(58).ok_or(Base58Error::Overflow)?;
        }
    }
    if out_size < FULL_BLOCK_SIZE && num >= (1u64 << (8 * out_size)) {
        return Err(Base58Error::Overflow);
    }
    out.extend_from_slice(&num.to_be_bytes()[FULL_BLOCK_SIZE - out_size..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground-truth vectors from monero-project/monero tests/unit_tests/base58.cpp.
    const VECTORS: &[(&str, &str)] = &[
        ("00", "11"),
        ("39", "1z"),
        ("ff", "5Q"),
        ("0000", "111"),
        ("0039", "11z"),
        ("ffff", "LUv"),
        ("0000000000000000", "11111111111"),
        ("ffffffffffffffff", "jpXCZedGfVQ"),
    ];

    #[test]
    fn decodes_known_vectors() {
        for (hex, base58) in VECTORS {
            let expected = hex::decode(hex).unwrap();
            assert_eq!(decode(base58).unwrap(), expected, "decode {base58}");
        }
    }

    #[test]
    fn encodes_known_vectors() {
        for (hex, base58) in VECTORS {
            let bytes = hex::decode(hex).unwrap();
            assert_eq!(&encode(&bytes), base58, "encode {hex}");
        }
    }

    #[test]
    fn round_trips_arbitrary_lengths() {
        for len in 0..=72 {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            assert_eq!(
                decode(&encode(&bytes)).unwrap(),
                bytes,
                "round trip len {len}"
            );
        }
    }

    #[test]
    fn rejects_invalid_characters() {
        for bad in ["10", "1I", "1O", "1l", "1_"] {
            assert!(
                matches!(decode(bad), Err(Base58Error::InvalidCharacter(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_invalid_block_length() {
        // 1 and 4 are not valid encoded block lengths.
        assert!(matches!(
            decode("1"),
            Err(Base58Error::InvalidBlockLength(1))
        ));
        assert!(matches!(
            decode("1111"),
            Err(Base58Error::InvalidBlockLength(4))
        ));
    }

    #[test]
    fn rejects_overflowing_blocks() {
        // One past the maximum for their block widths.
        for bad in ["5R", "zz", "LUw", "zzz"] {
            assert!(matches!(decode(bad), Err(Base58Error::Overflow)), "{bad}");
        }
    }
}
