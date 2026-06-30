//! Confidential-amount primitives for Nebula: Pedersen commitments + Bulletproofs range proofs.
//!
//! A shielded amount is a Pedersen commitment `C = v·B + r·B_blinding`, which hides the value `v`
//! behind a secret blinding factor `r`. A Bulletproofs range proof shows `0 <= v < 2^64` without
//! revealing `v`, and the additive homomorphism of the commitment lets the chain confirm that a
//! transaction's inputs equal its outputs plus fee (no inflation) by comparing commitment sums —
//! again without learning any amount.
//!
//! This crate is the self-contained cryptographic core. Wiring shielded balances into the runtime
//! (commitment-valued account balances, a commitment-aware `state_root`, encrypted owner notes) is
//! a later, consensus-critical step that builds on these primitives.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;

/// Range proofs cover values in `[0, 2^64)`.
pub const RANGE_BITS: usize = 64;
/// Domain-separation label for the range-proof transcript.
const TRANSCRIPT_LABEL: &[u8] = b"nebula-confidential-amount-v1";

fn pedersen_gens() -> PedersenGens {
    PedersenGens::default()
}

fn bulletproof_gens() -> BulletproofGens {
    BulletproofGens::new(RANGE_BITS, 1)
}

/// A secret blinding factor for a Pedersen commitment.
#[derive(Clone)]
pub struct Blinding(Scalar);

impl Blinding {
    /// A fresh random blinding factor drawn from OS randomness.
    pub fn random() -> Self {
        let mut wide = [0u8; 64];
        getrandom::getrandom(&mut wide).expect("OS randomness for blinding factor");
        Blinding(Scalar::from_bytes_mod_order_wide(&wide))
    }

    /// A deterministic blinding derived from 32 bytes (reproducible for tests / key derivation).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Blinding(Scalar::from_bytes_mod_order(bytes))
    }

    /// The canonical 32-byte encoding of this blinding factor.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Sum of two blinding factors. Provers use this to make a transaction's blindings balance.
    pub fn add(&self, other: &Blinding) -> Blinding {
        Blinding(self.0 + other.0)
    }
}

/// A Pedersen commitment to a hidden amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(CompressedRistretto);

impl Commitment {
    /// The 64-character hex encoding of the 32-byte compressed commitment.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Parse a commitment from its 64-character hex encoding.
    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes = hex::decode(value).map_err(|error| format!("commitment hex: {error}"))?;
        let compressed = CompressedRistretto::from_slice(&bytes)
            .map_err(|_| "commitment must be 32 bytes".to_string())?;
        Ok(Commitment(compressed))
    }

    fn point(&self) -> Option<RistrettoPoint> {
        self.0.decompress()
    }
}

/// Commit to `value` with `blinding`: `C = value·B + blinding·B_blinding`.
pub fn commit(value: u64, blinding: &Blinding) -> Commitment {
    Commitment(
        pedersen_gens()
            .commit(Scalar::from(value), blinding.0)
            .compress(),
    )
}

/// Produce a commitment to `value` together with a range proof that `0 <= value < 2^64`.
pub fn prove_amount(value: u64, blinding: &Blinding) -> (Commitment, Vec<u8>) {
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    let (proof, committed) = RangeProof::prove_single(
        &bulletproof_gens(),
        &pedersen_gens(),
        &mut transcript,
        value,
        &blinding.0,
        RANGE_BITS,
    )
    .expect("range proof generation cannot fail for a u64 value");
    (Commitment(committed), proof.to_bytes())
}

/// Verify a range proof against its commitment.
pub fn verify_amount(commitment: &Commitment, proof_bytes: &[u8]) -> bool {
    let Ok(proof) = RangeProof::from_bytes(proof_bytes) else {
        return false;
    };
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    proof
        .verify_single(
            &bulletproof_gens(),
            &pedersen_gens(),
            &mut transcript,
            &commitment.0,
            RANGE_BITS,
        )
        .is_ok()
}

/// Check that committed `inputs` equal committed `outputs` plus a committed `fee` — proving the
/// transaction neither creates nor destroys value — purely from the commitments, revealing no
/// amount. Returns `false` if any commitment is malformed.
pub fn amounts_balance(inputs: &[Commitment], outputs: &[Commitment], fee: &Commitment) -> bool {
    let sum = |commitments: &[Commitment]| -> Option<RistrettoPoint> {
        commitments
            .iter()
            .try_fold(RistrettoPoint::identity(), |acc, c| Some(acc + c.point()?))
    };
    match (sum(inputs), sum(outputs), fee.point()) {
        (Some(input_sum), Some(output_sum), Some(fee_point)) => input_sum == output_sum + fee_point,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_matches_range_proof_commitment() {
        let blinding = Blinding::from_bytes([7u8; 32]);
        let (committed, _proof) = prove_amount(1234, &blinding);
        assert_eq!(commit(1234, &blinding), committed);
    }

    #[test]
    fn range_proof_round_trips() {
        let blinding = Blinding::from_bytes([7u8; 32]);
        let (commitment, proof) = prove_amount(1_000_000, &blinding);
        assert!(verify_amount(&commitment, &proof));
    }

    #[test]
    fn range_proof_rejects_tampering_and_wrong_commitment() {
        let blinding = Blinding::from_bytes([7u8; 32]);
        let (commitment, proof) = prove_amount(1234, &blinding);

        let mut tampered = proof.clone();
        tampered[0] ^= 0xff;
        assert!(!verify_amount(&commitment, &tampered));

        let (other_commitment, _) = prove_amount(5678, &Blinding::from_bytes([8u8; 32]));
        assert!(!verify_amount(&other_commitment, &proof));

        assert!(!verify_amount(&commitment, b"not a proof"));
    }

    #[test]
    fn balanced_commitments_verify_and_inflation_is_caught() {
        // The prover makes blindings balance: r_in = r_out + r_fee.
        let r_out = Blinding::from_bytes([2u8; 32]);
        let r_fee = Blinding::from_bytes([3u8; 32]);
        let r_in = r_out.add(&r_fee);

        let input = commit(100, &r_in);
        let output = commit(70, &r_out);
        let fee = commit(30, &r_fee);
        assert!(amounts_balance(&[input], &[output], &fee));

        // Inflated output (80 instead of 70) breaks the balance even though blindings still sum.
        let inflated = commit(80, &r_out);
        assert!(!amounts_balance(&[input], &[inflated], &fee));
    }

    #[test]
    fn multi_input_output_balance() {
        // inputs 60 + 40 = outputs 90 + fee 10. Blindings must satisfy r_in1+r_in2 = r_out+r_fee,
        // so choose r_fee = r_in1 + r_in2 - r_out.
        let r_in1 = Blinding::from_bytes([11u8; 32]);
        let r_in2 = Blinding::from_bytes([12u8; 32]);
        let r_out = Blinding::from_bytes([13u8; 32]);
        let r_fee = Blinding(r_in1.0 + r_in2.0 - r_out.0);
        let inputs = [commit(60, &r_in1), commit(40, &r_in2)];
        let outputs = [commit(90, &r_out)];
        let fee = commit(10, &r_fee);
        assert!(amounts_balance(&inputs, &outputs, &fee));
    }

    #[test]
    fn commitment_hex_round_trips() {
        let commitment = commit(42, &Blinding::from_bytes([9u8; 32]));
        let hex = commitment.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Commitment::from_hex(&hex).unwrap(), commitment);
        assert!(Commitment::from_hex("zz").is_err());
    }
}
