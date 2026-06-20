use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPqWithdrawalProofBatchVerifierResult<T> = Result<T, String>;

pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_PROTOCOL_VERSION: &str =
    "nebula-monero-pq-withdrawal-proof-batch-verifier-v1";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_SCHEMA_VERSION: u64 = 1;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_HEIGHT: u64 = 24_480;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192s-withdrawal-batch-devnet";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_MEMBERSHIP_SCHEME: &str =
    "monero-output-membership-commitment-v1";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_NULLIFIER_SCHEME: &str =
    "monero-key-image-nullifier-fence-v1";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_FINALITY_SCHEME: &str =
    "monero-pq-header-finality-reference-v1";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_REORG_INSURANCE_SCHEME: &str =
    "monero-reorg-insurance-hook-v1";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_PRIVACY_ENVELOPE_SCHEME: &str =
    "monero-withdrawal-privacy-proof-envelope-v1";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_QUEUE_SCHEME: &str =
    "pq-batched-withdrawal-verification-queue-v1";
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_BATCH_SIZE: usize = 128;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_BATCH_WEIGHT: u64 = 2_500_000;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_BATCH_BYTES: u64 = 4_000_000;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_TARGET_RING_SIZE: u64 = 32;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_FINALITY_DEPTH: u64 = 20;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_REORG_HOLD_BLOCKS: u64 = 12;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_REORG_CLAIM_BLOCKS: u64 = 48;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_ATTESTATION_QUORUM: u64 = 3;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_FEE_BPS: u64 = 40;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_SPONSOR_FEE_UNITS: u64 = 80_000;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_TARGET_VERIFY_MICROS: u64 = 22_000;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalProofStatus {
    Queued,
    MembershipBound,
    NullifierReserved,
    EnvelopeVerified,
    PqAttested,
    BatchSealed,
    ChallengeOpen,
    Finalized,
    ReorgHeld,
    Rejected,
    Expired,
}

impl WithdrawalProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::MembershipBound => "membership_bound",
            Self::NullifierReserved => "nullifier_reserved",
            Self::EnvelopeVerified => "envelope_verified",
            Self::PqAttested => "pq_attested",
            Self::BatchSealed => "batch_sealed",
            Self::ChallengeOpen => "challenge_open",
            Self::Finalized => "finalized",
            Self::ReorgHeld => "reorg_held",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::MembershipBound
                | Self::NullifierReserved
                | Self::EnvelopeVerified
                | Self::PqAttested
                | Self::BatchSealed
                | Self::ChallengeOpen
                | Self::ReorgHeld
        )
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::MembershipBound
                | Self::NullifierReserved
                | Self::EnvelopeVerified
                | Self::PqAttested
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Verifying,
    PqCertified,
    ChallengeOpen,
    FinalityReady,
    Settled,
    ReorgHeld,
    Cancelled,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Verifying => "verifying",
            Self::PqCertified => "pq_certified",
            Self::ChallengeOpen => "challenge_open",
            Self::FinalityReady => "finality_ready",
            Self::Settled => "settled",
            Self::ReorgHeld => "reorg_held",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Sealed
                | Self::Verifying
                | Self::PqCertified
                | Self::ChallengeOpen
                | Self::FinalityReady
                | Self::ReorgHeld
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Challenged,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationQueueStatus {
    Accepting,
    Sampling,
    Saturated,
    Draining,
    Paused,
    Closed,
}

impl VerificationQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::Sampling => "sampling",
            Self::Saturated => "saturated",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Accepting | Self::Sampling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgHookStatus {
    Armed,
    Holding,
    Claimable,
    Released,
    Disputed,
    Exhausted,
}

impl ReorgHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Holding => "holding",
            Self::Claimable => "claimable",
            Self::Released => "released",
            Self::Disputed => "disputed",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCapStatus {
    Available,
    Reserved,
    Applied,
    Refunded,
    Breached,
    Revoked,
}

impl FeeCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Refunded => "refunded",
            Self::Breached => "breached",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_batch_size: usize,
    pub max_batch_weight: u64,
    pub max_batch_bytes: u64,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub finality_depth: u64,
    pub reorg_hold_blocks: u64,
    pub reorg_claim_blocks: u64,
    pub attestation_quorum: u64,
    pub watchtower_quorum: u64,
    pub max_fee_bps: u64,
    pub max_sponsor_fee_units: u64,
    pub target_verify_micros: u64,
    pub batch_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub membership_scheme: String,
    pub nullifier_scheme: String,
    pub finality_scheme: String,
    pub reorg_insurance_scheme: String,
    pub privacy_envelope_scheme: String,
    pub queue_scheme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monero_network: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_FEE_ASSET_ID.to_string(),
            max_batch_size: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_BATCH_SIZE,
            max_batch_weight: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_BATCH_WEIGHT,
            max_batch_bytes: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_BATCH_BYTES,
            min_ring_size: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MIN_RING_SIZE,
            target_ring_size: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_TARGET_RING_SIZE,
            finality_depth: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_FINALITY_DEPTH,
            reorg_hold_blocks: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_REORG_HOLD_BLOCKS,
            reorg_claim_blocks:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_REORG_CLAIM_BLOCKS,
            attestation_quorum:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_ATTESTATION_QUORUM,
            watchtower_quorum: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_WATCHTOWER_QUORUM,
            max_fee_bps: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_FEE_BPS,
            max_sponsor_fee_units:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MAX_SPONSOR_FEE_UNITS,
            target_verify_micros:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_TARGET_VERIFY_MICROS,
            batch_window_blocks:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_BATCH_WINDOW_BLOCKS,
            challenge_window_blocks:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEFAULT_MIN_PQ_SECURITY_BITS,
            hash_suite: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_HASH_SUITE.to_string(),
            pq_attestation_suite: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_PQ_ATTESTATION_SUITE
                .to_string(),
            membership_scheme: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_MEMBERSHIP_SCHEME
                .to_string(),
            nullifier_scheme: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_NULLIFIER_SCHEME
                .to_string(),
            finality_scheme: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_FINALITY_SCHEME.to_string(),
            reorg_insurance_scheme:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_REORG_INSURANCE_SCHEME.to_string(),
            privacy_envelope_scheme:
                MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_PRIVACY_ENVELOPE_SCHEME.to_string(),
            queue_scheme: MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_QUEUE_SCHEME.to_string(),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("monero_network", &self.monero_network)?;
        validate_non_empty("l2_network", &self.l2_network)?;
        validate_non_empty("asset_id", &self.asset_id)?;
        validate_non_empty("fee_asset_id", &self.fee_asset_id)?;
        validate_non_zero_usize("max_batch_size", self.max_batch_size)?;
        validate_non_zero("max_batch_weight", self.max_batch_weight)?;
        validate_non_zero("max_batch_bytes", self.max_batch_bytes)?;
        validate_non_zero("min_ring_size", self.min_ring_size)?;
        validate_non_zero("target_ring_size", self.target_ring_size)?;
        validate_non_zero("finality_depth", self.finality_depth)?;
        validate_non_zero("attestation_quorum", self.attestation_quorum)?;
        validate_non_zero("watchtower_quorum", self.watchtower_quorum)?;
        validate_non_zero("target_verify_micros", self.target_verify_micros)?;
        validate_non_zero("batch_window_blocks", self.batch_window_blocks)?;
        validate_non_zero("challenge_window_blocks", self.challenge_window_blocks)?;
        validate_non_zero("min_privacy_set_size", self.min_privacy_set_size)?;
        validate_non_zero("min_pq_security_bits", self.min_pq_security_bits)?;
        if self.min_ring_size > self.target_ring_size {
            return Err("min ring size cannot exceed target ring size".to_string());
        }
        if self.reorg_claim_blocks < self.reorg_hold_blocks {
            return Err("reorg claim window cannot be shorter than hold window".to_string());
        }
        if self.max_fee_bps > MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_MAX_BPS {
            return Err("max fee bps exceeds bps denominator".to_string());
        }
        validate_non_empty("hash_suite", &self.hash_suite)?;
        validate_non_empty("pq_attestation_suite", &self.pq_attestation_suite)?;
        validate_non_empty("membership_scheme", &self.membership_scheme)?;
        validate_non_empty("nullifier_scheme", &self.nullifier_scheme)?;
        validate_non_empty("finality_scheme", &self.finality_scheme)?;
        validate_non_empty("reorg_insurance_scheme", &self.reorg_insurance_scheme)?;
        validate_non_empty("privacy_envelope_scheme", &self.privacy_envelope_scheme)?;
        validate_non_empty("queue_scheme", &self.queue_scheme)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_batch_size": self.max_batch_size.to_string(),
            "max_batch_weight": self.max_batch_weight.to_string(),
            "max_batch_bytes": self.max_batch_bytes.to_string(),
            "min_ring_size": self.min_ring_size.to_string(),
            "target_ring_size": self.target_ring_size.to_string(),
            "finality_depth": self.finality_depth.to_string(),
            "reorg_hold_blocks": self.reorg_hold_blocks.to_string(),
            "reorg_claim_blocks": self.reorg_claim_blocks.to_string(),
            "attestation_quorum": self.attestation_quorum.to_string(),
            "watchtower_quorum": self.watchtower_quorum.to_string(),
            "max_fee_bps": self.max_fee_bps.to_string(),
            "max_sponsor_fee_units": self.max_sponsor_fee_units.to_string(),
            "target_verify_micros": self.target_verify_micros.to_string(),
            "batch_window_blocks": self.batch_window_blocks.to_string(),
            "challenge_window_blocks": self.challenge_window_blocks.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size.to_string(),
            "min_pq_security_bits": self.min_pq_security_bits.to_string(),
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "membership_scheme": self.membership_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "finality_scheme": self.finality_scheme,
            "reorg_insurance_scheme": self.reorg_insurance_scheme,
            "privacy_envelope_scheme": self.privacy_envelope_scheme,
            "queue_scheme": self.queue_scheme,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalProofTicket {
    pub ticket_id: String,
    pub batch_id: String,
    pub owner_commitment: String,
    pub output_commitment_id: String,
    pub nullifier_id: String,
    pub privacy_envelope_id: String,
    pub header_ref_id: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub ring_size: u64,
    pub privacy_set_size: u64,
    pub weight: u64,
    pub encoded_bytes: u64,
    pub fee_bps: u64,
    pub submitted_height: u64,
    pub status: WithdrawalProofStatus,
}

impl WithdrawalProofTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "batch_id": self.batch_id,
            "owner_commitment": self.owner_commitment,
            "output_commitment_id": self.output_commitment_id,
            "nullifier_id": self.nullifier_id,
            "privacy_envelope_id": self.privacy_envelope_id,
            "header_ref_id": self.header_ref_id,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "ring_size": self.ring_size.to_string(),
            "privacy_set_size": self.privacy_set_size.to_string(),
            "weight": self.weight.to_string(),
            "encoded_bytes": self.encoded_bytes.to_string(),
            "fee_bps": self.fee_bps.to_string(),
            "submitted_height": self.submitted_height.to_string(),
            "status": self.status.as_str(),
        })
    }

    pub fn ticket_root(&self) -> String {
        payload_root("WITHDRAWAL-PROOF-TICKET", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("ticket_id", &self.ticket_id)?;
        validate_non_empty("owner_commitment", &self.owner_commitment)?;
        validate_non_empty("output_commitment_id", &self.output_commitment_id)?;
        validate_non_empty("nullifier_id", &self.nullifier_id)?;
        validate_non_empty("privacy_envelope_id", &self.privacy_envelope_id)?;
        validate_non_empty("header_ref_id", &self.header_ref_id)?;
        validate_non_empty("amount_commitment", &self.amount_commitment)?;
        validate_non_empty("fee_commitment", &self.fee_commitment)?;
        validate_non_zero("ring_size", self.ring_size)?;
        validate_non_zero("privacy_set_size", self.privacy_set_size)?;
        validate_non_zero("weight", self.weight)?;
        validate_non_zero("encoded_bytes", self.encoded_bytes)?;
        if self.ring_size < config.min_ring_size {
            return Err(format!("ticket {} below minimum ring size", self.ticket_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("ticket {} below privacy set size", self.ticket_id));
        }
        if self.weight > config.max_batch_weight {
            return Err(format!(
                "ticket {} exceeds batch weight cap",
                self.ticket_id
            ));
        }
        if self.encoded_bytes > config.max_batch_bytes {
            return Err(format!("ticket {} exceeds batch byte cap", self.ticket_id));
        }
        if self.fee_bps > config.max_fee_bps {
            return Err(format!("ticket {} exceeds fee cap", self.ticket_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalBatch {
    pub batch_id: String,
    pub queue_id: String,
    pub header_ref_id: String,
    pub ticket_ids: Vec<String>,
    pub aggregate_membership_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_privacy_envelope_root: String,
    pub aggregate_attestation_root: String,
    pub total_weight: u64,
    pub total_bytes: u64,
    pub max_fee_bps: u64,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub status: BatchStatus,
}

impl WithdrawalBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "queue_id": self.queue_id,
            "header_ref_id": self.header_ref_id,
            "ticket_ids": self.ticket_ids,
            "aggregate_membership_root": self.aggregate_membership_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "aggregate_privacy_envelope_root": self.aggregate_privacy_envelope_root,
            "aggregate_attestation_root": self.aggregate_attestation_root,
            "total_weight": self.total_weight.to_string(),
            "total_bytes": self.total_bytes.to_string(),
            "max_fee_bps": self.max_fee_bps.to_string(),
            "opened_height": self.opened_height.to_string(),
            "sealed_height": self.sealed_height.to_string(),
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        payload_root("WITHDRAWAL-BATCH", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("batch_id", &self.batch_id)?;
        validate_non_empty("queue_id", &self.queue_id)?;
        validate_non_empty("header_ref_id", &self.header_ref_id)?;
        validate_non_empty("aggregate_membership_root", &self.aggregate_membership_root)?;
        validate_non_empty("aggregate_nullifier_root", &self.aggregate_nullifier_root)?;
        validate_non_empty(
            "aggregate_privacy_envelope_root",
            &self.aggregate_privacy_envelope_root,
        )?;
        validate_non_empty(
            "aggregate_attestation_root",
            &self.aggregate_attestation_root,
        )?;
        if self.ticket_ids.is_empty() {
            return Err(format!("batch {} has no tickets", self.batch_id));
        }
        if self.ticket_ids.len() > config.max_batch_size {
            return Err(format!("batch {} exceeds ticket limit", self.batch_id));
        }
        if self.total_weight > config.max_batch_weight {
            return Err(format!("batch {} exceeds weight cap", self.batch_id));
        }
        if self.total_bytes > config.max_batch_bytes {
            return Err(format!("batch {} exceeds byte cap", self.batch_id));
        }
        if self.max_fee_bps > config.max_fee_bps {
            return Err(format!("batch {} exceeds fee cap", self.batch_id));
        }
        if self.sealed_height > 0 && self.sealed_height < self.opened_height {
            return Err(format!("batch {} sealed before opened", self.batch_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputMembershipCommitment {
    pub commitment_id: String,
    pub ticket_id: String,
    pub header_ref_id: String,
    pub output_index_commitment: String,
    pub ring_commitment_root: String,
    pub amount_mask_root: String,
    pub proof_commitment: String,
    pub ring_size: u64,
    pub observed_height: u64,
}

impl OutputMembershipCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "ticket_id": self.ticket_id,
            "header_ref_id": self.header_ref_id,
            "output_index_commitment": self.output_index_commitment,
            "ring_commitment_root": self.ring_commitment_root,
            "amount_mask_root": self.amount_mask_root,
            "proof_commitment": self.proof_commitment,
            "ring_size": self.ring_size.to_string(),
            "observed_height": self.observed_height.to_string(),
        })
    }

    pub fn commitment_root(&self) -> String {
        payload_root("OUTPUT-MEMBERSHIP-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("commitment_id", &self.commitment_id)?;
        validate_non_empty("ticket_id", &self.ticket_id)?;
        validate_non_empty("header_ref_id", &self.header_ref_id)?;
        validate_non_empty("output_index_commitment", &self.output_index_commitment)?;
        validate_non_empty("ring_commitment_root", &self.ring_commitment_root)?;
        validate_non_empty("amount_mask_root", &self.amount_mask_root)?;
        validate_non_empty("proof_commitment", &self.proof_commitment)?;
        if self.ring_size < config.min_ring_size {
            return Err(format!(
                "membership commitment {} below ring size",
                self.commitment_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierFence {
    pub nullifier_id: String,
    pub ticket_id: String,
    pub key_image_commitment: String,
    pub nullifier_root: String,
    pub fence_epoch: u64,
    pub first_seen_height: u64,
    pub reserved_until_height: u64,
    pub spent: bool,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "ticket_id": self.ticket_id,
            "key_image_commitment": self.key_image_commitment,
            "nullifier_root": self.nullifier_root,
            "fence_epoch": self.fence_epoch.to_string(),
            "first_seen_height": self.first_seen_height.to_string(),
            "reserved_until_height": self.reserved_until_height.to_string(),
            "spent": self.spent,
        })
    }

    pub fn nullifier_fence_root(&self) -> String {
        payload_root("NULLIFIER-FENCE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("nullifier_id", &self.nullifier_id)?;
        validate_non_empty("ticket_id", &self.ticket_id)?;
        validate_non_empty("key_image_commitment", &self.key_image_commitment)?;
        validate_non_empty("nullifier_root", &self.nullifier_root)?;
        validate_non_zero("reserved_until_height", self.reserved_until_height)?;
        if self.reserved_until_height < self.first_seen_height {
            return Err(format!(
                "nullifier {} reservation ends before first seen height",
                self.nullifier_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderFinalityRef {
    pub header_ref_id: String,
    pub monero_height: u64,
    pub block_hash_commitment: String,
    pub parent_hash_commitment: String,
    pub cumulative_work_commitment: String,
    pub finality_depth: u64,
    pub pq_finality_root: String,
    pub watchtower_root: String,
    pub reorg_risk_bps: u64,
}

impl HeaderFinalityRef {
    pub fn public_record(&self) -> Value {
        json!({
            "header_ref_id": self.header_ref_id,
            "monero_height": self.monero_height.to_string(),
            "block_hash_commitment": self.block_hash_commitment,
            "parent_hash_commitment": self.parent_hash_commitment,
            "cumulative_work_commitment": self.cumulative_work_commitment,
            "finality_depth": self.finality_depth.to_string(),
            "pq_finality_root": self.pq_finality_root,
            "watchtower_root": self.watchtower_root,
            "reorg_risk_bps": self.reorg_risk_bps.to_string(),
        })
    }

    pub fn finality_ref_root(&self) -> String {
        payload_root("HEADER-FINALITY-REF", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("header_ref_id", &self.header_ref_id)?;
        validate_non_empty("block_hash_commitment", &self.block_hash_commitment)?;
        validate_non_empty("parent_hash_commitment", &self.parent_hash_commitment)?;
        validate_non_empty(
            "cumulative_work_commitment",
            &self.cumulative_work_commitment,
        )?;
        validate_non_empty("pq_finality_root", &self.pq_finality_root)?;
        validate_non_empty("watchtower_root", &self.watchtower_root)?;
        if self.finality_depth < config.finality_depth {
            return Err(format!(
                "header ref {} below finality depth",
                self.header_ref_id
            ));
        }
        if self.reorg_risk_bps > MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_MAX_BPS {
            return Err(format!(
                "header ref {} risk exceeds bps",
                self.header_ref_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttestationSet {
    pub attestation_id: String,
    pub batch_id: String,
    pub committee_id: String,
    pub signer_commitments: Vec<String>,
    pub attestation_root: String,
    pub transcript_root: String,
    pub verifier_key_root: String,
    pub security_bits: u64,
    pub quorum_weight: u64,
    pub submitted_height: u64,
    pub status: AttestationStatus,
}

impl PqAttestationSet {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "committee_id": self.committee_id,
            "signer_commitments": self.signer_commitments,
            "attestation_root": self.attestation_root,
            "transcript_root": self.transcript_root,
            "verifier_key_root": self.verifier_key_root,
            "security_bits": self.security_bits.to_string(),
            "quorum_weight": self.quorum_weight.to_string(),
            "submitted_height": self.submitted_height.to_string(),
            "status": self.status.as_str(),
        })
    }

    pub fn pq_attestation_root(&self) -> String {
        payload_root("PQ-ATTESTATION-SET", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("attestation_id", &self.attestation_id)?;
        validate_non_empty("batch_id", &self.batch_id)?;
        validate_non_empty("committee_id", &self.committee_id)?;
        validate_non_empty("attestation_root", &self.attestation_root)?;
        validate_non_empty("transcript_root", &self.transcript_root)?;
        validate_non_empty("verifier_key_root", &self.verifier_key_root)?;
        if self.signer_commitments.len() < config.attestation_quorum as usize {
            return Err(format!(
                "attestation {} below signer quorum",
                self.attestation_id
            ));
        }
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below pq security floor",
                self.attestation_id
            ));
        }
        if self.quorum_weight < config.attestation_quorum {
            return Err(format!(
                "attestation {} below quorum weight",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationQueue {
    pub queue_id: String,
    pub lane: String,
    pub batch_ids: Vec<String>,
    pub ticket_ids: Vec<String>,
    pub max_weight: u64,
    pub current_weight: u64,
    pub fee_cap_bps: u64,
    pub priority: u64,
    pub status: VerificationQueueStatus,
}

impl VerificationQueue {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "lane": self.lane,
            "batch_ids": self.batch_ids,
            "ticket_ids": self.ticket_ids,
            "max_weight": self.max_weight.to_string(),
            "current_weight": self.current_weight.to_string(),
            "fee_cap_bps": self.fee_cap_bps.to_string(),
            "priority": self.priority.to_string(),
            "status": self.status.as_str(),
        })
    }

    pub fn queue_root(&self) -> String {
        payload_root("VERIFICATION-QUEUE", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("queue_id", &self.queue_id)?;
        validate_non_empty("lane", &self.lane)?;
        validate_non_zero("max_weight", self.max_weight)?;
        if self.current_weight > self.max_weight {
            return Err(format!("queue {} exceeds its weight limit", self.queue_id));
        }
        if self.current_weight > config.max_batch_weight {
            return Err(format!(
                "queue {} exceeds config weight limit",
                self.queue_id
            ));
        }
        if self.fee_cap_bps > config.max_fee_bps {
            return Err(format!("queue {} exceeds fee cap", self.queue_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCapReservation {
    pub reservation_id: String,
    pub ticket_id: String,
    pub sponsor_id: String,
    pub fee_asset_id: String,
    pub fee_cap_bps: u64,
    pub sponsor_fee_units: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub status: FeeCapStatus,
}

impl FeeCapReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "ticket_id": self.ticket_id,
            "sponsor_id": self.sponsor_id,
            "fee_asset_id": self.fee_asset_id,
            "fee_cap_bps": self.fee_cap_bps.to_string(),
            "sponsor_fee_units": self.sponsor_fee_units.to_string(),
            "reserved_height": self.reserved_height.to_string(),
            "expires_height": self.expires_height.to_string(),
            "status": self.status.as_str(),
        })
    }

    pub fn fee_cap_root(&self) -> String {
        payload_root("FEE-CAP-RESERVATION", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("reservation_id", &self.reservation_id)?;
        validate_non_empty("ticket_id", &self.ticket_id)?;
        validate_non_empty("sponsor_id", &self.sponsor_id)?;
        validate_non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.fee_asset_id != config.fee_asset_id {
            return Err(format!(
                "fee reservation {} uses wrong fee asset",
                self.reservation_id
            ));
        }
        if self.fee_cap_bps > config.max_fee_bps {
            return Err(format!(
                "fee reservation {} exceeds fee cap",
                self.reservation_id
            ));
        }
        if self.sponsor_fee_units > config.max_sponsor_fee_units {
            return Err(format!(
                "fee reservation {} exceeds sponsor unit cap",
                self.reservation_id
            ));
        }
        if self.expires_height < self.reserved_height {
            return Err(format!(
                "fee reservation {} expires before reservation",
                self.reservation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyProofEnvelope {
    pub envelope_id: String,
    pub ticket_id: String,
    pub proof_system: String,
    pub statement_root: String,
    pub witness_commitment_root: String,
    pub disclosure_policy_root: String,
    pub view_tag_bucket: String,
    pub privacy_set_size: u64,
    pub encoded_bytes: u64,
}

impl PrivacyProofEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "ticket_id": self.ticket_id,
            "proof_system": self.proof_system,
            "statement_root": self.statement_root,
            "witness_commitment_root": self.witness_commitment_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "view_tag_bucket": self.view_tag_bucket,
            "privacy_set_size": self.privacy_set_size.to_string(),
            "encoded_bytes": self.encoded_bytes.to_string(),
        })
    }

    pub fn envelope_root(&self) -> String {
        payload_root("PRIVACY-PROOF-ENVELOPE", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("envelope_id", &self.envelope_id)?;
        validate_non_empty("ticket_id", &self.ticket_id)?;
        validate_non_empty("proof_system", &self.proof_system)?;
        validate_non_empty("statement_root", &self.statement_root)?;
        validate_non_empty("witness_commitment_root", &self.witness_commitment_root)?;
        validate_non_empty("disclosure_policy_root", &self.disclosure_policy_root)?;
        validate_non_empty("view_tag_bucket", &self.view_tag_bucket)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "privacy envelope {} below privacy set floor",
                self.envelope_id
            ));
        }
        if self.encoded_bytes > config.max_batch_bytes {
            return Err(format!(
                "privacy envelope {} exceeds byte cap",
                self.envelope_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgInsuranceHook {
    pub hook_id: String,
    pub batch_id: String,
    pub header_ref_id: String,
    pub insurer_id: String,
    pub coverage_commitment: String,
    pub bond_commitment: String,
    pub armed_height: u64,
    pub hold_until_height: u64,
    pub claim_until_height: u64,
    pub status: ReorgHookStatus,
}

impl ReorgInsuranceHook {
    pub fn public_record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "batch_id": self.batch_id,
            "header_ref_id": self.header_ref_id,
            "insurer_id": self.insurer_id,
            "coverage_commitment": self.coverage_commitment,
            "bond_commitment": self.bond_commitment,
            "armed_height": self.armed_height.to_string(),
            "hold_until_height": self.hold_until_height.to_string(),
            "claim_until_height": self.claim_until_height.to_string(),
            "status": self.status.as_str(),
        })
    }

    pub fn hook_root(&self) -> String {
        payload_root("REORG-INSURANCE-HOOK", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("hook_id", &self.hook_id)?;
        validate_non_empty("batch_id", &self.batch_id)?;
        validate_non_empty("header_ref_id", &self.header_ref_id)?;
        validate_non_empty("insurer_id", &self.insurer_id)?;
        validate_non_empty("coverage_commitment", &self.coverage_commitment)?;
        validate_non_empty("bond_commitment", &self.bond_commitment)?;
        if self.hold_until_height < self.armed_height {
            return Err(format!("reorg hook {} hold precedes arm", self.hook_id));
        }
        if self.claim_until_height < self.hold_until_height {
            return Err(format!("reorg hook {} claim precedes hold", self.hook_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub subject_id: String,
    pub event_type: String,
    pub height: u64,
    pub record_root: String,
}

impl AuditEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "subject_id": self.subject_id,
            "event_type": self.event_type,
            "height": self.height.to_string(),
            "record_root": self.record_root,
        })
    }

    pub fn event_root(&self) -> String {
        payload_root("AUDIT-EVENT", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        validate_non_empty("event_id", &self.event_id)?;
        validate_non_empty("subject_id", &self.subject_id)?;
        validate_non_empty("event_type", &self.event_type)?;
        validate_non_empty("record_root", &self.record_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub ticket_root: String,
    pub batch_root: String,
    pub membership_commitment_root: String,
    pub nullifier_fence_root: String,
    pub header_finality_ref_root: String,
    pub pq_attestation_root: String,
    pub verification_queue_root: String,
    pub fee_cap_root: String,
    pub privacy_envelope_root: String,
    pub reorg_insurance_hook_root: String,
    pub audit_event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "ticket_root": self.ticket_root,
            "batch_root": self.batch_root,
            "membership_commitment_root": self.membership_commitment_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "header_finality_ref_root": self.header_finality_ref_root,
            "pq_attestation_root": self.pq_attestation_root,
            "verification_queue_root": self.verification_queue_root,
            "fee_cap_root": self.fee_cap_root,
            "privacy_envelope_root": self.privacy_envelope_root,
            "reorg_insurance_hook_root": self.reorg_insurance_hook_root,
            "audit_event_root": self.audit_event_root,
        })
    }

    pub fn roots_root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub ticket_count: u64,
    pub live_ticket_count: u64,
    pub finalized_ticket_count: u64,
    pub batch_count: u64,
    pub live_batch_count: u64,
    pub membership_commitment_count: u64,
    pub nullifier_fence_count: u64,
    pub spent_nullifier_count: u64,
    pub header_finality_ref_count: u64,
    pub pq_attestation_count: u64,
    pub accepted_attestation_count: u64,
    pub verification_queue_count: u64,
    pub accepting_queue_count: u64,
    pub fee_cap_count: u64,
    pub applied_fee_cap_count: u64,
    pub privacy_envelope_count: u64,
    pub reorg_hook_count: u64,
    pub active_reorg_hook_count: u64,
    pub audit_event_count: u64,
    pub total_queued_weight: u64,
    pub total_queued_bytes: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_count": self.ticket_count.to_string(),
            "live_ticket_count": self.live_ticket_count.to_string(),
            "finalized_ticket_count": self.finalized_ticket_count.to_string(),
            "batch_count": self.batch_count.to_string(),
            "live_batch_count": self.live_batch_count.to_string(),
            "membership_commitment_count": self.membership_commitment_count.to_string(),
            "nullifier_fence_count": self.nullifier_fence_count.to_string(),
            "spent_nullifier_count": self.spent_nullifier_count.to_string(),
            "header_finality_ref_count": self.header_finality_ref_count.to_string(),
            "pq_attestation_count": self.pq_attestation_count.to_string(),
            "accepted_attestation_count": self.accepted_attestation_count.to_string(),
            "verification_queue_count": self.verification_queue_count.to_string(),
            "accepting_queue_count": self.accepting_queue_count.to_string(),
            "fee_cap_count": self.fee_cap_count.to_string(),
            "applied_fee_cap_count": self.applied_fee_cap_count.to_string(),
            "privacy_envelope_count": self.privacy_envelope_count.to_string(),
            "reorg_hook_count": self.reorg_hook_count.to_string(),
            "active_reorg_hook_count": self.active_reorg_hook_count.to_string(),
            "audit_event_count": self.audit_event_count.to_string(),
            "total_queued_weight": self.total_queued_weight.to_string(),
            "total_queued_bytes": self.total_queued_bytes.to_string(),
        })
    }

    pub fn counters_root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub config: Config,
    pub tickets: BTreeMap<String, WithdrawalProofTicket>,
    pub batches: BTreeMap<String, WithdrawalBatch>,
    pub membership_commitments: BTreeMap<String, OutputMembershipCommitment>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub header_finality_refs: BTreeMap<String, HeaderFinalityRef>,
    pub pq_attestations: BTreeMap<String, PqAttestationSet>,
    pub verification_queues: BTreeMap<String, VerificationQueue>,
    pub fee_caps: BTreeMap<String, FeeCapReservation>,
    pub privacy_envelopes: BTreeMap<String, PrivacyProofEnvelope>,
    pub reorg_insurance_hooks: BTreeMap<String, ReorgInsuranceHook>,
    pub audit_events: BTreeMap<String, AuditEvent>,
}

impl State {
    pub fn new(config: Config, height: u64) -> MoneroPqWithdrawalProofBatchVerifierResult<Self> {
        config.validate()?;
        Ok(Self {
            height,
            monero_network: config.monero_network.clone(),
            l2_network: config.l2_network.clone(),
            asset_id: config.asset_id.clone(),
            fee_asset_id: config.fee_asset_id.clone(),
            config,
            tickets: BTreeMap::new(),
            batches: BTreeMap::new(),
            membership_commitments: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            header_finality_refs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            verification_queues: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            privacy_envelopes: BTreeMap::new(),
            reorg_insurance_hooks: BTreeMap::new(),
            audit_events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> MoneroPqWithdrawalProofBatchVerifierResult<Self> {
        let config = Config::devnet();
        let mut state = Self::new(
            config,
            MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_DEVNET_HEIGHT,
        )?;
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        if height < self.height {
            return Err("withdrawal verifier height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root("CONFIG", &self.config.public_record()),
            ticket_root: map_root("TICKET-SET", &self.tickets, |item| item.public_record()),
            batch_root: map_root("BATCH-SET", &self.batches, |item| item.public_record()),
            membership_commitment_root: map_root(
                "MEMBERSHIP-COMMITMENT-SET",
                &self.membership_commitments,
                |item| item.public_record(),
            ),
            nullifier_fence_root: map_root("NULLIFIER-FENCE-SET", &self.nullifier_fences, |item| {
                item.public_record()
            }),
            header_finality_ref_root: map_root(
                "HEADER-FINALITY-REF-SET",
                &self.header_finality_refs,
                |item| item.public_record(),
            ),
            pq_attestation_root: map_root("PQ-ATTESTATION-SET", &self.pq_attestations, |item| {
                item.public_record()
            }),
            verification_queue_root: map_root(
                "VERIFICATION-QUEUE-SET",
                &self.verification_queues,
                |item| item.public_record(),
            ),
            fee_cap_root: map_root("FEE-CAP-SET", &self.fee_caps, |item| item.public_record()),
            privacy_envelope_root: map_root(
                "PRIVACY-ENVELOPE-SET",
                &self.privacy_envelopes,
                |item| item.public_record(),
            ),
            reorg_insurance_hook_root: map_root(
                "REORG-INSURANCE-HOOK-SET",
                &self.reorg_insurance_hooks,
                |item| item.public_record(),
            ),
            audit_event_root: map_root("AUDIT-EVENT-SET", &self.audit_events, |item| {
                item.public_record()
            }),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            ticket_count: self.tickets.len() as u64,
            live_ticket_count: self
                .tickets
                .values()
                .filter(|ticket| ticket.status.live())
                .count() as u64,
            finalized_ticket_count: self
                .tickets
                .values()
                .filter(|ticket| ticket.status == WithdrawalProofStatus::Finalized)
                .count() as u64,
            batch_count: self.batches.len() as u64,
            live_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status.live())
                .count() as u64,
            membership_commitment_count: self.membership_commitments.len() as u64,
            nullifier_fence_count: self.nullifier_fences.len() as u64,
            spent_nullifier_count: self
                .nullifier_fences
                .values()
                .filter(|fence| fence.spent)
                .count() as u64,
            header_finality_ref_count: self.header_finality_refs.len() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            accepted_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.counts_for_quorum())
                .count() as u64,
            verification_queue_count: self.verification_queues.len() as u64,
            accepting_queue_count: self
                .verification_queues
                .values()
                .filter(|queue| queue.status.accepts_work())
                .count() as u64,
            fee_cap_count: self.fee_caps.len() as u64,
            applied_fee_cap_count: self
                .fee_caps
                .values()
                .filter(|fee_cap| fee_cap.status == FeeCapStatus::Applied)
                .count() as u64,
            privacy_envelope_count: self.privacy_envelopes.len() as u64,
            reorg_hook_count: self.reorg_insurance_hooks.len() as u64,
            active_reorg_hook_count: self
                .reorg_insurance_hooks
                .values()
                .filter(|hook| {
                    matches!(
                        hook.status,
                        ReorgHookStatus::Armed
                            | ReorgHookStatus::Holding
                            | ReorgHookStatus::Claimable
                    )
                })
                .count() as u64,
            audit_event_count: self.audit_events.len() as u64,
            total_queued_weight: self.tickets.values().map(|ticket| ticket.weight).sum(),
            total_queued_bytes: self
                .tickets
                .values()
                .map(|ticket| ticket.encoded_bytes)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_pq_withdrawal_proof_batch_verifier_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_PROTOCOL_VERSION,
            "schema_version": MONERO_PQ_WITHDRAWAL_PROOF_BATCH_VERIFIER_SCHEMA_VERSION.to_string(),
            "height": self.height.to_string(),
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<String> {
        self.config.validate()?;
        if self.monero_network != self.config.monero_network {
            return Err("state monero network differs from config".to_string());
        }
        if self.l2_network != self.config.l2_network {
            return Err("state l2 network differs from config".to_string());
        }
        if self.asset_id != self.config.asset_id {
            return Err("state asset differs from config".to_string());
        }
        if self.fee_asset_id != self.config.fee_asset_id {
            return Err("state fee asset differs from config".to_string());
        }
        self.validate_tickets()?;
        self.validate_batches()?;
        self.validate_membership_commitments()?;
        self.validate_nullifier_fences()?;
        self.validate_header_finality_refs()?;
        self.validate_pq_attestations()?;
        self.validate_verification_queues()?;
        self.validate_fee_caps()?;
        self.validate_privacy_envelopes()?;
        self.validate_reorg_hooks()?;
        self.validate_audit_events()?;
        Ok(self.state_root())
    }

    fn validate_tickets(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        let mut nullifiers = BTreeSet::new();
        for ticket in self.tickets.values() {
            ticket.validate(&self.config)?;
            if !self
                .membership_commitments
                .contains_key(&ticket.output_commitment_id)
            {
                return Err(format!(
                    "ticket {} points to missing output commitment",
                    ticket.ticket_id
                ));
            }
            if !self.nullifier_fences.contains_key(&ticket.nullifier_id) {
                return Err(format!(
                    "ticket {} points to missing nullifier fence",
                    ticket.ticket_id
                ));
            }
            if !self
                .privacy_envelopes
                .contains_key(&ticket.privacy_envelope_id)
            {
                return Err(format!(
                    "ticket {} points to missing privacy envelope",
                    ticket.ticket_id
                ));
            }
            if !self
                .header_finality_refs
                .contains_key(&ticket.header_ref_id)
            {
                return Err(format!(
                    "ticket {} points to missing header finality ref",
                    ticket.ticket_id
                ));
            }
            if !ticket.batch_id.is_empty() && !self.batches.contains_key(&ticket.batch_id) {
                return Err(format!(
                    "ticket {} points to missing batch",
                    ticket.ticket_id
                ));
            }
            if !nullifiers.insert(ticket.nullifier_id.clone()) {
                return Err(format!(
                    "duplicate nullifier fence used by ticket {}",
                    ticket.ticket_id
                ));
            }
        }
        Ok(())
    }

    fn validate_batches(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for batch in self.batches.values() {
            batch.validate(&self.config)?;
            if !self.verification_queues.contains_key(&batch.queue_id) {
                return Err(format!("batch {} points to missing queue", batch.batch_id));
            }
            if !self.header_finality_refs.contains_key(&batch.header_ref_id) {
                return Err(format!(
                    "batch {} points to missing header finality ref",
                    batch.batch_id
                ));
            }
            let mut total_weight = 0_u64;
            let mut total_bytes = 0_u64;
            for ticket_id in &batch.ticket_ids {
                let ticket = self
                    .tickets
                    .get(ticket_id)
                    .ok_or_else(|| format!("batch points to missing ticket {}", ticket_id))?;
                if ticket.batch_id != batch.batch_id {
                    return Err(format!(
                        "batch {} reverse link mismatch for ticket {}",
                        batch.batch_id, ticket_id
                    ));
                }
                total_weight = total_weight.saturating_add(ticket.weight);
                total_bytes = total_bytes.saturating_add(ticket.encoded_bytes);
            }
            if total_weight != batch.total_weight {
                return Err(format!("batch {} total weight mismatch", batch.batch_id));
            }
            if total_bytes != batch.total_bytes {
                return Err(format!("batch {} total bytes mismatch", batch.batch_id));
            }
        }
        Ok(())
    }

    fn validate_membership_commitments(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for commitment in self.membership_commitments.values() {
            commitment.validate(&self.config)?;
            if !self
                .header_finality_refs
                .contains_key(&commitment.header_ref_id)
            {
                return Err(format!(
                    "membership commitment {} points to missing header ref",
                    commitment.commitment_id
                ));
            }
        }
        Ok(())
    }

    fn validate_nullifier_fences(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for fence in self.nullifier_fences.values() {
            fence.validate()?;
        }
        Ok(())
    }

    fn validate_header_finality_refs(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for header_ref in self.header_finality_refs.values() {
            header_ref.validate(&self.config)?;
        }
        Ok(())
    }

    fn validate_pq_attestations(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        let mut accepted_by_batch: BTreeMap<String, u64> = BTreeMap::new();
        for attestation in self.pq_attestations.values() {
            attestation.validate(&self.config)?;
            if !self.batches.contains_key(&attestation.batch_id) {
                return Err(format!(
                    "attestation {} points to missing batch",
                    attestation.attestation_id
                ));
            }
            if attestation.status.counts_for_quorum() {
                let entry = accepted_by_batch
                    .entry(attestation.batch_id.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }
        for batch in self.batches.values() {
            if matches!(
                batch.status,
                BatchStatus::PqCertified
                    | BatchStatus::ChallengeOpen
                    | BatchStatus::FinalityReady
                    | BatchStatus::Settled
            ) {
                let accepted = match accepted_by_batch.get(&batch.batch_id) {
                    Some(value) => *value,
                    None => 0,
                };
                if accepted < self.config.attestation_quorum {
                    return Err(format!(
                        "batch {} lacks accepted pq attestation quorum",
                        batch.batch_id
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_verification_queues(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for queue in self.verification_queues.values() {
            queue.validate(&self.config)?;
            for batch_id in &queue.batch_ids {
                if !self.batches.contains_key(batch_id) {
                    return Err(format!("queue points to missing batch {}", batch_id));
                }
            }
            for ticket_id in &queue.ticket_ids {
                if !self.tickets.contains_key(ticket_id) {
                    return Err(format!("queue points to missing ticket {}", ticket_id));
                }
            }
        }
        Ok(())
    }

    fn validate_fee_caps(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for fee_cap in self.fee_caps.values() {
            fee_cap.validate(&self.config)?;
            if !self.tickets.contains_key(&fee_cap.ticket_id) {
                return Err(format!(
                    "fee cap {} points to missing ticket",
                    fee_cap.reservation_id
                ));
            }
        }
        Ok(())
    }

    fn validate_privacy_envelopes(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for envelope in self.privacy_envelopes.values() {
            envelope.validate(&self.config)?;
        }
        Ok(())
    }

    fn validate_reorg_hooks(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for hook in self.reorg_insurance_hooks.values() {
            hook.validate()?;
            if !self.batches.contains_key(&hook.batch_id) {
                return Err(format!(
                    "reorg hook {} points to missing batch",
                    hook.hook_id
                ));
            }
            if !self.header_finality_refs.contains_key(&hook.header_ref_id) {
                return Err(format!(
                    "reorg hook {} points to missing header ref",
                    hook.hook_id
                ));
            }
        }
        Ok(())
    }

    fn validate_audit_events(&self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        for event in self.audit_events.values() {
            event.validate()?;
        }
        Ok(())
    }

    fn seed_devnet_records(&mut self) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
        let header_ref = HeaderFinalityRef {
            header_ref_id: "monero-devnet-header-finality-24460".to_string(),
            monero_height: 24_460,
            block_hash_commitment: deterministic_id("devnet-header-block", "24460"),
            parent_hash_commitment: deterministic_id("devnet-header-parent", "24459"),
            cumulative_work_commitment: deterministic_id("devnet-work", "24460"),
            finality_depth: self.config.finality_depth,
            pq_finality_root: deterministic_id("devnet-pq-finality", "24460"),
            watchtower_root: deterministic_id("devnet-watchtower", "24460"),
            reorg_risk_bps: 12,
        };
        self.header_finality_refs
            .insert(header_ref.header_ref_id.clone(), header_ref);

        let queue = VerificationQueue {
            queue_id: "monero-pq-withdrawal-devnet-priority".to_string(),
            lane: "priority_withdrawal".to_string(),
            batch_ids: vec!["withdrawal-batch-devnet-0001".to_string()],
            ticket_ids: vec![
                "withdrawal-ticket-devnet-0001".to_string(),
                "withdrawal-ticket-devnet-0002".to_string(),
                "withdrawal-ticket-devnet-0003".to_string(),
            ],
            max_weight: 2_500_000,
            current_weight: 120_000,
            fee_cap_bps: 32,
            priority: 9,
            status: VerificationQueueStatus::Sampling,
        };
        self.verification_queues
            .insert(queue.queue_id.clone(), queue);

        for index in 1..=3_u64 {
            let ticket_id = format!("withdrawal-ticket-devnet-{index:04}");
            let membership_id = format!("output-membership-devnet-{index:04}");
            let nullifier_id = format!("nullifier-fence-devnet-{index:04}");
            let envelope_id = format!("privacy-envelope-devnet-{index:04}");
            let reservation_id = format!("fee-cap-devnet-{index:04}");
            let suffix = index.to_string();
            let membership = OutputMembershipCommitment {
                commitment_id: membership_id.clone(),
                ticket_id: ticket_id.clone(),
                header_ref_id: "monero-devnet-header-finality-24460".to_string(),
                output_index_commitment: deterministic_id("output-index", &suffix),
                ring_commitment_root: deterministic_id("ring-root", &suffix),
                amount_mask_root: deterministic_id("amount-mask", &suffix),
                proof_commitment: deterministic_id("membership-proof", &suffix),
                ring_size: self.config.target_ring_size,
                observed_height: 24_460,
            };
            self.membership_commitments
                .insert(membership_id.clone(), membership);
            let nullifier = NullifierFence {
                nullifier_id: nullifier_id.clone(),
                ticket_id: ticket_id.clone(),
                key_image_commitment: deterministic_id("key-image", &suffix),
                nullifier_root: deterministic_id("nullifier-root", &suffix),
                fence_epoch: 34,
                first_seen_height: 24_461 + index,
                reserved_until_height: 24_560 + index,
                spent: false,
            };
            self.nullifier_fences
                .insert(nullifier_id.clone(), nullifier);
            let envelope = PrivacyProofEnvelope {
                envelope_id: envelope_id.clone(),
                ticket_id: ticket_id.clone(),
                proof_system: self.config.privacy_envelope_scheme.clone(),
                statement_root: deterministic_id("privacy-statement", &suffix),
                witness_commitment_root: deterministic_id("privacy-witness", &suffix),
                disclosure_policy_root: deterministic_id("privacy-policy", &suffix),
                view_tag_bucket: format!("devnet-view-tag-bucket-{index}"),
                privacy_set_size: 512,
                encoded_bytes: 38_000 + index,
            };
            self.privacy_envelopes.insert(envelope_id.clone(), envelope);
            let ticket = WithdrawalProofTicket {
                ticket_id: ticket_id.clone(),
                batch_id: "withdrawal-batch-devnet-0001".to_string(),
                owner_commitment: deterministic_id("owner", &suffix),
                output_commitment_id: membership_id,
                nullifier_id,
                privacy_envelope_id: envelope_id,
                header_ref_id: "monero-devnet-header-finality-24460".to_string(),
                amount_commitment: deterministic_id("amount", &suffix),
                fee_commitment: deterministic_id("fee", &suffix),
                ring_size: self.config.target_ring_size,
                privacy_set_size: 512,
                weight: 40_000,
                encoded_bytes: 38_000 + index,
                fee_bps: 24,
                submitted_height: 24_462 + index,
                status: WithdrawalProofStatus::PqAttested,
            };
            self.tickets.insert(ticket_id.clone(), ticket);
            let fee_cap = FeeCapReservation {
                reservation_id: reservation_id.clone(),
                ticket_id,
                sponsor_id: "devnet-withdrawal-fee-sponsor".to_string(),
                fee_asset_id: self.config.fee_asset_id.clone(),
                fee_cap_bps: 24,
                sponsor_fee_units: 9_000 + index,
                reserved_height: 24_462,
                expires_height: 24_520,
                status: FeeCapStatus::Reserved,
            };
            self.fee_caps.insert(reservation_id, fee_cap);
        }

        let ticket_ids = vec![
            "withdrawal-ticket-devnet-0001".to_string(),
            "withdrawal-ticket-devnet-0002".to_string(),
            "withdrawal-ticket-devnet-0003".to_string(),
        ];
        let membership_records = records_for_ids(
            &self.membership_commitments,
            &[
                "output-membership-devnet-0001",
                "output-membership-devnet-0002",
                "output-membership-devnet-0003",
            ],
        );
        let nullifier_records = records_for_ids(
            &self.nullifier_fences,
            &[
                "nullifier-fence-devnet-0001",
                "nullifier-fence-devnet-0002",
                "nullifier-fence-devnet-0003",
            ],
        );
        let envelope_records = records_for_ids(
            &self.privacy_envelopes,
            &[
                "privacy-envelope-devnet-0001",
                "privacy-envelope-devnet-0002",
                "privacy-envelope-devnet-0003",
            ],
        );
        let batch = WithdrawalBatch {
            batch_id: "withdrawal-batch-devnet-0001".to_string(),
            queue_id: "monero-pq-withdrawal-devnet-priority".to_string(),
            header_ref_id: "monero-devnet-header-finality-24460".to_string(),
            ticket_ids,
            aggregate_membership_root: merkle_root(
                "MONERO-PQ-WITHDRAWAL-BATCH-MEMBERSHIP",
                &membership_records,
            ),
            aggregate_nullifier_root: merkle_root(
                "MONERO-PQ-WITHDRAWAL-BATCH-NULLIFIER",
                &nullifier_records,
            ),
            aggregate_privacy_envelope_root: merkle_root(
                "MONERO-PQ-WITHDRAWAL-BATCH-PRIVACY",
                &envelope_records,
            ),
            aggregate_attestation_root: deterministic_id("batch-attestation-root", "0001"),
            total_weight: 120_000,
            total_bytes: 114_006,
            max_fee_bps: 24,
            opened_height: 24_462,
            sealed_height: 24_468,
            status: BatchStatus::PqCertified,
        };
        self.batches.insert(batch.batch_id.clone(), batch);

        for index in 1..=3_u64 {
            let suffix = index.to_string();
            let attestation = PqAttestationSet {
                attestation_id: format!("pq-withdrawal-attestation-devnet-{index:04}"),
                batch_id: "withdrawal-batch-devnet-0001".to_string(),
                committee_id: "monero-pq-withdrawal-devnet-committee".to_string(),
                signer_commitments: vec![
                    deterministic_id("signer-a", &suffix),
                    deterministic_id("signer-b", &suffix),
                    deterministic_id("signer-c", &suffix),
                ],
                attestation_root: deterministic_id("attestation", &suffix),
                transcript_root: deterministic_id("transcript", &suffix),
                verifier_key_root: deterministic_id("verifier-key", &suffix),
                security_bits: 256,
                quorum_weight: 3,
                submitted_height: 24_468 + index,
                status: AttestationStatus::Accepted,
            };
            self.pq_attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }

        let hook = ReorgInsuranceHook {
            hook_id: "reorg-hook-devnet-0001".to_string(),
            batch_id: "withdrawal-batch-devnet-0001".to_string(),
            header_ref_id: "monero-devnet-header-finality-24460".to_string(),
            insurer_id: "devnet-reorg-insurance-vault".to_string(),
            coverage_commitment: deterministic_id("coverage", "0001"),
            bond_commitment: deterministic_id("bond", "0001"),
            armed_height: 24_468,
            hold_until_height: 24_480,
            claim_until_height: 24_528,
            status: ReorgHookStatus::Armed,
        };
        self.reorg_insurance_hooks
            .insert(hook.hook_id.clone(), hook);

        self.refresh_audit_events();
        Ok(())
    }

    fn refresh_audit_events(&mut self) {
        self.audit_events.clear();
        for ticket in self.tickets.values() {
            let event = AuditEvent {
                event_id: format!("audit-ticket-{}", ticket.ticket_id),
                subject_id: ticket.ticket_id.clone(),
                event_type: "withdrawal_ticket_indexed".to_string(),
                height: ticket.submitted_height,
                record_root: ticket.ticket_root(),
            };
            self.audit_events.insert(event.event_id.clone(), event);
        }
        for batch in self.batches.values() {
            let event = AuditEvent {
                event_id: format!("audit-batch-{}", batch.batch_id),
                subject_id: batch.batch_id.clone(),
                event_type: "withdrawal_batch_sealed".to_string(),
                height: batch.sealed_height,
                record_root: batch.batch_root(),
            };
            self.audit_events.insert(event.event_id.clone(), event);
        }
    }
}

pub fn root_from_record(record: &serde_json::Value) -> String {
    payload_root("STATE", record)
}

pub fn devnet() -> MoneroPqWithdrawalProofBatchVerifierResult<State> {
    State::devnet()
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("MONERO-PQ-WITHDRAWAL-PROOF-BATCH-VERIFIER-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

fn deterministic_id(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("MONERO-PQ-WITHDRAWAL-PROOF-BATCH-VERIFIER-ID-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, to_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, item)| {
            json!({
                "key": key,
                "record": to_record(item),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-PQ-WITHDRAWAL-PROOF-BATCH-VERIFIER-{domain}"),
        &leaves,
    )
}

fn records_for_ids<T>(map: &BTreeMap<String, T>, ids: &[&str]) -> Vec<Value>
where
    T: PublicRecord,
{
    ids.iter()
        .filter_map(|id| map.get(*id))
        .map(PublicRecord::public_record_value)
        .collect::<Vec<_>>()
}

trait PublicRecord {
    fn public_record_value(&self) -> Value;
}

impl PublicRecord for OutputMembershipCommitment {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for NullifierFence {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PrivacyProofEnvelope {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

fn validate_non_empty(name: &str, value: &str) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_non_zero(name: &str, value: u64) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
    if value == 0 {
        Err(format!("{name} cannot be zero"))
    } else {
        Ok(())
    }
}

fn validate_non_zero_usize(
    name: &str,
    value: usize,
) -> MoneroPqWithdrawalProofBatchVerifierResult<()> {
    if value == 0 {
        Err(format!("{name} cannot be zero"))
    } else {
        Ok(())
    }
}
