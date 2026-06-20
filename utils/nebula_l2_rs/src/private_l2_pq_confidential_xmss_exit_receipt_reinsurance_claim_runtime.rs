use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialXmssExitReceiptReinsuranceClaimRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_XMSS_EXIT_RECEIPT_REINSURANCE_CLAIM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-xmss-exit-receipt-reinsurance-claim-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_XMSS_EXIT_RECEIPT_REINSURANCE_CLAIM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const XMSS_EXIT_RECEIPT_REINSURANCE_CLAIM_SUITE: &str =
    "xmss-stateful-hash-based-exit-receipt-reinsurance-claim-v1";
pub const SEALED_EXIT_RECEIPT_CLAIM_SUITE: &str = "pq-confidential-sealed-exit-receipt-claim-v1";
pub const REINSURANCE_CLAIM_COUPON_SUITE: &str =
    "confidential-exit-receipt-reinsurance-claim-coupon-v1";
pub const PQ_WITNESS_BUNDLE_SUITE: &str = "xmss-pq-reinsurance-claim-witness-bundle-v1";
pub const CLAIM_NULLIFIER_SUITE: &str = "private-l2-exit-reinsurance-claim-nullifier-v1";
pub const LOW_FEE_BATCH_ADJUDICATION_SUITE: &str =
    "low-fee-xmss-exit-receipt-reinsurance-claim-adjudication-batch-v1";
pub const PRIVACY_REDACTION_ROOT_SUITE: &str =
    "privacy-redaction-root-for-reinsurance-claim-disclosure-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-xmss-exit-receipt-reinsurance-claim-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 8_736_000;
pub const DEVNET_EPOCH: u64 = 36_400;
pub const DEVNET_SLOT: u64 = 512;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_XMSS_TREE_HEIGHT: u8 = 20;
pub const DEFAULT_XMSS_LAYER_COUNT: u8 = 4;
pub const DEFAULT_XMSS_WINTERNITZ_PARAMETER: u8 = 16;
pub const DEFAULT_XMSS_LEAF_BUDGET: u32 = 1_048_576;
pub const DEFAULT_NULLIFIER_BUCKETS: u32 = 262_144;
pub const DEFAULT_CLAIM_WINDOW_SLOTS: u64 = 4_096;
pub const DEFAULT_EVIDENCE_GRACE_SLOTS: u64 = 768;
pub const DEFAULT_ADJUDICATION_DELAY_SLOTS: u64 = 1_024;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 64;
pub const DEFAULT_COUPON_RETENTION_EPOCHS: u64 = 96;
pub const DEFAULT_MIN_REDATION_SHARES: u16 = 3;
pub const DEFAULT_MAX_PUBLIC_DISCLOSURE_FIELDS: u16 = 12;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 36_000_000_000;
pub const DEFAULT_REINSURANCE_RESERVE_ATOMIC: u64 = 18_000_000_000;
pub const DEFAULT_CLAIM_BOND_ATOMIC: u64 = 1_900_000_000;
pub const DEFAULT_SUCCESS_REWARD_BPS: u16 = 1_200;
pub const DEFAULT_REINSURANCE_PAYOUT_BPS: u16 = 8_800;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 1_024;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 90;
pub const DEFAULT_EPOCH_BUCKET_TARGET_CLAIMS: u64 = 49_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Drafted,
    Sealed,
    Witnessed,
    CouponLocked,
    AdjudicationPending,
    Accepted,
    Rejected,
    Paid,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Unknown,
    Sealed,
    Claimed,
    Reinsured,
    Paid,
    Superseded,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Locked,
    Consumed,
    Refunded,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    Submitted,
    HashAttested,
    BundleRooted,
    Quarantined,
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjudicationStatus {
    Collecting,
    Posted,
    Decided,
    Settled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimDecision {
    Undecided,
    Accept,
    Reject,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimRisk {
    Low,
    Medium,
    High,
    Emergency,
}

impl ClaimRisk {
    pub fn score(self) -> u16 {
        match self {
            Self::Low => 100,
            Self::Medium => 350,
            Self::High => 700,
            Self::Emergency => 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFailureKind {
    DuplicateClaimNullifier,
    XmssLeafReuse,
    InvalidXmssAuthPath,
    ReceiptCommitmentMismatch,
    CouponCommitmentMismatch,
    WitnessBundleRootMismatch,
    RedactionRootMismatch,
    ClaimWindowViolation,
    ReserveInsufficient,
}

impl ClaimFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateClaimNullifier => "duplicate_claim_nullifier",
            Self::XmssLeafReuse => "xmss_leaf_reuse",
            Self::InvalidXmssAuthPath => "invalid_xmss_auth_path",
            Self::ReceiptCommitmentMismatch => "receipt_commitment_mismatch",
            Self::CouponCommitmentMismatch => "coupon_commitment_mismatch",
            Self::WitnessBundleRootMismatch => "witness_bundle_root_mismatch",
            Self::RedactionRootMismatch => "redaction_root_mismatch",
            Self::ClaimWindowViolation => "claim_window_violation",
            Self::ReserveInsufficient => "reserve_insufficient",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub xmss_claim_suite: String,
    pub sealed_exit_receipt_claim_suite: String,
    pub reinsurance_claim_coupon_suite: String,
    pub pq_witness_bundle_suite: String,
    pub claim_nullifier_suite: String,
    pub low_fee_batch_adjudication_suite: String,
    pub privacy_redaction_root_suite: String,
    pub roots_only_public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub xmss_tree_height: u8,
    pub xmss_layer_count: u8,
    pub xmss_winternitz_parameter: u8,
    pub xmss_leaf_budget: u32,
    pub nullifier_buckets: u32,
    pub claim_window_slots: u64,
    pub evidence_grace_slots: u64,
    pub adjudication_delay_slots: u64,
    pub receipt_retention_epochs: u64,
    pub coupon_retention_epochs: u64,
    pub min_redaction_shares: u16,
    pub max_public_disclosure_fields: u16,
    pub exit_bond_atomic: u64,
    pub reinsurance_reserve_atomic: u64,
    pub claim_bond_atomic: u64,
    pub success_reward_bps: u16,
    pub reinsurance_payout_bps: u16,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_claims: u64,
    pub stateful_xmss_attestations_required: bool,
    pub sealed_claims_required: bool,
    pub claim_coupons_required: bool,
    pub pq_witness_bundles_required: bool,
    pub claim_nullifiers_required: bool,
    pub privacy_redaction_roots_required: bool,
    pub roots_only_public_records_required: bool,
    pub low_fee_batching_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: "nebula-private-l2-devnet".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            xmss_claim_suite: XMSS_EXIT_RECEIPT_REINSURANCE_CLAIM_SUITE.to_string(),
            sealed_exit_receipt_claim_suite: SEALED_EXIT_RECEIPT_CLAIM_SUITE.to_string(),
            reinsurance_claim_coupon_suite: REINSURANCE_CLAIM_COUPON_SUITE.to_string(),
            pq_witness_bundle_suite: PQ_WITNESS_BUNDLE_SUITE.to_string(),
            claim_nullifier_suite: CLAIM_NULLIFIER_SUITE.to_string(),
            low_fee_batch_adjudication_suite: LOW_FEE_BATCH_ADJUDICATION_SUITE.to_string(),
            privacy_redaction_root_suite: PRIVACY_REDACTION_ROOT_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            xmss_tree_height: DEFAULT_XMSS_TREE_HEIGHT,
            xmss_layer_count: DEFAULT_XMSS_LAYER_COUNT,
            xmss_winternitz_parameter: DEFAULT_XMSS_WINTERNITZ_PARAMETER,
            xmss_leaf_budget: DEFAULT_XMSS_LEAF_BUDGET,
            nullifier_buckets: DEFAULT_NULLIFIER_BUCKETS,
            claim_window_slots: DEFAULT_CLAIM_WINDOW_SLOTS,
            evidence_grace_slots: DEFAULT_EVIDENCE_GRACE_SLOTS,
            adjudication_delay_slots: DEFAULT_ADJUDICATION_DELAY_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            coupon_retention_epochs: DEFAULT_COUPON_RETENTION_EPOCHS,
            min_redaction_shares: DEFAULT_MIN_REDATION_SHARES,
            max_public_disclosure_fields: DEFAULT_MAX_PUBLIC_DISCLOSURE_FIELDS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            reinsurance_reserve_atomic: DEFAULT_REINSURANCE_RESERVE_ATOMIC,
            claim_bond_atomic: DEFAULT_CLAIM_BOND_ATOMIC,
            success_reward_bps: DEFAULT_SUCCESS_REWARD_BPS,
            reinsurance_payout_bps: DEFAULT_REINSURANCE_PAYOUT_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_claims: DEFAULT_EPOCH_BUCKET_TARGET_CLAIMS,
            stateful_xmss_attestations_required: true,
            sealed_claims_required: true,
            claim_coupons_required: true,
            pq_witness_bundles_required: true,
            claim_nullifiers_required: true,
            privacy_redaction_roots_required: true,
            roots_only_public_records_required: true,
            low_fee_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below xmss reinsurance claim minimum".to_string());
        }
        if self.xmss_tree_height < 16 || self.xmss_layer_count == 0 {
            return Err("invalid xmss claim hypertree parameter schedule".to_string());
        }
        if !matches!(self.xmss_winternitz_parameter, 4 | 8 | 16) {
            return Err("unsupported xmss winternitz parameter".to_string());
        }
        if self.xmss_leaf_budget == 0 || self.nullifier_buckets == 0 {
            return Err("xmss leaf budget and nullifier buckets must be positive".to_string());
        }
        if self.claim_window_slots == 0
            || self.evidence_grace_slots == 0
            || self.adjudication_delay_slots == 0
        {
            return Err("claim windows and adjudication delay must be positive".to_string());
        }
        if self.evidence_grace_slots > self.claim_window_slots {
            return Err("evidence grace cannot exceed claim window".to_string());
        }
        if self.receipt_retention_epochs == 0 || self.coupon_retention_epochs == 0 {
            return Err("retention epochs must be positive".to_string());
        }
        if self.min_redaction_shares == 0 || self.max_public_disclosure_fields == 0 {
            return Err("privacy redaction policy must expose bounded roots".to_string());
        }
        if self.exit_bond_atomic == 0
            || self.reinsurance_reserve_atomic == 0
            || self.claim_bond_atomic == 0
        {
            return Err("claim bonds and reinsurance reserve must be positive".to_string());
        }
        if u32::from(self.success_reward_bps) + u32::from(self.reinsurance_payout_bps) != 10_000 {
            return Err("claim payout basis points must sum to 10000".to_string());
        }
        if self.low_fee_batch_limit == 0 || self.min_batch_size == 0 {
            return Err("low-fee claim batch sizing must be positive".to_string());
        }
        if self.min_batch_size > self.low_fee_batch_limit {
            return Err("minimum batch size cannot exceed batch limit".to_string());
        }
        if self.epoch_bucket_target_claims == 0 {
            return Err("epoch bucket target claims must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sealed_claims: u64,
    pub witness_bundles: u64,
    pub claim_coupons: u64,
    pub nullifiers: u64,
    pub redaction_roots: u64,
    pub batches: u64,
    pub accepted_claims: u64,
    pub rejected_claims: u64,
    pub quarantined_claims: u64,
    pub paid_claims: u64,
    pub slashed_coupons: u64,
    pub low_fee_savings_micro_units: u64,
    pub total_claimed_atomic: u64,
    pub total_paid_atomic: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub sealed_claim_root: String,
    pub coupon_root: String,
    pub witness_bundle_root: String,
    pub nullifier_root: String,
    pub adjudication_batch_root: String,
    pub privacy_redaction_root: String,
    pub receipt_status_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            sealed_claim_root: merkle_root("xmss-reinsurance-claims:sealed:empty", &[]),
            coupon_root: merkle_root("xmss-reinsurance-claims:coupons:empty", &[]),
            witness_bundle_root: merkle_root("xmss-reinsurance-claims:witnesses:empty", &[]),
            nullifier_root: merkle_root("xmss-reinsurance-claims:nullifiers:empty", &[]),
            adjudication_batch_root: merkle_root("xmss-reinsurance-claims:batches:empty", &[]),
            privacy_redaction_root: merkle_root("xmss-reinsurance-claims:redactions:empty", &[]),
            receipt_status_root: merkle_root("xmss-reinsurance-claims:receipts:empty", &[]),
            public_record_root: merkle_root("xmss-reinsurance-claims:public:empty", &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XmssClaimAttestation {
    pub attestation_id: String,
    pub xmss_public_root: String,
    pub xmss_leaf_index: u32,
    pub xmss_tree_epoch: u64,
    pub wots_chain_commitment: String,
    pub auth_path_root: String,
    pub message_digest: String,
    pub prior_leaf_cursor: u32,
    pub next_leaf_cursor: u32,
    pub pq_security_bits: u16,
    pub leaf_state_hash: String,
}

impl XmssClaimAttestation {
    pub fn new(
        xmss_public_root: impl Into<String>,
        xmss_leaf_index: u32,
        xmss_tree_epoch: u64,
        wots_chain_commitment: impl Into<String>,
        auth_path_root: impl Into<String>,
        message_digest: impl Into<String>,
        prior_leaf_cursor: u32,
        pq_security_bits: u16,
    ) -> Self {
        let xmss_public_root = xmss_public_root.into();
        let wots_chain_commitment = wots_chain_commitment.into();
        let auth_path_root = auth_path_root.into();
        let message_digest = message_digest.into();
        let next_leaf_cursor = xmss_leaf_index.saturating_add(1);
        let leaf_state_hash = domain_hash(
            "xmss-reinsurance-claim:leaf-state",
            &[
                HashPart::Str(&xmss_public_root),
                HashPart::U64(u64::from(xmss_leaf_index)),
                HashPart::U64(xmss_tree_epoch),
                HashPart::Str(&wots_chain_commitment),
                HashPart::Str(&auth_path_root),
                HashPart::Str(&message_digest),
                HashPart::U64(u64::from(prior_leaf_cursor)),
                HashPart::U64(u64::from(next_leaf_cursor)),
            ],
            32,
        );
        let attestation_id = domain_hash(
            "xmss-reinsurance-claim:attestation-id",
            &[
                HashPart::Str(&xmss_public_root),
                HashPart::U64(u64::from(xmss_leaf_index)),
                HashPart::U64(xmss_tree_epoch),
                HashPart::Str(&leaf_state_hash),
            ],
            32,
        );
        Self {
            attestation_id,
            xmss_public_root,
            xmss_leaf_index,
            xmss_tree_epoch,
            wots_chain_commitment,
            auth_path_root,
            message_digest,
            prior_leaf_cursor,
            next_leaf_cursor,
            pq_security_bits,
            leaf_state_hash,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("xmss claim attestation below pq security floor".to_string());
        }
        if self.xmss_leaf_index >= config.xmss_leaf_budget {
            return Err("xmss claim leaf index outside configured budget".to_string());
        }
        if self.next_leaf_cursor <= self.prior_leaf_cursor {
            return Err("xmss claim leaf cursor did not advance".to_string());
        }
        if self.next_leaf_cursor != self.xmss_leaf_index.saturating_add(1) {
            return Err("xmss claim leaf cursor inconsistent with leaf index".to_string());
        }
        require_hash_like("xmss_public_root", &self.xmss_public_root)?;
        require_hash_like("wots_chain_commitment", &self.wots_chain_commitment)?;
        require_hash_like("auth_path_root", &self.auth_path_root)?;
        require_hash_like("message_digest", &self.message_digest)?;
        require_hash_like("leaf_state_hash", &self.leaf_state_hash)?;
        Ok(())
    }

    pub fn public_commitment(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "xmss_public_root": self.xmss_public_root,
            "xmss_tree_epoch": self.xmss_tree_epoch,
            "leaf_state_hash": self.leaf_state_hash,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedExitReceiptClaim {
    pub claim_id: String,
    pub receipt_commitment: String,
    pub sealed_claim_ciphertext_root: String,
    pub claimant_commitment: String,
    pub exit_queue_root: String,
    pub exit_amount_commitment: String,
    pub claim_amount_commitment: String,
    pub claim_open_slot: u64,
    pub claim_deadline_slot: u64,
    pub risk: ClaimRisk,
    pub status: ClaimStatus,
    pub attestation_id: String,
    pub redaction_root_id: String,
}

impl SealedExitReceiptClaim {
    pub fn new(input: SealClaimInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let claim_id = domain_hash(
            "xmss-reinsurance-claim:sealed-claim-id",
            &[
                HashPart::Str(&input.receipt_commitment),
                HashPart::Str(&input.claimant_commitment),
                HashPart::Str(&input.sealed_claim_ciphertext_root),
                HashPart::U64(input.claim_open_slot),
            ],
            32,
        );
        let claim_deadline_slot = input
            .claim_open_slot
            .saturating_add(config.claim_window_slots);
        Ok(Self {
            claim_id,
            receipt_commitment: input.receipt_commitment,
            sealed_claim_ciphertext_root: input.sealed_claim_ciphertext_root,
            claimant_commitment: input.claimant_commitment,
            exit_queue_root: input.exit_queue_root,
            exit_amount_commitment: input.exit_amount_commitment,
            claim_amount_commitment: input.claim_amount_commitment,
            claim_open_slot: input.claim_open_slot,
            claim_deadline_slot,
            risk: input.risk,
            status: ClaimStatus::Sealed,
            attestation_id: input.attestation.attestation_id,
            redaction_root_id: input.redaction_root.redaction_root_id,
        })
    }

    pub fn leaf(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "receipt_commitment": self.receipt_commitment,
            "sealed_claim_ciphertext_root": self.sealed_claim_ciphertext_root,
            "claimant_commitment": self.claimant_commitment,
            "exit_queue_root": self.exit_queue_root,
            "exit_amount_commitment": self.exit_amount_commitment,
            "claim_amount_commitment": self.claim_amount_commitment,
            "claim_open_slot": self.claim_open_slot,
            "claim_deadline_slot": self.claim_deadline_slot,
            "risk": self.risk,
            "status": self.status,
            "attestation_id": self.attestation_id,
            "redaction_root_id": self.redaction_root_id,
        })
    }

    pub fn public_commitment(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "receipt_commitment": self.receipt_commitment,
            "sealed_claim_ciphertext_root": self.sealed_claim_ciphertext_root,
            "exit_queue_root": self.exit_queue_root,
            "claim_open_slot": self.claim_open_slot,
            "claim_deadline_slot": self.claim_deadline_slot,
            "risk_score": self.risk.score(),
            "status": self.status,
            "attestation_id": self.attestation_id,
            "redaction_root_id": self.redaction_root_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReinsuranceClaimCoupon {
    pub coupon_id: String,
    pub claim_id: String,
    pub reinsurer_commitment: String,
    pub reserve_commitment: String,
    pub coupon_secret_hash: String,
    pub payout_cap_commitment: String,
    pub premium_commitment: String,
    pub issued_epoch: u64,
    pub expiry_epoch: u64,
    pub status: CouponStatus,
}

impl ReinsuranceClaimCoupon {
    pub fn new(input: IssueCouponInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let expiry_epoch = input
            .issued_epoch
            .saturating_add(config.coupon_retention_epochs);
        let coupon_id = domain_hash(
            "xmss-reinsurance-claim:coupon-id",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(&input.reinsurer_commitment),
                HashPart::Str(&input.coupon_secret_hash),
                HashPart::U64(input.issued_epoch),
            ],
            32,
        );
        Ok(Self {
            coupon_id,
            claim_id: input.claim_id,
            reinsurer_commitment: input.reinsurer_commitment,
            reserve_commitment: input.reserve_commitment,
            coupon_secret_hash: input.coupon_secret_hash,
            payout_cap_commitment: input.payout_cap_commitment,
            premium_commitment: input.premium_commitment,
            issued_epoch: input.issued_epoch,
            expiry_epoch,
            status: CouponStatus::Issued,
        })
    }

    pub fn leaf(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "claim_id": self.claim_id,
            "reinsurer_commitment": self.reinsurer_commitment,
            "reserve_commitment": self.reserve_commitment,
            "coupon_secret_hash": self.coupon_secret_hash,
            "payout_cap_commitment": self.payout_cap_commitment,
            "premium_commitment": self.premium_commitment,
            "issued_epoch": self.issued_epoch,
            "expiry_epoch": self.expiry_epoch,
            "status": self.status,
        })
    }

    pub fn public_commitment(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "claim_id": self.claim_id,
            "reserve_commitment": self.reserve_commitment,
            "issued_epoch": self.issued_epoch,
            "expiry_epoch": self.expiry_epoch,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWitnessBundle {
    pub witness_id: String,
    pub claim_id: String,
    pub attestation_id: String,
    pub receipt_membership_root: String,
    pub coupon_membership_root: String,
    pub nullifier_membership_root: String,
    pub xmss_auth_path_root: String,
    pub redaction_share_root: String,
    pub witness_ciphertext_root: String,
    pub submitted_slot: u64,
    pub status: WitnessStatus,
}

impl PqWitnessBundle {
    pub fn new(input: SubmitWitnessInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let witness_id = domain_hash(
            "xmss-reinsurance-claim:witness-id",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(&input.attestation_id),
                HashPart::Str(&input.receipt_membership_root),
                HashPart::Str(&input.coupon_membership_root),
                HashPart::U64(input.submitted_slot),
            ],
            32,
        );
        Ok(Self {
            witness_id,
            claim_id: input.claim_id,
            attestation_id: input.attestation_id,
            receipt_membership_root: input.receipt_membership_root,
            coupon_membership_root: input.coupon_membership_root,
            nullifier_membership_root: input.nullifier_membership_root,
            xmss_auth_path_root: input.xmss_auth_path_root,
            redaction_share_root: input.redaction_share_root,
            witness_ciphertext_root: input.witness_ciphertext_root,
            submitted_slot: input.submitted_slot,
            status: WitnessStatus::Submitted,
        })
    }

    pub fn bundle_root(&self) -> String {
        domain_hash(
            "xmss-reinsurance-claim:witness-bundle-root",
            &[
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.attestation_id),
                HashPart::Str(&self.receipt_membership_root),
                HashPart::Str(&self.coupon_membership_root),
                HashPart::Str(&self.nullifier_membership_root),
                HashPart::Str(&self.xmss_auth_path_root),
                HashPart::Str(&self.redaction_share_root),
                HashPart::Str(&self.witness_ciphertext_root),
            ],
            32,
        )
    }

    pub fn leaf(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "claim_id": self.claim_id,
            "attestation_id": self.attestation_id,
            "receipt_membership_root": self.receipt_membership_root,
            "coupon_membership_root": self.coupon_membership_root,
            "nullifier_membership_root": self.nullifier_membership_root,
            "xmss_auth_path_root": self.xmss_auth_path_root,
            "redaction_share_root": self.redaction_share_root,
            "witness_ciphertext_root": self.witness_ciphertext_root,
            "submitted_slot": self.submitted_slot,
            "status": self.status,
            "bundle_root": self.bundle_root(),
        })
    }

    pub fn public_commitment(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "claim_id": self.claim_id,
            "attestation_id": self.attestation_id,
            "bundle_root": self.bundle_root(),
            "submitted_slot": self.submitted_slot,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimNullifier {
    pub nullifier_id: String,
    pub claim_id: String,
    pub receipt_commitment: String,
    pub coupon_id: String,
    pub claimant_nullifier_key_root: String,
    pub bucket: u32,
    pub spent_slot: u64,
}

impl ClaimNullifier {
    pub fn new(input: SpendNullifierInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let nullifier_id = domain_hash(
            "xmss-reinsurance-claim:nullifier-id",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(&input.receipt_commitment),
                HashPart::Str(&input.coupon_id),
                HashPart::Str(&input.claimant_nullifier_key_root),
            ],
            32,
        );
        let bucket_hash = domain_hash(
            "xmss-reinsurance-claim:nullifier-bucket",
            &[HashPart::Str(&nullifier_id)],
            8,
        );
        let bucket = u64::from_str_radix(&bucket_hash, 16).unwrap_or_default()
            % u64::from(config.nullifier_buckets);
        Ok(Self {
            nullifier_id,
            claim_id: input.claim_id,
            receipt_commitment: input.receipt_commitment,
            coupon_id: input.coupon_id,
            claimant_nullifier_key_root: input.claimant_nullifier_key_root,
            bucket: bucket as u32,
            spent_slot: input.spent_slot,
        })
    }

    pub fn leaf(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "claim_id": self.claim_id,
            "receipt_commitment": self.receipt_commitment,
            "coupon_id": self.coupon_id,
            "claimant_nullifier_key_root": self.claimant_nullifier_key_root,
            "bucket": self.bucket,
            "spent_slot": self.spent_slot,
        })
    }

    pub fn public_commitment(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "claim_id": self.claim_id,
            "coupon_id": self.coupon_id,
            "bucket": self.bucket,
            "spent_slot": self.spent_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionRoot {
    pub redaction_root_id: String,
    pub claim_id_hint: String,
    pub disclosure_policy_root: String,
    pub encrypted_field_root: String,
    pub view_tag_root: String,
    pub auditor_share_root: String,
    pub public_field_count: u16,
    pub required_shares: u16,
}

impl PrivacyRedactionRoot {
    pub fn new(input: RedactionRootInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let redaction_root_id = domain_hash(
            "xmss-reinsurance-claim:redaction-root-id",
            &[
                HashPart::Str(&input.claim_id_hint),
                HashPart::Str(&input.disclosure_policy_root),
                HashPart::Str(&input.encrypted_field_root),
                HashPart::Str(&input.auditor_share_root),
            ],
            32,
        );
        Ok(Self {
            redaction_root_id,
            claim_id_hint: input.claim_id_hint,
            disclosure_policy_root: input.disclosure_policy_root,
            encrypted_field_root: input.encrypted_field_root,
            view_tag_root: input.view_tag_root,
            auditor_share_root: input.auditor_share_root,
            public_field_count: input.public_field_count,
            required_shares: input.required_shares,
        })
    }

    pub fn leaf(&self) -> Value {
        json!({
            "redaction_root_id": self.redaction_root_id,
            "claim_id_hint": self.claim_id_hint,
            "disclosure_policy_root": self.disclosure_policy_root,
            "encrypted_field_root": self.encrypted_field_root,
            "view_tag_root": self.view_tag_root,
            "auditor_share_root": self.auditor_share_root,
            "public_field_count": self.public_field_count,
            "required_shares": self.required_shares,
        })
    }

    pub fn public_commitment(&self) -> Value {
        json!({
            "redaction_root_id": self.redaction_root_id,
            "disclosure_policy_root": self.disclosure_policy_root,
            "view_tag_root": self.view_tag_root,
            "public_field_count": self.public_field_count,
            "required_shares": self.required_shares,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeClaimAdjudicationBatch {
    pub batch_id: String,
    pub claim_ids: Vec<String>,
    pub accepted_claim_ids: Vec<String>,
    pub rejected_claim_ids: Vec<String>,
    pub quarantined_claim_ids: Vec<String>,
    pub witness_root: String,
    pub coupon_root: String,
    pub nullifier_root: String,
    pub redaction_root: String,
    pub fee_micro_units: u64,
    pub posted_slot: u64,
    pub status: AdjudicationStatus,
    pub settlement_root: String,
}

impl LowFeeClaimAdjudicationBatch {
    pub fn new(input: AdjudicateBatchInput, state: &State) -> Result<Self> {
        input.validate(&state.config)?;
        if input.claim_ids.len() < usize::from(state.config.min_batch_size) {
            return Err("claim adjudication batch below minimum size".to_string());
        }
        if input.claim_ids.len() > usize::from(state.config.low_fee_batch_limit) {
            return Err("claim adjudication batch exceeds low-fee limit".to_string());
        }
        if input.fee_micro_units > state.config.max_batch_fee_micro_units {
            return Err("claim adjudication batch fee exceeds cap".to_string());
        }
        let mut seen = BTreeSet::new();
        for claim_id in &input.claim_ids {
            if !state.sealed_claims.contains_key(claim_id) {
                return Err(format!("unknown claim in adjudication batch: {claim_id}"));
            }
            if !seen.insert(claim_id.clone()) {
                return Err("duplicate claim in adjudication batch".to_string());
            }
        }
        let settlement_root = domain_hash(
            "xmss-reinsurance-claim:batch-settlement-root",
            &[
                HashPart::Json(&json!(input.claim_ids)),
                HashPart::Json(&json!(input.accepted_claim_ids)),
                HashPart::Json(&json!(input.rejected_claim_ids)),
                HashPart::Json(&json!(input.quarantined_claim_ids)),
                HashPart::Str(&state.roots.witness_bundle_root),
                HashPart::Str(&state.roots.coupon_root),
                HashPart::Str(&state.roots.nullifier_root),
                HashPart::Str(&state.roots.privacy_redaction_root),
            ],
            32,
        );
        let batch_id = domain_hash(
            "xmss-reinsurance-claim:batch-id",
            &[
                HashPart::Json(&json!(input.claim_ids)),
                HashPart::U64(input.posted_slot),
                HashPart::U64(input.fee_micro_units),
                HashPart::Str(&settlement_root),
            ],
            32,
        );
        Ok(Self {
            batch_id,
            claim_ids: input.claim_ids,
            accepted_claim_ids: input.accepted_claim_ids,
            rejected_claim_ids: input.rejected_claim_ids,
            quarantined_claim_ids: input.quarantined_claim_ids,
            witness_root: state.roots.witness_bundle_root.clone(),
            coupon_root: state.roots.coupon_root.clone(),
            nullifier_root: state.roots.nullifier_root.clone(),
            redaction_root: state.roots.privacy_redaction_root.clone(),
            fee_micro_units: input.fee_micro_units,
            posted_slot: input.posted_slot,
            status: AdjudicationStatus::Posted,
            settlement_root,
        })
    }

    pub fn leaf(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "claim_ids": self.claim_ids,
            "accepted_claim_ids": self.accepted_claim_ids,
            "rejected_claim_ids": self.rejected_claim_ids,
            "quarantined_claim_ids": self.quarantined_claim_ids,
            "witness_root": self.witness_root,
            "coupon_root": self.coupon_root,
            "nullifier_root": self.nullifier_root,
            "redaction_root": self.redaction_root,
            "fee_micro_units": self.fee_micro_units,
            "posted_slot": self.posted_slot,
            "status": self.status,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptRecord {
    pub receipt_commitment: String,
    pub claim_id: String,
    pub status: ReceiptStatus,
    pub last_slot: u64,
}

impl ReceiptRecord {
    pub fn leaf(&self) -> Value {
        json!({
            "receipt_commitment": self.receipt_commitment,
            "claim_id": self.claim_id,
            "status": self.status,
            "last_slot": self.last_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealClaimInput {
    pub receipt_commitment: String,
    pub sealed_claim_ciphertext_root: String,
    pub claimant_commitment: String,
    pub exit_queue_root: String,
    pub exit_amount_commitment: String,
    pub claim_amount_commitment: String,
    pub claim_open_slot: u64,
    pub risk: ClaimRisk,
    pub attestation: XmssClaimAttestation,
    pub redaction_root: PrivacyRedactionRoot,
}

impl SealClaimInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        self.attestation.validate(config)?;
        require_hash_like("receipt_commitment", &self.receipt_commitment)?;
        require_hash_like(
            "sealed_claim_ciphertext_root",
            &self.sealed_claim_ciphertext_root,
        )?;
        require_hash_like("claimant_commitment", &self.claimant_commitment)?;
        require_hash_like("exit_queue_root", &self.exit_queue_root)?;
        require_hash_like("exit_amount_commitment", &self.exit_amount_commitment)?;
        require_hash_like("claim_amount_commitment", &self.claim_amount_commitment)?;
        if self.claim_open_slot == 0 {
            return Err("claim open slot must be positive".to_string());
        }
        if self.redaction_root.required_shares < config.min_redaction_shares {
            return Err("claim redaction root below share threshold".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueCouponInput {
    pub claim_id: String,
    pub reinsurer_commitment: String,
    pub reserve_commitment: String,
    pub coupon_secret_hash: String,
    pub payout_cap_commitment: String,
    pub premium_commitment: String,
    pub issued_epoch: u64,
}

impl IssueCouponInput {
    pub fn validate(&self, _config: &Config) -> Result<()> {
        require_hash_like("claim_id", &self.claim_id)?;
        require_hash_like("reinsurer_commitment", &self.reinsurer_commitment)?;
        require_hash_like("reserve_commitment", &self.reserve_commitment)?;
        require_hash_like("coupon_secret_hash", &self.coupon_secret_hash)?;
        require_hash_like("payout_cap_commitment", &self.payout_cap_commitment)?;
        require_hash_like("premium_commitment", &self.premium_commitment)?;
        if self.issued_epoch == 0 {
            return Err("coupon issued epoch must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitWitnessInput {
    pub claim_id: String,
    pub attestation_id: String,
    pub receipt_membership_root: String,
    pub coupon_membership_root: String,
    pub nullifier_membership_root: String,
    pub xmss_auth_path_root: String,
    pub redaction_share_root: String,
    pub witness_ciphertext_root: String,
    pub submitted_slot: u64,
}

impl SubmitWitnessInput {
    pub fn validate(&self, _config: &Config) -> Result<()> {
        require_hash_like("claim_id", &self.claim_id)?;
        require_hash_like("attestation_id", &self.attestation_id)?;
        require_hash_like("receipt_membership_root", &self.receipt_membership_root)?;
        require_hash_like("coupon_membership_root", &self.coupon_membership_root)?;
        require_hash_like("nullifier_membership_root", &self.nullifier_membership_root)?;
        require_hash_like("xmss_auth_path_root", &self.xmss_auth_path_root)?;
        require_hash_like("redaction_share_root", &self.redaction_share_root)?;
        require_hash_like("witness_ciphertext_root", &self.witness_ciphertext_root)?;
        if self.submitted_slot == 0 {
            return Err("witness submitted slot must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpendNullifierInput {
    pub claim_id: String,
    pub receipt_commitment: String,
    pub coupon_id: String,
    pub claimant_nullifier_key_root: String,
    pub spent_slot: u64,
}

impl SpendNullifierInput {
    pub fn validate(&self, _config: &Config) -> Result<()> {
        require_hash_like("claim_id", &self.claim_id)?;
        require_hash_like("receipt_commitment", &self.receipt_commitment)?;
        require_hash_like("coupon_id", &self.coupon_id)?;
        require_hash_like(
            "claimant_nullifier_key_root",
            &self.claimant_nullifier_key_root,
        )?;
        if self.spent_slot == 0 {
            return Err("nullifier spent slot must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionRootInput {
    pub claim_id_hint: String,
    pub disclosure_policy_root: String,
    pub encrypted_field_root: String,
    pub view_tag_root: String,
    pub auditor_share_root: String,
    pub public_field_count: u16,
    pub required_shares: u16,
}

impl RedactionRootInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_hash_like("claim_id_hint", &self.claim_id_hint)?;
        require_hash_like("disclosure_policy_root", &self.disclosure_policy_root)?;
        require_hash_like("encrypted_field_root", &self.encrypted_field_root)?;
        require_hash_like("view_tag_root", &self.view_tag_root)?;
        require_hash_like("auditor_share_root", &self.auditor_share_root)?;
        if self.public_field_count > config.max_public_disclosure_fields {
            return Err("redaction root exposes too many public fields".to_string());
        }
        if self.required_shares < config.min_redaction_shares {
            return Err("redaction root below minimum share threshold".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdjudicateBatchInput {
    pub claim_ids: Vec<String>,
    pub accepted_claim_ids: Vec<String>,
    pub rejected_claim_ids: Vec<String>,
    pub quarantined_claim_ids: Vec<String>,
    pub fee_micro_units: u64,
    pub posted_slot: u64,
}

impl AdjudicateBatchInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if !config.low_fee_batching_enabled {
            return Err("low-fee claim adjudication batching disabled".to_string());
        }
        if self.claim_ids.is_empty() {
            return Err("adjudication batch cannot be empty".to_string());
        }
        if self.posted_slot == 0 {
            return Err("adjudication posted slot must be positive".to_string());
        }
        if self.fee_micro_units > config.max_batch_fee_micro_units {
            return Err("adjudication fee above configured cap".to_string());
        }
        for claim_id in self
            .claim_ids
            .iter()
            .chain(self.accepted_claim_ids.iter())
            .chain(self.rejected_claim_ids.iter())
            .chain(self.quarantined_claim_ids.iter())
        {
            require_hash_like("batch claim_id", claim_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sealed_claims: BTreeMap<String, SealedExitReceiptClaim>,
    pub attestations: BTreeMap<String, XmssClaimAttestation>,
    pub coupons: BTreeMap<String, ReinsuranceClaimCoupon>,
    pub witness_bundles: BTreeMap<String, PqWitnessBundle>,
    pub nullifiers: BTreeMap<String, ClaimNullifier>,
    pub redaction_roots: BTreeMap<String, PrivacyRedactionRoot>,
    pub adjudication_batches: BTreeMap<String, LowFeeClaimAdjudicationBatch>,
    pub receipt_records: BTreeMap<String, ReceiptRecord>,
    pub used_xmss_leaves: BTreeSet<String>,
    pub spent_nullifiers: BTreeSet<String>,
    pub claim_failures: BTreeMap<String, ClaimFailureKind>,
    pub reserve_available_atomic: u64,
    pub current_height: u64,
    pub current_epoch: u64,
    pub current_slot: u64,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64, slot: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            reserve_available_atomic: config.reinsurance_reserve_atomic,
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            sealed_claims: BTreeMap::new(),
            attestations: BTreeMap::new(),
            coupons: BTreeMap::new(),
            witness_bundles: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            redaction_roots: BTreeMap::new(),
            adjudication_batches: BTreeMap::new(),
            receipt_records: BTreeMap::new(),
            used_xmss_leaves: BTreeSet::new(),
            spent_nullifiers: BTreeSet::new(),
            claim_failures: BTreeMap::new(),
            current_height: height,
            current_epoch: epoch,
            current_slot: slot,
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self::new(config, DEVNET_HEIGHT, DEVNET_EPOCH, DEVNET_SLOT)
            .expect("devnet xmss reinsurance claim config is valid")
    }

    pub fn seal_claim(&mut self, input: SealClaimInput) -> Result<String> {
        self.config.validate()?;
        let redaction = input.redaction_root.clone();
        let attestation = input.attestation.clone();
        let leaf_key = xmss_leaf_key(&attestation);
        if self.used_xmss_leaves.contains(&leaf_key) {
            self.claim_failures.insert(
                attestation.attestation_id.clone(),
                ClaimFailureKind::XmssLeafReuse,
            );
            return Err("xmss leaf already used for reinsurance claim".to_string());
        }
        let claim = SealedExitReceiptClaim::new(input, &self.config)?;
        if self.sealed_claims.contains_key(&claim.claim_id) {
            return Err("sealed reinsurance claim already exists".to_string());
        }
        self.used_xmss_leaves.insert(leaf_key);
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.redaction_roots
            .insert(redaction.redaction_root_id.clone(), redaction);
        self.receipt_records.insert(
            claim.receipt_commitment.clone(),
            ReceiptRecord {
                receipt_commitment: claim.receipt_commitment.clone(),
                claim_id: claim.claim_id.clone(),
                status: ReceiptStatus::Claimed,
                last_slot: self.current_slot,
            },
        );
        let claim_id = claim.claim_id.clone();
        self.sealed_claims.insert(claim_id.clone(), claim);
        self.counters.sealed_claims = self.counters.sealed_claims.saturating_add(1);
        self.counters.redaction_roots = self.counters.redaction_roots.saturating_add(1);
        self.refresh_roots();
        Ok(claim_id)
    }

    pub fn issue_coupon(&mut self, input: IssueCouponInput) -> Result<String> {
        if !self.sealed_claims.contains_key(&input.claim_id) {
            return Err("cannot issue coupon for unknown reinsurance claim".to_string());
        }
        let coupon = ReinsuranceClaimCoupon::new(input, &self.config)?;
        if self.coupons.contains_key(&coupon.coupon_id) {
            return Err("reinsurance claim coupon already exists".to_string());
        }
        if let Some(claim) = self.sealed_claims.get_mut(&coupon.claim_id) {
            claim.status = ClaimStatus::CouponLocked;
        }
        let coupon_id = coupon.coupon_id.clone();
        self.coupons.insert(coupon_id.clone(), coupon);
        self.counters.claim_coupons = self.counters.claim_coupons.saturating_add(1);
        self.refresh_roots();
        Ok(coupon_id)
    }

    pub fn submit_witness_bundle(&mut self, input: SubmitWitnessInput) -> Result<String> {
        let claim = self
            .sealed_claims
            .get(&input.claim_id)
            .ok_or_else(|| "cannot submit witness for unknown claim".to_string())?;
        if claim.attestation_id != input.attestation_id {
            return Err("witness attestation does not match sealed claim".to_string());
        }
        let witness = PqWitnessBundle::new(input, &self.config)?;
        if self.witness_bundles.contains_key(&witness.witness_id) {
            return Err("pq witness bundle already exists".to_string());
        }
        if let Some(claim) = self.sealed_claims.get_mut(&witness.claim_id) {
            claim.status = ClaimStatus::Witnessed;
        }
        let witness_id = witness.witness_id.clone();
        self.witness_bundles.insert(witness_id.clone(), witness);
        self.counters.witness_bundles = self.counters.witness_bundles.saturating_add(1);
        self.refresh_roots();
        Ok(witness_id)
    }

    pub fn spend_claim_nullifier(&mut self, input: SpendNullifierInput) -> Result<String> {
        if !self.sealed_claims.contains_key(&input.claim_id) {
            return Err("cannot spend nullifier for unknown claim".to_string());
        }
        if !self.coupons.contains_key(&input.coupon_id) {
            return Err("cannot spend nullifier for unknown coupon".to_string());
        }
        let nullifier = ClaimNullifier::new(input, &self.config)?;
        if self.spent_nullifiers.contains(&nullifier.nullifier_id) {
            self.claim_failures.insert(
                nullifier.claim_id.clone(),
                ClaimFailureKind::DuplicateClaimNullifier,
            );
            return Err("claim nullifier already spent".to_string());
        }
        self.spent_nullifiers.insert(nullifier.nullifier_id.clone());
        let nullifier_id = nullifier.nullifier_id.clone();
        self.nullifiers.insert(nullifier_id.clone(), nullifier);
        self.counters.nullifiers = self.counters.nullifiers.saturating_add(1);
        self.refresh_roots();
        Ok(nullifier_id)
    }

    pub fn adjudicate_batch(&mut self, input: AdjudicateBatchInput) -> Result<String> {
        let batch = LowFeeClaimAdjudicationBatch::new(input, self)?;
        for claim_id in &batch.claim_ids {
            let decision = if batch.accepted_claim_ids.contains(claim_id) {
                ClaimDecision::Accept
            } else if batch.rejected_claim_ids.contains(claim_id) {
                ClaimDecision::Reject
            } else if batch.quarantined_claim_ids.contains(claim_id) {
                ClaimDecision::Quarantine
            } else {
                ClaimDecision::Undecided
            };
            self.apply_claim_decision(claim_id, decision)?;
        }
        let savings = self
            .config
            .max_batch_fee_micro_units
            .saturating_mul(batch.claim_ids.len() as u64)
            .saturating_sub(batch.fee_micro_units);
        self.counters.low_fee_savings_micro_units = self
            .counters
            .low_fee_savings_micro_units
            .saturating_add(savings);
        let batch_id = batch.batch_id.clone();
        self.adjudication_batches.insert(batch_id.clone(), batch);
        self.counters.batches = self.counters.batches.saturating_add(1);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn settle_accepted_claim(&mut self, claim_id: &str, amount_atomic: u64) -> Result<()> {
        if amount_atomic == 0 {
            return Err("settled claim amount must be positive".to_string());
        }
        let claim = self
            .sealed_claims
            .get_mut(claim_id)
            .ok_or_else(|| "cannot settle unknown claim".to_string())?;
        if claim.status != ClaimStatus::Accepted {
            return Err("only accepted claims can be settled".to_string());
        }
        if self.reserve_available_atomic < amount_atomic {
            self.claim_failures
                .insert(claim_id.to_string(), ClaimFailureKind::ReserveInsufficient);
            return Err("reinsurance reserve insufficient for claim payout".to_string());
        }
        self.reserve_available_atomic = self.reserve_available_atomic.saturating_sub(amount_atomic);
        claim.status = ClaimStatus::Paid;
        self.counters.paid_claims = self.counters.paid_claims.saturating_add(1);
        self.counters.total_paid_atomic = self
            .counters
            .total_paid_atomic
            .saturating_add(amount_atomic);
        for coupon in self
            .coupons
            .values_mut()
            .filter(|coupon| coupon.claim_id == claim_id)
        {
            coupon.status = CouponStatus::Consumed;
        }
        if let Some(record) = self.receipt_records.get_mut(&claim.receipt_commitment) {
            record.status = ReceiptStatus::Paid;
            record.last_slot = self.current_slot;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn expire_old_claims(&mut self, current_slot: u64, current_epoch: u64) -> Result<u64> {
        self.current_slot = current_slot;
        self.current_epoch = current_epoch;
        let mut expired = 0_u64;
        for claim in self.sealed_claims.values_mut() {
            if matches!(
                claim.status,
                ClaimStatus::Sealed
                    | ClaimStatus::Witnessed
                    | ClaimStatus::CouponLocked
                    | ClaimStatus::AdjudicationPending
            ) && current_slot
                > claim
                    .claim_deadline_slot
                    .saturating_add(self.config.evidence_grace_slots)
            {
                claim.status = ClaimStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for coupon in self.coupons.values_mut() {
            if matches!(coupon.status, CouponStatus::Issued | CouponStatus::Locked)
                && current_epoch > coupon.expiry_epoch
            {
                coupon.status = CouponStatus::Expired;
            }
        }
        if expired > 0 {
            self.refresh_roots();
        }
        Ok(expired)
    }

    pub fn refresh_roots(&mut self) {
        let sealed_claims = self
            .sealed_claims
            .values()
            .map(SealedExitReceiptClaim::leaf)
            .collect::<Vec<_>>();
        let coupons = self
            .coupons
            .values()
            .map(ReinsuranceClaimCoupon::leaf)
            .collect::<Vec<_>>();
        let witnesses = self
            .witness_bundles
            .values()
            .map(PqWitnessBundle::leaf)
            .collect::<Vec<_>>();
        let nullifiers = self
            .nullifiers
            .values()
            .map(ClaimNullifier::leaf)
            .collect::<Vec<_>>();
        let batches = self
            .adjudication_batches
            .values()
            .map(LowFeeClaimAdjudicationBatch::leaf)
            .collect::<Vec<_>>();
        let redactions = self
            .redaction_roots
            .values()
            .map(PrivacyRedactionRoot::leaf)
            .collect::<Vec<_>>();
        let receipts = self
            .receipt_records
            .values()
            .map(ReceiptRecord::leaf)
            .collect::<Vec<_>>();
        self.roots = Roots {
            sealed_claim_root: merkle_root("xmss-reinsurance-claims:sealed", &sealed_claims),
            coupon_root: merkle_root("xmss-reinsurance-claims:coupons", &coupons),
            witness_bundle_root: merkle_root("xmss-reinsurance-claims:witnesses", &witnesses),
            nullifier_root: merkle_root("xmss-reinsurance-claims:nullifiers", &nullifiers),
            adjudication_batch_root: merkle_root("xmss-reinsurance-claims:batches", &batches),
            privacy_redaction_root: merkle_root("xmss-reinsurance-claims:redactions", &redactions),
            receipt_status_root: merkle_root("xmss-reinsurance-claims:receipts", &receipts),
            public_record_root: merkle_root(
                "xmss-reinsurance-claims:public-record",
                &[self.public_record_without_public_root()],
            ),
        };
    }

    pub fn state_root(&self) -> String {
        let root_json = json!({
            "config": {
                "chain_id": self.config.chain_id,
                "network": self.config.network,
                "protocol_version": self.config.protocol_version,
                "schema_version": self.config.schema_version,
                "hash_suite": self.config.hash_suite,
            },
            "counters": self.counters,
            "roots": self.roots,
            "reserve_available_atomic": self.reserve_available_atomic,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "current_slot": self.current_slot,
        });
        domain_hash(
            "xmss-reinsurance-claim:state-root",
            &[HashPart::Json(&root_json)],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_public_root();
        if let Value::Object(ref mut object) = record {
            object.insert(
                "public_record_root".to_string(),
                Value::String(self.roots.public_record_root.clone()),
            );
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn public_record_without_public_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "network": self.config.network,
            "hash_suite": self.config.hash_suite,
            "suites": {
                "xmss_claim": self.config.xmss_claim_suite,
                "sealed_exit_receipt_claim": self.config.sealed_exit_receipt_claim_suite,
                "reinsurance_claim_coupon": self.config.reinsurance_claim_coupon_suite,
                "pq_witness_bundle": self.config.pq_witness_bundle_suite,
                "claim_nullifier": self.config.claim_nullifier_suite,
                "low_fee_batch_adjudication": self.config.low_fee_batch_adjudication_suite,
                "privacy_redaction_root": self.config.privacy_redaction_root_suite,
                "roots_only_public_record": self.config.roots_only_public_record_suite,
            },
            "height": self.current_height,
            "epoch": self.current_epoch,
            "slot": self.current_slot,
            "roots": {
                "sealed_claim_root": self.roots.sealed_claim_root,
                "coupon_root": self.roots.coupon_root,
                "witness_bundle_root": self.roots.witness_bundle_root,
                "nullifier_root": self.roots.nullifier_root,
                "adjudication_batch_root": self.roots.adjudication_batch_root,
                "privacy_redaction_root": self.roots.privacy_redaction_root,
                "receipt_status_root": self.roots.receipt_status_root,
            },
            "counters": {
                "sealed_claims": self.counters.sealed_claims,
                "witness_bundles": self.counters.witness_bundles,
                "claim_coupons": self.counters.claim_coupons,
                "nullifiers": self.counters.nullifiers,
                "redaction_roots": self.counters.redaction_roots,
                "batches": self.counters.batches,
                "accepted_claims": self.counters.accepted_claims,
                "rejected_claims": self.counters.rejected_claims,
                "quarantined_claims": self.counters.quarantined_claims,
                "paid_claims": self.counters.paid_claims,
                "low_fee_savings_micro_units": self.counters.low_fee_savings_micro_units,
            },
            "fee_policy": {
                "low_fee_batch_limit": self.config.low_fee_batch_limit,
                "min_batch_size": self.config.min_batch_size,
                "max_batch_fee_micro_units": self.config.max_batch_fee_micro_units,
            },
            "privacy_policy": {
                "roots_only_public_records_required": self.config.roots_only_public_records_required,
                "privacy_redaction_roots_required": self.config.privacy_redaction_roots_required,
                "max_public_disclosure_fields": self.config.max_public_disclosure_fields,
                "min_redaction_shares": self.config.min_redaction_shares,
            },
        })
    }

    fn apply_claim_decision(&mut self, claim_id: &str, decision: ClaimDecision) -> Result<()> {
        let claim = self
            .sealed_claims
            .get_mut(claim_id)
            .ok_or_else(|| "cannot decide unknown claim".to_string())?;
        match decision {
            ClaimDecision::Accept => {
                claim.status = ClaimStatus::Accepted;
                self.counters.accepted_claims = self.counters.accepted_claims.saturating_add(1);
                self.counters.total_claimed_atomic = self
                    .counters
                    .total_claimed_atomic
                    .saturating_add(self.config.claim_bond_atomic);
                if let Some(record) = self.receipt_records.get_mut(&claim.receipt_commitment) {
                    record.status = ReceiptStatus::Reinsured;
                    record.last_slot = self.current_slot;
                }
                for coupon in self
                    .coupons
                    .values_mut()
                    .filter(|coupon| coupon.claim_id == claim_id)
                {
                    coupon.status = CouponStatus::Locked;
                }
            }
            ClaimDecision::Reject => {
                claim.status = ClaimStatus::Rejected;
                self.counters.rejected_claims = self.counters.rejected_claims.saturating_add(1);
                for coupon in self
                    .coupons
                    .values_mut()
                    .filter(|coupon| coupon.claim_id == claim_id)
                {
                    coupon.status = CouponStatus::Refunded;
                }
            }
            ClaimDecision::Quarantine => {
                claim.status = ClaimStatus::AdjudicationPending;
                self.counters.quarantined_claims =
                    self.counters.quarantined_claims.saturating_add(1);
            }
            ClaimDecision::Undecided => {
                claim.status = ClaimStatus::AdjudicationPending;
            }
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

fn require_hash_like(label: &str, value: &str) -> Result<()> {
    if value.len() < 16 {
        return Err(format!("{label} must be a non-trivial commitment"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{label} must not contain whitespace"));
    }
    Ok(())
}

fn xmss_leaf_key(attestation: &XmssClaimAttestation) -> String {
    domain_hash(
        "xmss-reinsurance-claim:leaf-key",
        &[
            HashPart::Str(&attestation.xmss_public_root),
            HashPart::U64(attestation.xmss_tree_epoch),
            HashPart::U64(u64::from(attestation.xmss_leaf_index)),
        ],
        32,
    )
}
