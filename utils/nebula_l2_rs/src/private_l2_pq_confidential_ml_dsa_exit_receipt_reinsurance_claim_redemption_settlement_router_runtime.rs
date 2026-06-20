use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlDsaExitReceiptReinsuranceClaimRedemptionSettlementRouterRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_EXIT_RECEIPT_REINSURANCE_CLAIM_REDEMPTION_SETTLEMENT_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-ml-dsa-exit-receipt-reinsurance-claim-redemption-settlement-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_EXIT_RECEIPT_REINSURANCE_CLAIM_REDEMPTION_SETTLEMENT_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_DSA_ROUTER_SETTLEMENT_SUITE: &str =
    "ml-dsa-module-lattice-exit-receipt-reinsurance-claim-redemption-settlement-router-v1";
pub const CONFIDENTIAL_EXIT_RECEIPT_SUITE: &str =
    "ml-dsa-confidential-exit-receipt-router-commitment-v1";
pub const CLAIM_REDEMPTION_AUTH_SUITE: &str =
    "module-lattice-ml-dsa-private-claim-redemption-router-authorization-v1";
pub const REINSURANCE_SETTLEMENT_ACCOUNTING_SUITE: &str =
    "roots-only-ml-dsa-reinsurance-claim-redemption-router-accounting-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str = "low-fee-ml-dsa-claim-redemption-router-batch-v1";
pub const SOLVENCY_RESERVE_SUITE: &str =
    "privacy-preserving-reinsurance-solvency-reserve-release-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-ml-dsa-claim-redemption-settlement-router-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 10_208_000;
pub const DEVNET_EPOCH: u64 = 42_533;
pub const DEVNET_SLOT: u64 = 704;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ML_DSA_MODULE_RANK: u8 = 8;
pub const DEFAULT_ML_DSA_PARAMETER_SET: u8 = 5;
pub const DEFAULT_ML_DSA_HINT_WEIGHT: u16 = 80;
pub const DEFAULT_ML_DSA_ETA: u8 = 4;
pub const DEFAULT_ML_DSA_SIGNATURE_BYTES_CAP: u32 = 4_627;
pub const DEFAULT_REDEMPTION_WINDOW_SLOTS: u64 = 4_096;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 512;
pub const DEFAULT_CLAIM_PROOF_GRACE_SLOTS: u64 = 384;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 160;
pub const DEFAULT_NULLIFIER_BUCKETS: u32 = 262_144;
pub const DEFAULT_REINSURANCE_POOL_ATOMIC: u64 = 144_000_000_000;
pub const DEFAULT_MIN_SOLVENCY_RESERVE_ATOMIC: u64 = 28_800_000_000;
pub const DEFAULT_MAX_CLAIM_REDEMPTION_ATOMIC: u64 = 14_400_000_000;
pub const DEFAULT_SETTLEMENT_ESCROW_ATOMIC: u64 = 1_440_000_000;
pub const DEFAULT_REINSURER_SHARE_BPS: u16 = 7_400;
pub const DEFAULT_CEDENT_SHARE_BPS: u16 = 2_600;
pub const DEFAULT_SOLVENCY_BUFFER_BPS: u16 = 1_800;
pub const DEFAULT_PROTOCOL_FEE_BPS: u16 = 12;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 1_536;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 72;
pub const DEFAULT_EPOCH_BUCKET_TARGET_SETTLEMENTS: u64 = 73_728;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Drafted,
    ReceiptCommitted,
    ClaimAuthorized,
    ReserveLocked,
    ProofAnchored,
    Queued,
    Redeemed,
    Settled,
    Rejected,
    Expired,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::ReceiptCommitted => "receipt_committed",
            Self::ClaimAuthorized => "claim_authorized",
            Self::ReserveLocked => "reserve_locked",
            Self::ProofAnchored => "proof_anchored",
            Self::Queued => "queued",
            Self::Redeemed => "redeemed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAccountingSide {
    ClaimReserveLock,
    SettlementEscrow,
    ReinsurerPayable,
    CedentPayable,
    ClaimantPayout,
    SolvencyBuffer,
    SolvencyRelease,
    Refund,
    ProtocolFee,
    BatchFee,
}

impl SettlementAccountingSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimReserveLock => "claim_reserve_lock",
            Self::SettlementEscrow => "settlement_escrow",
            Self::ReinsurerPayable => "reinsurer_payable",
            Self::CedentPayable => "cedent_payable",
            Self::ClaimantPayout => "claimant_payout",
            Self::SolvencyBuffer => "solvency_buffer",
            Self::SolvencyRelease => "solvency_release",
            Self::Refund => "refund",
            Self::ProtocolFee => "protocol_fee",
            Self::BatchFee => "batch_fee",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Collecting,
    Posted,
    Executed,
    Settled,
    Rejected,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Posted => "posted",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofMode {
    MlDsaModuleLatticeAttestation,
    MerkleMembership,
    AggregatedBatchProof,
    SolvencyStateTransition,
}

impl ProofMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsaModuleLatticeAttestation => "ml_dsa_router_hash_attestation",
            Self::MerkleMembership => "merkle_membership",
            Self::AggregatedBatchProof => "aggregated_batch_proof",
            Self::SolvencyStateTransition => "solvency_state_transition",
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
    pub ml_dsa_router_settlement_suite: String,
    pub confidential_exit_receipt_suite: String,
    pub claim_redemption_auth_suite: String,
    pub reinsurance_settlement_accounting_suite: String,
    pub low_fee_settlement_batch_suite: String,
    pub solvency_reserve_suite: String,
    pub roots_only_public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub ml_dsa_module_rank: u8,
    pub ml_dsa_parameter_set: u8,
    pub ml_dsa_hint_weight: u16,
    pub ml_dsa_eta: u8,
    pub ml_dsa_signature_bytes_cap: u32,
    pub redemption_window_slots: u64,
    pub settlement_delay_slots: u64,
    pub claim_proof_grace_slots: u64,
    pub receipt_retention_epochs: u64,
    pub nullifier_buckets: u32,
    pub reinsurance_pool_atomic: u64,
    pub min_solvency_reserve_atomic: u64,
    pub max_claim_redemption_atomic: u64,
    pub settlement_escrow_atomic: u64,
    pub reinsurer_share_bps: u16,
    pub cedent_share_bps: u16,
    pub solvency_buffer_bps: u16,
    pub protocol_fee_bps: u16,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_settlements: u64,
    pub ml_dsa_authorization_required: bool,
    pub confidential_exit_receipts_required: bool,
    pub claim_nullifiers_required: bool,
    pub solvency_reserve_required: bool,
    pub low_fee_batching_enabled: bool,
    pub roots_only_public_records_required: bool,
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
            ml_dsa_router_settlement_suite: ML_DSA_ROUTER_SETTLEMENT_SUITE.to_string(),
            confidential_exit_receipt_suite: CONFIDENTIAL_EXIT_RECEIPT_SUITE.to_string(),
            claim_redemption_auth_suite: CLAIM_REDEMPTION_AUTH_SUITE.to_string(),
            reinsurance_settlement_accounting_suite: REINSURANCE_SETTLEMENT_ACCOUNTING_SUITE
                .to_string(),
            low_fee_settlement_batch_suite: LOW_FEE_SETTLEMENT_BATCH_SUITE.to_string(),
            solvency_reserve_suite: SOLVENCY_RESERVE_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            ml_dsa_module_rank: DEFAULT_ML_DSA_MODULE_RANK,
            ml_dsa_parameter_set: DEFAULT_ML_DSA_PARAMETER_SET,
            ml_dsa_hint_weight: DEFAULT_ML_DSA_HINT_WEIGHT,
            ml_dsa_eta: DEFAULT_ML_DSA_ETA,
            ml_dsa_signature_bytes_cap: DEFAULT_ML_DSA_SIGNATURE_BYTES_CAP,
            redemption_window_slots: DEFAULT_REDEMPTION_WINDOW_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            claim_proof_grace_slots: DEFAULT_CLAIM_PROOF_GRACE_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            nullifier_buckets: DEFAULT_NULLIFIER_BUCKETS,
            reinsurance_pool_atomic: DEFAULT_REINSURANCE_POOL_ATOMIC,
            min_solvency_reserve_atomic: DEFAULT_MIN_SOLVENCY_RESERVE_ATOMIC,
            max_claim_redemption_atomic: DEFAULT_MAX_CLAIM_REDEMPTION_ATOMIC,
            settlement_escrow_atomic: DEFAULT_SETTLEMENT_ESCROW_ATOMIC,
            reinsurer_share_bps: DEFAULT_REINSURER_SHARE_BPS,
            cedent_share_bps: DEFAULT_CEDENT_SHARE_BPS,
            solvency_buffer_bps: DEFAULT_SOLVENCY_BUFFER_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_settlements: DEFAULT_EPOCH_BUCKET_TARGET_SETTLEMENTS,
            ml_dsa_authorization_required: true,
            confidential_exit_receipts_required: true,
            claim_nullifiers_required: true,
            solvency_reserve_required: true,
            low_fee_batching_enabled: true,
            roots_only_public_records_required: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below ml-dsa-router settlement minimum".to_string());
        }
        if self.ml_dsa_module_rank < 4
            || self.ml_dsa_parameter_set == 0
            || self.ml_dsa_hint_weight < 30
            || self.ml_dsa_eta == 0
        {
            return Err("invalid ml-dsa-router settlement parameter schedule".to_string());
        }
        if self.ml_dsa_signature_bytes_cap < 2_400 {
            return Err(
                "ml-dsa-router signature cap below expected module-lattice floor".to_string(),
            );
        }
        if self.redemption_window_slots
            <= self.settlement_delay_slots + self.claim_proof_grace_slots
        {
            return Err("invalid claim redemption settlement window".to_string());
        }
        if self.receipt_retention_epochs == 0
            || self.nullifier_buckets == 0
            || self.epoch_bucket_target_settlements == 0
        {
            return Err("retention, buckets, and settlement targets must be positive".to_string());
        }
        if self.reinsurance_pool_atomic <= self.min_solvency_reserve_atomic
            || self.max_claim_redemption_atomic == 0
            || self.max_claim_redemption_atomic > self.reinsurance_pool_atomic
            || self.settlement_escrow_atomic == 0
        {
            return Err("invalid reinsurance settlement economics".to_string());
        }
        if u32::from(self.reinsurer_share_bps) + u32::from(self.cedent_share_bps) != 10_000 {
            return Err("reinsurance settlement shares must sum to 10000 bps".to_string());
        }
        if self.solvency_buffer_bps > 5_000 || self.protocol_fee_bps > 500 {
            return Err("settlement buffer or protocol fee exceeds policy bound".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
            || self.max_batch_fee_micro_units == 0
        {
            return Err("invalid low-fee settlement batch policy".to_string());
        }
        if !self.ml_dsa_authorization_required
            || !self.confidential_exit_receipts_required
            || !self.claim_nullifiers_required
            || !self.solvency_reserve_required
            || !self.roots_only_public_records_required
        {
            return Err(
                "ml-dsa-router, confidentiality, nullifier, reserve, and roots-only gates are mandatory"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "network": self.network,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "suites": {
                "ml_dsa_router_settlement": self.ml_dsa_router_settlement_suite,
                "confidential_exit_receipt": self.confidential_exit_receipt_suite,
                "claim_redemption_auth": self.claim_redemption_auth_suite,
                "reinsurance_settlement_accounting": self.reinsurance_settlement_accounting_suite,
                "low_fee_settlement_batch": self.low_fee_settlement_batch_suite,
                "solvency_reserve": self.solvency_reserve_suite,
                "roots_only_public_record": self.roots_only_public_record_suite,
            },
            "security": {
                "min_pq_security_bits": self.min_pq_security_bits,
                "ml_dsa_module_rank": self.ml_dsa_module_rank,
                "ml_dsa_parameter_set": self.ml_dsa_parameter_set,
                "ml_dsa_hint_weight": self.ml_dsa_hint_weight,
                "ml_dsa_eta": self.ml_dsa_eta,
                "ml_dsa_signature_bytes_cap": self.ml_dsa_signature_bytes_cap,
            },
            "timing": {
                "redemption_window_slots": self.redemption_window_slots,
                "settlement_delay_slots": self.settlement_delay_slots,
                "claim_proof_grace_slots": self.claim_proof_grace_slots,
                "receipt_retention_epochs": self.receipt_retention_epochs,
            },
            "fees": {
                "protocol_fee_bps": self.protocol_fee_bps,
                "low_fee_batch_limit": self.low_fee_batch_limit,
                "min_batch_size": self.min_batch_size,
                "max_batch_fee_micro_units": self.max_batch_fee_micro_units,
                "low_fee_batching_enabled": self.low_fee_batching_enabled,
            },
            "privacy": {
                "claim_nullifiers_required": self.claim_nullifiers_required,
                "confidential_exit_receipts_required": self.confidential_exit_receipts_required,
                "roots_only_public_records_required": self.roots_only_public_records_required,
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub settlement_claims: u64,
    pub receipt_commitments: u64,
    pub ml_dsa_router_authorizations: u64,
    pub proof_anchors: u64,
    pub accounting_entries: u64,
    pub settlement_batches: u64,
    pub spent_claim_nullifiers: u64,
    pub reserve_locks: u64,
    pub redeemed_claims: u64,
    pub settled_claims: u64,
    pub rejected_claims: u64,
    pub expired_claims: u64,
    pub total_claimed_atomic: u64,
    pub total_reserved_atomic: u64,
    pub total_escrowed_atomic: u64,
    pub total_reinsurer_payable_atomic: u64,
    pub total_cedent_payable_atomic: u64,
    pub total_claimant_payout_atomic: u64,
    pub total_solvency_buffer_atomic: u64,
    pub total_solvency_released_atomic: u64,
    pub total_refunded_atomic: u64,
    pub total_protocol_fee_atomic: u64,
    pub total_batch_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub settlement_claim_root: String,
    pub receipt_commitment_root: String,
    pub ml_dsa_router_authorization_root: String,
    pub proof_anchor_root: String,
    pub accounting_entry_root: String,
    pub settlement_batch_root: String,
    pub claim_nullifier_root: String,
    pub reserve_lock_root: String,
    pub solvency_reserve_root: String,
    pub fee_market_root: String,
    pub privacy_redaction_root: String,
    pub private_accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = record_root("empty", Vec::new());
        Self {
            settlement_claim_root: empty.clone(),
            receipt_commitment_root: empty.clone(),
            ml_dsa_router_authorization_root: empty.clone(),
            proof_anchor_root: empty.clone(),
            accounting_entry_root: empty.clone(),
            settlement_batch_root: empty.clone(),
            claim_nullifier_root: empty.clone(),
            reserve_lock_root: empty.clone(),
            solvency_reserve_root: empty.clone(),
            fee_market_root: empty.clone(),
            privacy_redaction_root: empty.clone(),
            private_accounting_root: empty.clone(),
            public_record_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementClaimInput {
    pub exit_receipt_commitment_root: String,
    pub claim_commitment_root: String,
    pub policy_commitment_root: String,
    pub claimant_commitment_root: String,
    pub cedent_commitment_root: String,
    pub reinsurer_commitment_root: String,
    pub encrypted_claim_terms_root: String,
    pub claim_amount_commitment: String,
    pub claim_amount_atomic: u64,
    pub claim_nullifier: String,
    pub nullifier_bucket: u32,
    pub receipt_slot: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitReceiptCommitmentInput {
    pub settlement_id: String,
    pub receipt_digest_root: String,
    pub exit_state_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_membership_root: String,
    pub receipt_nullifier: String,
    pub privacy_redaction_root: String,
    pub committed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlDsaRouterClaimAuthorizationInput {
    pub settlement_id: String,
    pub ml_dsa_public_key_root: String,
    pub ml_dsa_signature_root: String,
    pub message_digest_root: String,
    pub ml_dsa_challenge_root: String,
    pub module_lattice_transcript_root: String,
    pub hint_commitment_root: String,
    pub pq_security_bits: u16,
    pub signature_bytes: u32,
    pub authorized_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementProofAnchorInput {
    pub settlement_id: String,
    pub proof_mode: ProofMode,
    pub proof_commitment_root: String,
    pub claim_membership_root: String,
    pub reserve_membership_root: String,
    pub accounting_transition_root: String,
    pub solvency_state_root: String,
    pub privacy_redaction_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementAccountingEntryInput {
    pub settlement_id: String,
    pub side: SettlementAccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
    pub memo_commitment_root: String,
    pub effective_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSettlementBatchInput {
    pub epoch: u64,
    pub sequencer_commitment_root: String,
    pub settlement_ids: BTreeSet<String>,
    pub settled_settlement_ids: BTreeSet<String>,
    pub rejected_settlement_ids: BTreeSet<String>,
    pub aggregation_root: String,
    pub compression_root: String,
    pub fee_sponsor_commitment_root: String,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementClaim {
    pub settlement_id: String,
    pub exit_receipt_commitment_root: String,
    pub claim_commitment_root: String,
    pub policy_commitment_root: String,
    pub claimant_commitment_root: String,
    pub cedent_commitment_root: String,
    pub reinsurer_commitment_root: String,
    pub encrypted_claim_terms_root: String,
    pub claim_amount_commitment: String,
    pub claim_amount_atomic: u64,
    pub claim_nullifier: String,
    pub nullifier_bucket: u32,
    pub receipt_slot: u64,
    pub submitted_slot: u64,
    pub eligible_slot: u64,
    pub expires_slot: u64,
    pub retained_until_epoch: u64,
    pub reinsurer_payable_atomic: u64,
    pub cedent_payable_atomic: u64,
    pub solvency_buffer_atomic: u64,
    pub protocol_fee_atomic: u64,
    pub status: SettlementStatus,
}

impl SettlementClaim {
    pub fn from_input(config: &Config, epoch: u64, input: SettlementClaimInput) -> Result<Self> {
        require_non_empty(&[
            (
                &input.exit_receipt_commitment_root,
                "exit receipt commitment root",
            ),
            (&input.claim_commitment_root, "claim commitment root"),
            (&input.policy_commitment_root, "policy commitment root"),
            (&input.claimant_commitment_root, "claimant commitment root"),
            (&input.cedent_commitment_root, "cedent commitment root"),
            (
                &input.reinsurer_commitment_root,
                "reinsurer commitment root",
            ),
            (
                &input.encrypted_claim_terms_root,
                "encrypted claim terms root",
            ),
            (&input.claim_amount_commitment, "claim amount commitment"),
            (&input.claim_nullifier, "claim nullifier"),
        ])?;
        if input.nullifier_bucket >= config.nullifier_buckets {
            return Err("claim nullifier bucket exceeds configured bucket count".to_string());
        }
        if input.claim_amount_atomic == 0
            || input.claim_amount_atomic > config.max_claim_redemption_atomic
        {
            return Err("claim amount outside settlement policy".to_string());
        }
        let settlement_id = deterministic_id(
            "settlement-claim",
            &[
                HashPart::Str(&input.exit_receipt_commitment_root),
                HashPart::Str(&input.claim_commitment_root),
                HashPart::Str(&input.claim_nullifier),
                HashPart::U64(u64::from(input.nullifier_bucket)),
                HashPart::U64(input.receipt_slot),
                HashPart::U64(input.submitted_slot),
            ],
        );
        let reinsurer_payable_atomic =
            bps_amount(input.claim_amount_atomic, config.reinsurer_share_bps);
        let cedent_payable_atomic = input.claim_amount_atomic - reinsurer_payable_atomic;
        let solvency_buffer_atomic =
            bps_amount(input.claim_amount_atomic, config.solvency_buffer_bps);
        let protocol_fee_atomic = bps_amount(input.claim_amount_atomic, config.protocol_fee_bps);
        Ok(Self {
            settlement_id,
            exit_receipt_commitment_root: input.exit_receipt_commitment_root,
            claim_commitment_root: input.claim_commitment_root,
            policy_commitment_root: input.policy_commitment_root,
            claimant_commitment_root: input.claimant_commitment_root,
            cedent_commitment_root: input.cedent_commitment_root,
            reinsurer_commitment_root: input.reinsurer_commitment_root,
            encrypted_claim_terms_root: input.encrypted_claim_terms_root,
            claim_amount_commitment: input.claim_amount_commitment,
            claim_amount_atomic: input.claim_amount_atomic,
            claim_nullifier: input.claim_nullifier,
            nullifier_bucket: input.nullifier_bucket,
            receipt_slot: input.receipt_slot,
            submitted_slot: input.submitted_slot,
            eligible_slot: input.submitted_slot + config.settlement_delay_slots,
            expires_slot: input.submitted_slot + config.redemption_window_slots,
            retained_until_epoch: epoch + config.receipt_retention_epochs,
            reinsurer_payable_atomic,
            cedent_payable_atomic,
            solvency_buffer_atomic,
            protocol_fee_atomic,
            status: SettlementStatus::Drafted,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "exit_receipt_commitment_root": self.exit_receipt_commitment_root,
            "claim_commitment_root": self.claim_commitment_root,
            "policy_commitment_root": self.policy_commitment_root,
            "claimant_commitment_root": self.claimant_commitment_root,
            "cedent_commitment_root": self.cedent_commitment_root,
            "reinsurer_commitment_root": self.reinsurer_commitment_root,
            "encrypted_claim_terms_root": self.encrypted_claim_terms_root,
            "claim_amount_commitment": self.claim_amount_commitment,
            "claim_nullifier": self.claim_nullifier,
            "nullifier_bucket": self.nullifier_bucket,
            "receipt_slot": self.receipt_slot,
            "submitted_slot": self.submitted_slot,
            "eligible_slot": self.eligible_slot,
            "expires_slot": self.expires_slot,
            "retained_until_epoch": self.retained_until_epoch,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitReceiptCommitment {
    pub receipt_id: String,
    pub settlement_id: String,
    pub receipt_digest_root: String,
    pub exit_state_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_membership_root: String,
    pub receipt_nullifier: String,
    pub privacy_redaction_root: String,
    pub committed_slot: u64,
}

impl ExitReceiptCommitment {
    pub fn from_input(input: ExitReceiptCommitmentInput) -> Result<Self> {
        require_non_empty(&[
            (&input.settlement_id, "settlement id"),
            (&input.receipt_digest_root, "receipt digest root"),
            (&input.exit_state_root, "exit state root"),
            (
                &input.encrypted_receipt_payload_root,
                "encrypted receipt payload root",
            ),
            (&input.receipt_membership_root, "receipt membership root"),
            (&input.receipt_nullifier, "receipt nullifier"),
            (&input.privacy_redaction_root, "privacy redaction root"),
        ])?;
        let receipt_id = deterministic_id(
            "exit-receipt-commitment",
            &[
                HashPart::Str(&input.settlement_id),
                HashPart::Str(&input.receipt_digest_root),
                HashPart::Str(&input.receipt_nullifier),
                HashPart::U64(input.committed_slot),
            ],
        );
        Ok(Self {
            receipt_id,
            settlement_id: input.settlement_id,
            receipt_digest_root: input.receipt_digest_root,
            exit_state_root: input.exit_state_root,
            encrypted_receipt_payload_root: input.encrypted_receipt_payload_root,
            receipt_membership_root: input.receipt_membership_root,
            receipt_nullifier: input.receipt_nullifier,
            privacy_redaction_root: input.privacy_redaction_root,
            committed_slot: input.committed_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "settlement_id": self.settlement_id,
            "receipt_digest_root": self.receipt_digest_root,
            "exit_state_root": self.exit_state_root,
            "encrypted_receipt_payload_root": self.encrypted_receipt_payload_root,
            "receipt_membership_root": self.receipt_membership_root,
            "receipt_nullifier": self.receipt_nullifier,
            "privacy_redaction_root": self.privacy_redaction_root,
            "committed_slot": self.committed_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlDsaRouterClaimAuthorization {
    pub authorization_id: String,
    pub settlement_id: String,
    pub ml_dsa_public_key_root: String,
    pub ml_dsa_signature_root: String,
    pub message_digest_root: String,
    pub ml_dsa_challenge_root: String,
    pub module_lattice_transcript_root: String,
    pub hint_commitment_root: String,
    pub pq_security_bits: u16,
    pub signature_bytes: u32,
    pub module_rank: u8,
    pub parameter_set: u8,
    pub hint_weight: u16,
    pub eta: u8,
    pub authorized_slot: u64,
}

impl MlDsaRouterClaimAuthorization {
    pub fn from_input(config: &Config, input: MlDsaRouterClaimAuthorizationInput) -> Result<Self> {
        require_non_empty(&[
            (&input.settlement_id, "settlement id"),
            (
                &input.ml_dsa_public_key_root,
                "ml-dsa-router public key root",
            ),
            (&input.ml_dsa_signature_root, "ml-dsa-router signature root"),
            (&input.message_digest_root, "message digest root"),
            (&input.ml_dsa_challenge_root, "ml-dsa challenge root"),
            (
                &input.module_lattice_transcript_root,
                "module lattice transcript root",
            ),
            (&input.hint_commitment_root, "hint commitment root"),
        ])?;
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("ml-dsa-router authorization below configured pq security".to_string());
        }
        if input.signature_bytes == 0 || input.signature_bytes > config.ml_dsa_signature_bytes_cap {
            return Err("ml-dsa-router authorization signature size outside policy".to_string());
        }
        let authorization_id = deterministic_id(
            "ml-dsa-router-claim-authorization",
            &[
                HashPart::Str(&input.settlement_id),
                HashPart::Str(&input.ml_dsa_public_key_root),
                HashPart::Str(&input.ml_dsa_signature_root),
                HashPart::Str(&input.message_digest_root),
                HashPart::Str(&input.ml_dsa_challenge_root),
                HashPart::U64(input.authorized_slot),
            ],
        );
        Ok(Self {
            authorization_id,
            settlement_id: input.settlement_id,
            ml_dsa_public_key_root: input.ml_dsa_public_key_root,
            ml_dsa_signature_root: input.ml_dsa_signature_root,
            message_digest_root: input.message_digest_root,
            ml_dsa_challenge_root: input.ml_dsa_challenge_root,
            module_lattice_transcript_root: input.module_lattice_transcript_root,
            hint_commitment_root: input.hint_commitment_root,
            pq_security_bits: input.pq_security_bits,
            signature_bytes: input.signature_bytes,
            module_rank: config.ml_dsa_module_rank,
            parameter_set: config.ml_dsa_parameter_set,
            hint_weight: config.ml_dsa_hint_weight,
            eta: config.ml_dsa_eta,
            authorized_slot: input.authorized_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "settlement_id": self.settlement_id,
            "ml_dsa_public_key_root": self.ml_dsa_public_key_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "message_digest_root": self.message_digest_root,
            "ml_dsa_challenge_root": self.ml_dsa_challenge_root,
            "module_lattice_transcript_root": self.module_lattice_transcript_root,
            "hint_commitment_root": self.hint_commitment_root,
            "pq_security_bits": self.pq_security_bits,
            "signature_bytes": self.signature_bytes,
            "authorized_slot": self.authorized_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementProofAnchor {
    pub proof_id: String,
    pub settlement_id: String,
    pub proof_mode: ProofMode,
    pub proof_commitment_root: String,
    pub claim_membership_root: String,
    pub reserve_membership_root: String,
    pub accounting_transition_root: String,
    pub solvency_state_root: String,
    pub privacy_redaction_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

impl SettlementProofAnchor {
    pub fn from_input(input: SettlementProofAnchorInput) -> Result<Self> {
        require_non_empty(&[
            (&input.settlement_id, "settlement id"),
            (&input.proof_commitment_root, "proof commitment root"),
            (&input.claim_membership_root, "claim membership root"),
            (&input.reserve_membership_root, "reserve membership root"),
            (
                &input.accounting_transition_root,
                "accounting transition root",
            ),
            (&input.solvency_state_root, "solvency state root"),
            (&input.privacy_redaction_root, "privacy redaction root"),
        ])?;
        let proof_id = deterministic_id(
            "settlement-proof-anchor",
            &[
                HashPart::Str(&input.settlement_id),
                HashPart::Str(input.proof_mode.as_str()),
                HashPart::Str(&input.proof_commitment_root),
                HashPart::U64(input.anchored_slot),
            ],
        );
        Ok(Self {
            proof_id,
            settlement_id: input.settlement_id,
            proof_mode: input.proof_mode,
            proof_commitment_root: input.proof_commitment_root,
            claim_membership_root: input.claim_membership_root,
            reserve_membership_root: input.reserve_membership_root,
            accounting_transition_root: input.accounting_transition_root,
            solvency_state_root: input.solvency_state_root,
            privacy_redaction_root: input.privacy_redaction_root,
            accepted: input.accepted,
            anchored_slot: input.anchored_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "settlement_id": self.settlement_id,
            "proof_mode": self.proof_mode.as_str(),
            "proof_commitment_root": self.proof_commitment_root,
            "claim_membership_root": self.claim_membership_root,
            "reserve_membership_root": self.reserve_membership_root,
            "accounting_transition_root": self.accounting_transition_root,
            "solvency_state_root": self.solvency_state_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "accepted": self.accepted,
            "anchored_slot": self.anchored_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementAccountingEntry {
    pub accounting_id: String,
    pub settlement_id: String,
    pub side: SettlementAccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
    pub memo_commitment_root: String,
    pub effective_slot: u64,
}

impl SettlementAccountingEntry {
    pub fn from_input(input: SettlementAccountingEntryInput) -> Result<Self> {
        require_non_empty(&[
            (&input.settlement_id, "settlement id"),
            (&input.account_commitment_root, "account commitment root"),
            (&input.memo_commitment_root, "memo commitment root"),
        ])?;
        if input.amount_atomic == 0 {
            return Err("settlement accounting amount must be positive".to_string());
        }
        let accounting_id = deterministic_id(
            "settlement-accounting-entry",
            &[
                HashPart::Str(&input.settlement_id),
                HashPart::Str(input.side.as_str()),
                HashPart::Str(&input.account_commitment_root),
                HashPart::Str(&input.memo_commitment_root),
                HashPart::U64(input.amount_atomic),
                HashPart::U64(input.effective_slot),
            ],
        );
        Ok(Self {
            accounting_id,
            settlement_id: input.settlement_id,
            side: input.side,
            amount_atomic: input.amount_atomic,
            account_commitment_root: input.account_commitment_root,
            memo_commitment_root: input.memo_commitment_root,
            effective_slot: input.effective_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "accounting_id": self.accounting_id,
            "settlement_id": self.settlement_id,
            "side": self.side.as_str(),
            "amount_commitment_root": value_root("redacted-accounting-amount", &json!({
                "accounting_id": self.accounting_id,
                "side": self.side.as_str(),
                "amount_atomic": self.amount_atomic,
            })),
            "account_commitment_root": self.account_commitment_root,
            "memo_commitment_root": self.memo_commitment_root,
            "effective_slot": self.effective_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub sequencer_commitment_root: String,
    pub settlement_ids: BTreeSet<String>,
    pub settled_settlement_ids: BTreeSet<String>,
    pub rejected_settlement_ids: BTreeSet<String>,
    pub aggregation_root: String,
    pub compression_root: String,
    pub fee_sponsor_commitment_root: String,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
    pub status: SettlementBatchStatus,
}

impl LowFeeSettlementBatch {
    pub fn from_input(config: &Config, input: LowFeeSettlementBatchInput) -> Result<Self> {
        require_non_empty(&[
            (
                &input.sequencer_commitment_root,
                "sequencer commitment root",
            ),
            (&input.aggregation_root, "aggregation root"),
            (&input.compression_root, "compression root"),
            (
                &input.fee_sponsor_commitment_root,
                "fee sponsor commitment root",
            ),
        ])?;
        if input.settlement_ids.len() < usize::from(config.min_batch_size)
            || input.settlement_ids.len() > usize::from(config.low_fee_batch_limit)
        {
            return Err("settlement batch size outside low-fee policy".to_string());
        }
        if input.batch_fee_micro_units > config.max_batch_fee_micro_units {
            return Err("settlement batch fee exceeds low-fee policy".to_string());
        }
        if !input
            .settled_settlement_ids
            .is_subset(&input.settlement_ids)
            || !input
                .rejected_settlement_ids
                .is_subset(&input.settlement_ids)
            || !input
                .settled_settlement_ids
                .is_disjoint(&input.rejected_settlement_ids)
        {
            return Err("settlement batch result sets are inconsistent".to_string());
        }
        let batch_id = deterministic_id(
            "low-fee-settlement-batch",
            &[
                HashPart::U64(input.epoch),
                HashPart::Str(&input.sequencer_commitment_root),
                HashPart::Str(&input.aggregation_root),
                HashPart::Str(&input.compression_root),
                HashPart::U64(input.posted_slot),
            ],
        );
        Ok(Self {
            batch_id,
            epoch: input.epoch,
            sequencer_commitment_root: input.sequencer_commitment_root,
            settlement_ids: input.settlement_ids,
            settled_settlement_ids: input.settled_settlement_ids,
            rejected_settlement_ids: input.rejected_settlement_ids,
            aggregation_root: input.aggregation_root,
            compression_root: input.compression_root,
            fee_sponsor_commitment_root: input.fee_sponsor_commitment_root,
            batch_fee_micro_units: input.batch_fee_micro_units,
            posted_slot: input.posted_slot,
            status: SettlementBatchStatus::Posted,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "sequencer_commitment_root": self.sequencer_commitment_root,
            "settlement_set_root": record_root("batch-settlement-set", self.settlement_ids.iter().map(|id| json!(id)).collect()),
            "settled_set_root": record_root("batch-settled-set", self.settled_settlement_ids.iter().map(|id| json!(id)).collect()),
            "rejected_set_root": record_root("batch-rejected-set", self.rejected_settlement_ids.iter().map(|id| json!(id)).collect()),
            "aggregation_root": self.aggregation_root,
            "compression_root": self.compression_root,
            "fee_sponsor_commitment_root": self.fee_sponsor_commitment_root,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "posted_slot": self.posted_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolvencySnapshot {
    pub reinsurance_pool_atomic: u64,
    pub min_solvency_reserve_atomic: u64,
    pub active_reserved_atomic: u64,
    pub active_escrowed_atomic: u64,
    pub settled_claimant_payout_atomic: u64,
    pub solvency_buffer_atomic: u64,
    pub available_after_reserve_atomic: u64,
    pub solvency_reserve_root: String,
}

impl SolvencySnapshot {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeMarketSnapshot {
    pub low_fee_batching_enabled: bool,
    pub max_batch_fee_micro_units: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_protocol_fee_atomic: u64,
    pub fee_market_root: String,
}

impl FeeMarketSnapshot {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyApiSnapshot {
    pub protocol_version: String,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub solvency: SolvencySnapshot,
    pub fee_market: FeeMarketSnapshot,
}

impl RootsOnlyApiSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "height": self.height,
            "epoch": self.epoch,
            "slot": self.slot,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "solvency": self.solvency.public_record(),
            "fee_market": self.fee_market.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub settlement_claims: BTreeMap<String, SettlementClaim>,
    pub receipt_commitments: BTreeMap<String, ExitReceiptCommitment>,
    pub ml_dsa_router_authorizations: BTreeMap<String, MlDsaRouterClaimAuthorization>,
    pub proof_anchors: BTreeMap<String, SettlementProofAnchor>,
    pub accounting_entries: BTreeMap<String, SettlementAccountingEntry>,
    pub settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64, slot: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            slot,
            counters: Counters::default(),
            roots: Roots::default(),
            settlement_claims: BTreeMap::new(),
            receipt_commitments: BTreeMap::new(),
            ml_dsa_router_authorizations: BTreeMap::new(),
            proof_anchors: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::empty_devnet();
        state
            .register_settlement_claim(SettlementClaimInput {
                exit_receipt_commitment_root: sample_root("exit-receipt", 1),
                claim_commitment_root: sample_root("claim", 1),
                policy_commitment_root: sample_root("policy", 1),
                claimant_commitment_root: sample_root("claimant", 1),
                cedent_commitment_root: sample_root("cedent", 1),
                reinsurer_commitment_root: sample_root("reinsurer", 1),
                encrypted_claim_terms_root: sample_root("encrypted-terms", 1),
                claim_amount_commitment: sample_root("amount-commitment", 1),
                claim_amount_atomic: 8_500_000_000,
                claim_nullifier: sample_root("claim-nullifier", 1),
                nullifier_bucket: 17,
                receipt_slot: DEVNET_SLOT.saturating_sub(64),
                submitted_slot: DEVNET_SLOT,
            })
            .expect("valid devnet settlement claim");
        let settlement_id = state
            .settlement_claims
            .keys()
            .next()
            .expect("devnet claim inserted")
            .clone();
        state
            .commit_exit_receipt(ExitReceiptCommitmentInput {
                settlement_id: settlement_id.clone(),
                receipt_digest_root: sample_root("receipt-digest", 1),
                exit_state_root: sample_root("exit-state", 1),
                encrypted_receipt_payload_root: sample_root("encrypted-receipt", 1),
                receipt_membership_root: sample_root("receipt-membership", 1),
                receipt_nullifier: sample_root("receipt-nullifier", 1),
                privacy_redaction_root: sample_root("receipt-redaction", 1),
                committed_slot: DEVNET_SLOT + 8,
            })
            .expect("valid devnet receipt commitment");
        state
            .authorize_claim(MlDsaRouterClaimAuthorizationInput {
                settlement_id: settlement_id.clone(),
                ml_dsa_public_key_root: sample_root("ml-dsa-router-pk", 1),
                ml_dsa_signature_root: sample_root("ml-dsa-router-sig", 1),
                message_digest_root: sample_root("message-digest", 1),
                ml_dsa_challenge_root: sample_root("ml-dsa-challenge", 1),
                module_lattice_transcript_root: sample_root("module-lattice-transcript", 1),
                hint_commitment_root: sample_root("hint-commitment", 1),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                signature_bytes: 45_512,
                authorized_slot: DEVNET_SLOT + 16,
            })
            .expect("valid devnet authorization");
        state
            .anchor_proof(SettlementProofAnchorInput {
                settlement_id: settlement_id.clone(),
                proof_mode: ProofMode::AggregatedBatchProof,
                proof_commitment_root: sample_root("proof", 1),
                claim_membership_root: sample_root("claim-membership", 1),
                reserve_membership_root: sample_root("reserve-membership", 1),
                accounting_transition_root: sample_root("accounting-transition", 1),
                solvency_state_root: sample_root("solvency-state", 1),
                privacy_redaction_root: sample_root("proof-redaction", 1),
                accepted: true,
                anchored_slot: DEVNET_SLOT + 24,
            })
            .expect("valid devnet proof");
        state
            .append_accounting_entry(SettlementAccountingEntryInput {
                settlement_id: settlement_id.clone(),
                side: SettlementAccountingSide::ClaimReserveLock,
                amount_atomic: 8_500_000_000,
                account_commitment_root: sample_root("reserve-account", 1),
                memo_commitment_root: sample_root("reserve-memo", 1),
                effective_slot: DEVNET_SLOT + 24,
            })
            .expect("valid devnet reserve accounting");
        state
            .append_accounting_entry(SettlementAccountingEntryInput {
                settlement_id: settlement_id.clone(),
                side: SettlementAccountingSide::SettlementEscrow,
                amount_atomic: DEFAULT_SETTLEMENT_ESCROW_ATOMIC,
                account_commitment_root: sample_root("escrow-account", 1),
                memo_commitment_root: sample_root("escrow-memo", 1),
                effective_slot: DEVNET_SLOT + 25,
            })
            .expect("valid devnet escrow accounting");
        state
            .append_accounting_entry(SettlementAccountingEntryInput {
                settlement_id: settlement_id.clone(),
                side: SettlementAccountingSide::ReinsurerPayable,
                amount_atomic: 6_290_000_000,
                account_commitment_root: sample_root("reinsurer-payable", 1),
                memo_commitment_root: sample_root("reinsurer-memo", 1),
                effective_slot: DEVNET_SLOT + 26,
            })
            .expect("valid devnet reinsurer accounting");
        state
            .append_accounting_entry(SettlementAccountingEntryInput {
                settlement_id: settlement_id.clone(),
                side: SettlementAccountingSide::CedentPayable,
                amount_atomic: 2_210_000_000,
                account_commitment_root: sample_root("cedent-payable", 1),
                memo_commitment_root: sample_root("cedent-memo", 1),
                effective_slot: DEVNET_SLOT + 26,
            })
            .expect("valid devnet cedent accounting");
        state
            .append_accounting_entry(SettlementAccountingEntryInput {
                settlement_id: settlement_id.clone(),
                side: SettlementAccountingSide::ProtocolFee,
                amount_atomic: 10_200_000,
                account_commitment_root: sample_root("protocol-fee", 1),
                memo_commitment_root: sample_root("protocol-fee-memo", 1),
                effective_slot: DEVNET_SLOT + 27,
            })
            .expect("valid devnet fee accounting");
        state
            .post_low_fee_batch(LowFeeSettlementBatchInput {
                epoch: DEVNET_EPOCH,
                sequencer_commitment_root: sample_root("sequencer", 1),
                settlement_ids: BTreeSet::from([
                    settlement_id.clone(),
                    sample_root("settlement", 2),
                ]),
                settled_settlement_ids: BTreeSet::from([settlement_id]),
                rejected_settlement_ids: BTreeSet::new(),
                aggregation_root: sample_root("aggregation", 1),
                compression_root: sample_root("compression", 1),
                fee_sponsor_commitment_root: sample_root("fee-sponsor", 1),
                batch_fee_micro_units: 48,
                posted_slot: DEVNET_SLOT + 32,
            })
            .expect("valid devnet settlement batch");
        state
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn roots_only_snapshot(&self) -> RootsOnlyApiSnapshot {
        RootsOnlyApiSnapshot {
            protocol_version: PROTOCOL_VERSION.to_string(),
            height: self.height,
            epoch: self.epoch,
            slot: self.slot,
            roots: self.roots.clone(),
            counters: self.counters.clone(),
            solvency: self.solvency_snapshot(),
            fee_market: self.fee_market_snapshot(),
        }
    }

    pub fn solvency_snapshot(&self) -> SolvencySnapshot {
        let active_reserved_atomic = self.counters.total_reserved_atomic;
        let active_escrowed_atomic = self.counters.total_escrowed_atomic;
        let settled_claimant_payout_atomic = self.counters.total_claimant_payout_atomic;
        let solvency_buffer_atomic = self.counters.total_solvency_buffer_atomic;
        let encumbered = self
            .config
            .min_solvency_reserve_atomic
            .saturating_add(active_reserved_atomic)
            .saturating_add(active_escrowed_atomic)
            .saturating_add(solvency_buffer_atomic);
        let available_after_reserve_atomic = self
            .config
            .reinsurance_pool_atomic
            .saturating_sub(encumbered);
        SolvencySnapshot {
            reinsurance_pool_atomic: self.config.reinsurance_pool_atomic,
            min_solvency_reserve_atomic: self.config.min_solvency_reserve_atomic,
            active_reserved_atomic,
            active_escrowed_atomic,
            settled_claimant_payout_atomic,
            solvency_buffer_atomic,
            available_after_reserve_atomic,
            solvency_reserve_root: self.roots.solvency_reserve_root.clone(),
        }
    }

    pub fn fee_market_snapshot(&self) -> FeeMarketSnapshot {
        FeeMarketSnapshot {
            low_fee_batching_enabled: self.config.low_fee_batching_enabled,
            max_batch_fee_micro_units: self.config.max_batch_fee_micro_units,
            total_batch_fee_micro_units: self.counters.total_batch_fee_micro_units,
            total_protocol_fee_atomic: self.counters.total_protocol_fee_atomic,
            fee_market_root: self.roots.fee_market_root.clone(),
        }
    }

    pub fn register_settlement_claim(&mut self, input: SettlementClaimInput) -> Result<String> {
        let claim = SettlementClaim::from_input(&self.config, self.epoch, input)?;
        if self
            .settlement_claims
            .values()
            .any(|existing| existing.claim_nullifier == claim.claim_nullifier)
        {
            return Err("claim nullifier already spent in settlement runtime".to_string());
        }
        let settlement_id = claim.settlement_id.clone();
        self.counters.settlement_claims += 1;
        self.counters.spent_claim_nullifiers += 1;
        self.counters.total_claimed_atomic = self
            .counters
            .total_claimed_atomic
            .saturating_add(claim.claim_amount_atomic);
        self.counters.total_reinsurer_payable_atomic = self
            .counters
            .total_reinsurer_payable_atomic
            .saturating_add(claim.reinsurer_payable_atomic);
        self.counters.total_cedent_payable_atomic = self
            .counters
            .total_cedent_payable_atomic
            .saturating_add(claim.cedent_payable_atomic);
        self.counters.total_solvency_buffer_atomic = self
            .counters
            .total_solvency_buffer_atomic
            .saturating_add(claim.solvency_buffer_atomic);
        self.counters.total_protocol_fee_atomic = self
            .counters
            .total_protocol_fee_atomic
            .saturating_add(claim.protocol_fee_atomic);
        self.settlement_claims.insert(settlement_id.clone(), claim);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn commit_exit_receipt(&mut self, input: ExitReceiptCommitmentInput) -> Result<String> {
        let receipt = ExitReceiptCommitment::from_input(input)?;
        let claim = self
            .settlement_claims
            .get_mut(&receipt.settlement_id)
            .ok_or_else(|| "unknown settlement for receipt commitment".to_string())?;
        if receipt.committed_slot > claim.expires_slot {
            return Err("receipt commitment outside settlement window".to_string());
        }
        claim.status = SettlementStatus::ReceiptCommitted;
        let receipt_id = receipt.receipt_id.clone();
        self.counters.receipt_commitments += 1;
        self.receipt_commitments.insert(receipt_id.clone(), receipt);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn authorize_claim(&mut self, input: MlDsaRouterClaimAuthorizationInput) -> Result<String> {
        let authorization = MlDsaRouterClaimAuthorization::from_input(&self.config, input)?;
        let claim = self
            .settlement_claims
            .get_mut(&authorization.settlement_id)
            .ok_or_else(|| "unknown settlement for ml-dsa-router authorization".to_string())?;
        if authorization.authorized_slot > claim.expires_slot {
            return Err("ml-dsa-router authorization outside settlement window".to_string());
        }
        claim.status = SettlementStatus::ClaimAuthorized;
        let authorization_id = authorization.authorization_id.clone();
        self.counters.ml_dsa_router_authorizations += 1;
        self.ml_dsa_router_authorizations
            .insert(authorization_id.clone(), authorization);
        self.refresh_roots();
        Ok(authorization_id)
    }

    pub fn anchor_proof(&mut self, input: SettlementProofAnchorInput) -> Result<String> {
        let proof = SettlementProofAnchor::from_input(input)?;
        let claim = self
            .settlement_claims
            .get_mut(&proof.settlement_id)
            .ok_or_else(|| "unknown settlement for proof anchor".to_string())?;
        if proof.anchored_slot > claim.expires_slot + self.config.claim_proof_grace_slots {
            return Err("settlement proof outside grace window".to_string());
        }
        claim.status = if proof.accepted {
            SettlementStatus::ProofAnchored
        } else {
            self.counters.rejected_claims += 1;
            SettlementStatus::Rejected
        };
        let proof_id = proof.proof_id.clone();
        self.counters.proof_anchors += 1;
        self.proof_anchors.insert(proof_id.clone(), proof);
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn append_accounting_entry(
        &mut self,
        input: SettlementAccountingEntryInput,
    ) -> Result<String> {
        let entry = SettlementAccountingEntry::from_input(input)?;
        if !self.settlement_claims.contains_key(&entry.settlement_id) {
            return Err("unknown settlement for accounting entry".to_string());
        }
        self.apply_accounting_counter(&entry);
        let accounting_id = entry.accounting_id.clone();
        self.counters.accounting_entries += 1;
        self.accounting_entries.insert(accounting_id.clone(), entry);
        self.refresh_roots();
        Ok(accounting_id)
    }

    pub fn post_low_fee_batch(&mut self, input: LowFeeSettlementBatchInput) -> Result<String> {
        let batch = LowFeeSettlementBatch::from_input(&self.config, input)?;
        for settlement_id in &batch.settlement_ids {
            if let Some(claim) = self.settlement_claims.get_mut(settlement_id) {
                if batch.settled_settlement_ids.contains(settlement_id) {
                    claim.status = SettlementStatus::Settled;
                    self.counters.settled_claims += 1;
                    self.counters.total_claimant_payout_atomic = self
                        .counters
                        .total_claimant_payout_atomic
                        .saturating_add(claim.claim_amount_atomic);
                } else if batch.rejected_settlement_ids.contains(settlement_id) {
                    claim.status = SettlementStatus::Rejected;
                    self.counters.rejected_claims += 1;
                } else {
                    claim.status = SettlementStatus::Queued;
                }
            }
        }
        let batch_id = batch.batch_id.clone();
        self.counters.settlement_batches += 1;
        self.counters.total_batch_fee_micro_units = self
            .counters
            .total_batch_fee_micro_units
            .saturating_add(batch.batch_fee_micro_units);
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn expire_stale_claims(&mut self, current_slot: u64) -> u64 {
        let mut expired = 0;
        for claim in self.settlement_claims.values_mut() {
            if current_slot > claim.expires_slot
                && !matches!(
                    claim.status,
                    SettlementStatus::Settled
                        | SettlementStatus::Rejected
                        | SettlementStatus::Expired
                )
            {
                claim.status = SettlementStatus::Expired;
                expired += 1;
            }
        }
        self.counters.expired_claims = self.counters.expired_claims.saturating_add(expired);
        if expired > 0 {
            self.refresh_roots();
        }
        expired
    }

    pub fn refresh_roots(&mut self) {
        self.roots = self.compute_roots();
    }

    fn apply_accounting_counter(&mut self, entry: &SettlementAccountingEntry) {
        match entry.side {
            SettlementAccountingSide::ClaimReserveLock => {
                self.counters.reserve_locks += 1;
                self.counters.total_reserved_atomic = self
                    .counters
                    .total_reserved_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::SettlementEscrow => {
                self.counters.total_escrowed_atomic = self
                    .counters
                    .total_escrowed_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::ReinsurerPayable => {
                self.counters.total_reinsurer_payable_atomic = self
                    .counters
                    .total_reinsurer_payable_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::CedentPayable => {
                self.counters.total_cedent_payable_atomic = self
                    .counters
                    .total_cedent_payable_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::ClaimantPayout => {
                self.counters.redeemed_claims += 1;
                self.counters.total_claimant_payout_atomic = self
                    .counters
                    .total_claimant_payout_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::SolvencyBuffer => {
                self.counters.total_solvency_buffer_atomic = self
                    .counters
                    .total_solvency_buffer_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::SolvencyRelease => {
                self.counters.total_solvency_released_atomic = self
                    .counters
                    .total_solvency_released_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::Refund => {
                self.counters.total_refunded_atomic = self
                    .counters
                    .total_refunded_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::ProtocolFee => {
                self.counters.total_protocol_fee_atomic = self
                    .counters
                    .total_protocol_fee_atomic
                    .saturating_add(entry.amount_atomic);
            }
            SettlementAccountingSide::BatchFee => {}
        }
    }

    fn compute_roots(&self) -> Roots {
        let settlement_claim_root = record_root(
            "settlement-claims",
            self.settlement_claims
                .values()
                .map(SettlementClaim::roots_only_record)
                .collect(),
        );
        let receipt_commitment_root = record_root(
            "receipt-commitments",
            self.receipt_commitments
                .values()
                .map(ExitReceiptCommitment::roots_only_record)
                .collect(),
        );
        let ml_dsa_router_authorization_root = record_root(
            "ml-dsa-router-authorizations",
            self.ml_dsa_router_authorizations
                .values()
                .map(MlDsaRouterClaimAuthorization::roots_only_record)
                .collect(),
        );
        let proof_anchor_root = record_root(
            "proof-anchors",
            self.proof_anchors
                .values()
                .map(SettlementProofAnchor::roots_only_record)
                .collect(),
        );
        let accounting_entry_root = record_root(
            "accounting-entries",
            self.accounting_entries
                .values()
                .map(SettlementAccountingEntry::roots_only_record)
                .collect(),
        );
        let settlement_batch_root = record_root(
            "settlement-batches",
            self.settlement_batches
                .values()
                .map(LowFeeSettlementBatch::roots_only_record)
                .collect(),
        );
        let claim_nullifier_root = record_root(
            "claim-nullifiers",
            self.settlement_claims
                .values()
                .map(|claim| {
                    json!({
                        "settlement_id": &claim.settlement_id,
                        "claim_nullifier": &claim.claim_nullifier,
                        "nullifier_bucket": claim.nullifier_bucket,
                    })
                })
                .collect(),
        );
        let reserve_lock_root = record_root(
            "reserve-locks",
            self.accounting_entries
                .values()
                .filter(|entry| entry.side == SettlementAccountingSide::ClaimReserveLock)
                .map(SettlementAccountingEntry::roots_only_record)
                .collect(),
        );
        let solvency_reserve_root = value_root(
            "solvency-reserve",
            &json!({
                "reinsurance_pool_atomic": self.config.reinsurance_pool_atomic,
                "min_solvency_reserve_atomic": self.config.min_solvency_reserve_atomic,
                "total_reserved_atomic": self.counters.total_reserved_atomic,
                "total_escrowed_atomic": self.counters.total_escrowed_atomic,
                "total_solvency_buffer_atomic": self.counters.total_solvency_buffer_atomic,
                "total_solvency_released_atomic": self.counters.total_solvency_released_atomic,
            }),
        );
        let fee_market_root = value_root(
            "fee-market",
            &json!({
                "protocol_fee_bps": self.config.protocol_fee_bps,
                "max_batch_fee_micro_units": self.config.max_batch_fee_micro_units,
                "total_protocol_fee_atomic": self.counters.total_protocol_fee_atomic,
                "total_batch_fee_micro_units": self.counters.total_batch_fee_micro_units,
            }),
        );
        let privacy_redaction_root = record_root(
            "privacy-redactions",
            self.receipt_commitments
                .values()
                .map(|receipt| {
                    json!({
                        "receipt_id": &receipt.receipt_id,
                        "privacy_redaction_root": &receipt.privacy_redaction_root,
                    })
                })
                .chain(self.proof_anchors.values().map(|proof| {
                    json!({
                        "proof_id": &proof.proof_id,
                        "privacy_redaction_root": &proof.privacy_redaction_root,
                    })
                }))
                .collect(),
        );
        let private_accounting_root = value_root(
            "private-accounting",
            &json!({
                "accounting_entry_root": accounting_entry_root,
                "reserve_lock_root": reserve_lock_root,
                "solvency_reserve_root": solvency_reserve_root,
                "fee_market_root": fee_market_root,
                "redacted_counters": self.counters,
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "settlement_claim_root": settlement_claim_root,
                "receipt_commitment_root": receipt_commitment_root,
                "ml_dsa_router_authorization_root": ml_dsa_router_authorization_root,
                "proof_anchor_root": proof_anchor_root,
                "accounting_entry_root": accounting_entry_root,
                "settlement_batch_root": settlement_batch_root,
                "claim_nullifier_root": claim_nullifier_root,
                "reserve_lock_root": reserve_lock_root,
                "solvency_reserve_root": solvency_reserve_root,
                "fee_market_root": fee_market_root,
                "privacy_redaction_root": privacy_redaction_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&settlement_claim_root),
                HashPart::Str(&receipt_commitment_root),
                HashPart::Str(&ml_dsa_router_authorization_root),
                HashPart::Str(&proof_anchor_root),
                HashPart::Str(&accounting_entry_root),
                HashPart::Str(&settlement_batch_root),
                HashPart::Str(&claim_nullifier_root),
                HashPart::Str(&reserve_lock_root),
                HashPart::Str(&solvency_reserve_root),
                HashPart::Str(&fee_market_root),
                HashPart::Str(&privacy_redaction_root),
                HashPart::Str(&private_accounting_root),
                HashPart::Str(&public_record_root),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slot),
            ],
            32,
        );
        Roots {
            settlement_claim_root,
            receipt_commitment_root,
            ml_dsa_router_authorization_root,
            proof_anchor_root,
            accounting_entry_root,
            settlement_batch_root,
            claim_nullifier_root,
            reserve_lock_root,
            solvency_reserve_root,
            fee_market_root,
            privacy_redaction_root,
            private_accounting_root,
            public_record_root,
            state_root,
        }
    }

    fn empty_devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            slot: DEVNET_SLOT,
            counters: Counters::default(),
            roots: Roots::default(),
            settlement_claims: BTreeMap::new(),
            receipt_commitments: BTreeMap::new(),
            ml_dsa_router_authorizations: BTreeMap::new(),
            proof_anchors: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "height": state.height,
        "epoch": state.epoch,
        "slot": state.slot,
        "hash_suite": HASH_SUITE,
        "ml_dsa_router_settlement_suite": ML_DSA_ROUTER_SETTLEMENT_SUITE,
        "confidential_exit_receipt_suite": CONFIDENTIAL_EXIT_RECEIPT_SUITE,
        "claim_redemption_auth_suite": CLAIM_REDEMPTION_AUTH_SUITE,
        "reinsurance_settlement_accounting_suite": REINSURANCE_SETTLEMENT_ACCOUNTING_SUITE,
        "low_fee_settlement_batch_suite": LOW_FEE_SETTLEMENT_BATCH_SUITE,
        "solvency_reserve_suite": SOLVENCY_RESERVE_SUITE,
        "roots_only_public_record_suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "snapshots": {
            "solvency": state.solvency_snapshot().public_record(),
            "fee_market": state.fee_market_snapshot().public_record(),
        },
        "redacted_private_records": {
            "settlement_claims": state.roots.settlement_claim_root,
            "receipt_commitments": state.roots.receipt_commitment_root,
            "ml_dsa_router_authorizations": state.roots.ml_dsa_router_authorization_root,
            "proof_anchors": state.roots.proof_anchor_root,
            "accounting_entries": state.roots.accounting_entry_root,
            "settlement_batches": state.roots.settlement_batch_root,
            "claim_nullifiers": state.roots.claim_nullifier_root,
            "reserve_locks": state.roots.reserve_lock_root,
            "privacy_redactions": state.roots.privacy_redaction_root,
        },
        "roots_only_public_records": true,
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-{domain}"),
        &values,
    )
}

fn bps_amount(amount_atomic: u64, bps: u16) -> u64 {
    amount_atomic.saturating_mul(u64::from(bps)) / 10_000
}

fn require_non_empty(values: &[(&String, &str)]) -> Result<()> {
    for (value, label) in values {
        if value.is_empty() {
            return Err(format!("{label} must be non-empty"));
        }
    }
    Ok(())
}
