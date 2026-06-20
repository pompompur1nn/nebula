use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialFalconExitReceiptReinsuranceClaimRedemptionSettlementRouterAppealRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_FALCON_EXIT_RECEIPT_REINSURANCE_CLAIM_REDEMPTION_SETTLEMENT_ROUTER_APPEAL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-falcon-exit-receipt-reinsurance-claim-redemption-settlement-router-appeal-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_FALCON_EXIT_RECEIPT_REINSURANCE_CLAIM_REDEMPTION_SETTLEMENT_ROUTER_APPEAL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FALCON_ROUTER_APPEAL_SETTLEMENT_SUITE: &str =
    "falcon-1024-ntru-exit-receipt-reinsurance-claim-redemption-settlement-router-appeal-v1";
pub const CONFIDENTIAL_EXIT_RECEIPT_SUITE: &str =
    "falcon-confidential-exit-receipt-router-appeal-commitment-v1";
pub const CLAIM_REDEMPTION_AUTH_SUITE: &str =
    "falcon-1024-private-claim-redemption-router-appeal-authorization-v1";
pub const REINSURANCE_SETTLEMENT_ACCOUNTING_SUITE: &str =
    "roots-only-falcon-reinsurance-claim-redemption-router-appeal-accounting-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str =
    "low-fee-falcon-claim-redemption-router-appeal-batch-v1";
pub const SOLVENCY_RESERVE_SUITE: &str =
    "privacy-preserving-reinsurance-solvency-reserve-release-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-falcon-claim-redemption-settlement-router-appeal-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 10_208_000;
pub const DEVNET_EPOCH: u64 = 42_533;
pub const DEVNET_SLOT: u64 = 704;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_FALCON_NTRU_DIMENSION: u8 = 8;
pub const DEFAULT_FALCON_PARAMETER_SET: u8 = 5;
pub const DEFAULT_FALCON_TREE_DEPTH: u16 = 80;
pub const DEFAULT_FALCON_NONCE_BYTES: u8 = 4;
pub const DEFAULT_FALCON_SIGNATURE_BYTES_CAP: u32 = 4_627;
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
    FalconNtruLatticeAttestation,
    MerkleMembership,
    AggregatedBatchProof,
    SolvencyStateTransition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    Intake,
    EvidenceAnchored,
    Routed,
    ReviewerQuorumMet,
    Quarantined,
    Upheld,
    Denied,
    Remanded,
    Settled,
}

impl AppealStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intake => "intake",
            Self::EvidenceAnchored => "evidence_anchored",
            Self::Routed => "routed",
            Self::ReviewerQuorumMet => "reviewer_quorum_met",
            Self::Quarantined => "quarantined",
            Self::Upheld => "upheld",
            Self::Denied => "denied",
            Self::Remanded => "remanded",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealDecision {
    UpholdClaimant,
    UpholdRouter,
    RemandForReinsuranceReview,
    QuarantineForFraudProof,
}

impl AppealDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpholdClaimant => "uphold_claimant",
            Self::UpholdRouter => "uphold_router",
            Self::RemandForReinsuranceReview => "remand_for_reinsurance_review",
            Self::QuarantineForFraudProof => "quarantine_for_fraud_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealRouteKind {
    FastPqReview,
    ReinsurancePanel,
    ContractArbiter,
    FraudQuarantine,
}

impl AppealRouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastPqReview => "fast_pq_review",
            Self::ReinsurancePanel => "reinsurance_panel",
            Self::ContractArbiter => "contract_arbiter",
            Self::FraudQuarantine => "fraud_quarantine",
        }
    }
}

impl ProofMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalconNtruLatticeAttestation => "falcon_router_hash_attestation",
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
    pub falcon_router_appeal_settlement_suite: String,
    pub confidential_exit_receipt_suite: String,
    pub claim_redemption_auth_suite: String,
    pub reinsurance_settlement_accounting_suite: String,
    pub low_fee_settlement_batch_suite: String,
    pub solvency_reserve_suite: String,
    pub roots_only_public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub falcon_ntru_dimension: u8,
    pub falcon_parameter_set: u8,
    pub falcon_tree_depth: u16,
    pub falcon_nonce_bytes: u8,
    pub falcon_signature_bytes_cap: u32,
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
    pub falcon_authorization_required: bool,
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
            falcon_router_appeal_settlement_suite: FALCON_ROUTER_APPEAL_SETTLEMENT_SUITE
                .to_string(),
            confidential_exit_receipt_suite: CONFIDENTIAL_EXIT_RECEIPT_SUITE.to_string(),
            claim_redemption_auth_suite: CLAIM_REDEMPTION_AUTH_SUITE.to_string(),
            reinsurance_settlement_accounting_suite: REINSURANCE_SETTLEMENT_ACCOUNTING_SUITE
                .to_string(),
            low_fee_settlement_batch_suite: LOW_FEE_SETTLEMENT_BATCH_SUITE.to_string(),
            solvency_reserve_suite: SOLVENCY_RESERVE_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            falcon_ntru_dimension: DEFAULT_FALCON_NTRU_DIMENSION,
            falcon_parameter_set: DEFAULT_FALCON_PARAMETER_SET,
            falcon_tree_depth: DEFAULT_FALCON_TREE_DEPTH,
            falcon_nonce_bytes: DEFAULT_FALCON_NONCE_BYTES,
            falcon_signature_bytes_cap: DEFAULT_FALCON_SIGNATURE_BYTES_CAP,
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
            falcon_authorization_required: true,
            confidential_exit_receipts_required: true,
            claim_nullifiers_required: true,
            solvency_reserve_required: true,
            low_fee_batching_enabled: true,
            roots_only_public_records_required: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below falcon-router settlement minimum".to_string());
        }
        if self.falcon_ntru_dimension < 4
            || self.falcon_parameter_set == 0
            || self.falcon_tree_depth < 30
            || self.falcon_nonce_bytes == 0
        {
            return Err("invalid falcon-router settlement parameter schedule".to_string());
        }
        if self.falcon_signature_bytes_cap < 2_400 {
            return Err(
                "falcon-router signature cap below expected ntru-lattice floor".to_string(),
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
        if !self.falcon_authorization_required
            || !self.confidential_exit_receipts_required
            || !self.claim_nullifiers_required
            || !self.solvency_reserve_required
            || !self.roots_only_public_records_required
        {
            return Err(
                "falcon-router, confidentiality, nullifier, reserve, and roots-only gates are mandatory"
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
                "falcon_router_appeal_settlement": self.falcon_router_appeal_settlement_suite,
                "confidential_exit_receipt": self.confidential_exit_receipt_suite,
                "claim_redemption_auth": self.claim_redemption_auth_suite,
                "reinsurance_settlement_accounting": self.reinsurance_settlement_accounting_suite,
                "low_fee_settlement_batch": self.low_fee_settlement_batch_suite,
                "solvency_reserve": self.solvency_reserve_suite,
                "roots_only_public_record": self.roots_only_public_record_suite,
            },
            "security": {
                "min_pq_security_bits": self.min_pq_security_bits,
                "falcon_ntru_dimension": self.falcon_ntru_dimension,
                "falcon_parameter_set": self.falcon_parameter_set,
                "falcon_tree_depth": self.falcon_tree_depth,
                "falcon_nonce_bytes": self.falcon_nonce_bytes,
                "falcon_signature_bytes_cap": self.falcon_signature_bytes_cap,
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
    pub falcon_router_authorizations: u64,
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
    pub appeal_intakes: u64,
    pub reviewer_quorums: u64,
    pub appeal_evidence_packets: u64,
    pub appeal_routes: u64,
    pub quarantined_appeals: u64,
    pub low_fee_appeal_credits: u64,
    pub appeal_outcomes: u64,
    pub upheld_appeals: u64,
    pub denied_appeals: u64,
    pub remanded_appeals: u64,
    pub total_appeal_bond_atomic: u64,
    pub total_appeal_credit_micro_units: u64,
    pub total_appeal_refund_atomic: u64,
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
    pub falcon_router_authorization_root: String,
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
    pub appeal_intake_root: String,
    pub reviewer_quorum_root: String,
    pub appeal_evidence_root: String,
    pub appeal_route_root: String,
    pub appeal_quarantine_root: String,
    pub low_fee_appeal_credit_root: String,
    pub appeal_outcome_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = record_root("empty", Vec::new());
        Self {
            settlement_claim_root: empty.clone(),
            receipt_commitment_root: empty.clone(),
            falcon_router_authorization_root: empty.clone(),
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
            appeal_intake_root: empty.clone(),
            reviewer_quorum_root: empty.clone(),
            appeal_evidence_root: empty.clone(),
            appeal_route_root: empty.clone(),
            appeal_quarantine_root: empty.clone(),
            low_fee_appeal_credit_root: empty.clone(),
            appeal_outcome_root: empty.clone(),
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
pub struct FalconRouterClaimAuthorizationInput {
    pub settlement_id: String,
    pub falcon_public_key_root: String,
    pub falcon_signature_root: String,
    pub message_digest_root: String,
    pub falcon_challenge_root: String,
    pub ntru_lattice_transcript_root: String,
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
pub struct FalconRouterClaimAuthorization {
    pub authorization_id: String,
    pub settlement_id: String,
    pub falcon_public_key_root: String,
    pub falcon_signature_root: String,
    pub message_digest_root: String,
    pub falcon_challenge_root: String,
    pub ntru_lattice_transcript_root: String,
    pub hint_commitment_root: String,
    pub pq_security_bits: u16,
    pub signature_bytes: u32,
    pub ntru_dimension: u8,
    pub parameter_set: u8,
    pub tree_depth: u16,
    pub nonce_bytes: u8,
    pub authorized_slot: u64,
}

impl FalconRouterClaimAuthorization {
    pub fn from_input(config: &Config, input: FalconRouterClaimAuthorizationInput) -> Result<Self> {
        require_non_empty(&[
            (&input.settlement_id, "settlement id"),
            (
                &input.falcon_public_key_root,
                "falcon-router public key root",
            ),
            (&input.falcon_signature_root, "falcon-router signature root"),
            (&input.message_digest_root, "message digest root"),
            (&input.falcon_challenge_root, "falcon challenge root"),
            (
                &input.ntru_lattice_transcript_root,
                "NTRU lattice transcript root",
            ),
            (&input.hint_commitment_root, "hint commitment root"),
        ])?;
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("falcon-router authorization below configured pq security".to_string());
        }
        if input.signature_bytes == 0 || input.signature_bytes > config.falcon_signature_bytes_cap {
            return Err("falcon-router authorization signature size outside policy".to_string());
        }
        let authorization_id = deterministic_id(
            "falcon-router-claim-authorization",
            &[
                HashPart::Str(&input.settlement_id),
                HashPart::Str(&input.falcon_public_key_root),
                HashPart::Str(&input.falcon_signature_root),
                HashPart::Str(&input.message_digest_root),
                HashPart::Str(&input.falcon_challenge_root),
                HashPart::U64(input.authorized_slot),
            ],
        );
        Ok(Self {
            authorization_id,
            settlement_id: input.settlement_id,
            falcon_public_key_root: input.falcon_public_key_root,
            falcon_signature_root: input.falcon_signature_root,
            message_digest_root: input.message_digest_root,
            falcon_challenge_root: input.falcon_challenge_root,
            ntru_lattice_transcript_root: input.ntru_lattice_transcript_root,
            hint_commitment_root: input.hint_commitment_root,
            pq_security_bits: input.pq_security_bits,
            signature_bytes: input.signature_bytes,
            ntru_dimension: config.falcon_ntru_dimension,
            parameter_set: config.falcon_parameter_set,
            tree_depth: config.falcon_tree_depth,
            nonce_bytes: config.falcon_nonce_bytes,
            authorized_slot: input.authorized_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "settlement_id": self.settlement_id,
            "falcon_public_key_root": self.falcon_public_key_root,
            "falcon_signature_root": self.falcon_signature_root,
            "message_digest_root": self.message_digest_root,
            "falcon_challenge_root": self.falcon_challenge_root,
            "ntru_lattice_transcript_root": self.ntru_lattice_transcript_root,
            "hint_commitment_root": self.hint_commitment_root,
            "pq_security_bits": self.pq_security_bits,
            "signature_bytes": self.signature_bytes,
            "ntru_dimension": self.ntru_dimension,
            "parameter_set": self.parameter_set,
            "tree_depth": self.tree_depth,
            "nonce_bytes": self.nonce_bytes,
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
pub struct AppealIntakeInput {
    pub settlement_id: String,
    pub prior_outcome_root: String,
    pub appellant_commitment_root: String,
    pub appeal_reason_commitment_root: String,
    pub contract_call_root: String,
    pub appeal_bond_atomic: u64,
    pub appeal_nullifier: String,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealReviewerQuorumInput {
    pub appeal_id: String,
    pub reviewer_set_root: String,
    pub vote_commitment_root: String,
    pub quorum_certificate_root: String,
    pub decision: AppealDecision,
    pub reviewers: u16,
    pub threshold: u16,
    pub decided_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealEvidenceInput {
    pub appeal_id: String,
    pub reinsurance_claim_evidence_root: String,
    pub exit_receipt_replay_root: String,
    pub reserve_transition_root: String,
    pub contract_trace_root: String,
    pub falcon_attestation_root: String,
    pub pq_transcript_root: String,
    pub privacy_redaction_root: String,
    pub anchored_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealRouteInput {
    pub appeal_id: String,
    pub route_kind: AppealRouteKind,
    pub router_commitment_root: String,
    pub destination_commitment_root: String,
    pub execution_budget_root: String,
    pub quarantine_reason_root: String,
    pub low_fee_lane: bool,
    pub routed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAppealCreditInput {
    pub appeal_id: String,
    pub sponsor_commitment_root: String,
    pub credit_commitment_root: String,
    pub fee_market_snapshot_root: String,
    pub credit_micro_units: u64,
    pub credited_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealSettlementOutcomeInput {
    pub appeal_id: String,
    pub decision: AppealDecision,
    pub settlement_transition_root: String,
    pub redemption_adjustment_root: String,
    pub claimant_payout_root: String,
    pub reserve_release_root: String,
    pub refund_atomic: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealCase {
    pub appeal_id: String,
    pub settlement_id: String,
    pub prior_outcome_root: String,
    pub appellant_commitment_root: String,
    pub appeal_reason_commitment_root: String,
    pub contract_call_root: String,
    pub appeal_bond_atomic: u64,
    pub appeal_nullifier: String,
    pub submitted_slot: u64,
    pub status: AppealStatus,
}

impl AppealCase {
    pub fn from_input(config: &Config, input: AppealIntakeInput) -> Result<Self> {
        require_non_empty(&[
            (&input.settlement_id, "settlement id"),
            (&input.prior_outcome_root, "prior outcome root"),
            (
                &input.appellant_commitment_root,
                "appellant commitment root",
            ),
            (
                &input.appeal_reason_commitment_root,
                "appeal reason commitment root",
            ),
            (&input.contract_call_root, "contract call root"),
            (&input.appeal_nullifier, "appeal nullifier"),
        ])?;
        if input.appeal_bond_atomic == 0
            || input.appeal_bond_atomic > config.settlement_escrow_atomic
        {
            return Err("appeal bond outside low-fee escrow policy".to_string());
        }
        let appeal_id = deterministic_id(
            "appeal-intake",
            &[
                HashPart::Str(&input.settlement_id),
                HashPart::Str(&input.prior_outcome_root),
                HashPart::Str(&input.appellant_commitment_root),
                HashPart::Str(&input.appeal_nullifier),
                HashPart::U64(input.submitted_slot),
            ],
        );
        Ok(Self {
            appeal_id,
            settlement_id: input.settlement_id,
            prior_outcome_root: input.prior_outcome_root,
            appellant_commitment_root: input.appellant_commitment_root,
            appeal_reason_commitment_root: input.appeal_reason_commitment_root,
            contract_call_root: input.contract_call_root,
            appeal_bond_atomic: input.appeal_bond_atomic,
            appeal_nullifier: input.appeal_nullifier,
            submitted_slot: input.submitted_slot,
            status: AppealStatus::Intake,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "appeal_id": self.appeal_id,
            "settlement_id": self.settlement_id,
            "prior_outcome_root": self.prior_outcome_root,
            "appellant_commitment_root": self.appellant_commitment_root,
            "appeal_reason_commitment_root": self.appeal_reason_commitment_root,
            "contract_call_root": self.contract_call_root,
            "appeal_bond_commitment_root": value_root("appeal-bond", &json!({
                "appeal_id": self.appeal_id,
                "appeal_bond_atomic": self.appeal_bond_atomic,
            })),
            "appeal_nullifier": self.appeal_nullifier,
            "submitted_slot": self.submitted_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealReviewerQuorum {
    pub quorum_id: String,
    pub appeal_id: String,
    pub reviewer_set_root: String,
    pub vote_commitment_root: String,
    pub quorum_certificate_root: String,
    pub decision: AppealDecision,
    pub reviewers: u16,
    pub threshold: u16,
    pub decided_slot: u64,
}

impl AppealReviewerQuorum {
    pub fn from_input(input: AppealReviewerQuorumInput) -> Result<Self> {
        require_non_empty(&[
            (&input.appeal_id, "appeal id"),
            (&input.reviewer_set_root, "reviewer set root"),
            (&input.vote_commitment_root, "vote commitment root"),
            (&input.quorum_certificate_root, "quorum certificate root"),
        ])?;
        if input.threshold == 0 || input.reviewers < input.threshold {
            return Err("appeal reviewer quorum threshold not met".to_string());
        }
        let quorum_id = deterministic_id(
            "appeal-reviewer-quorum",
            &[
                HashPart::Str(&input.appeal_id),
                HashPart::Str(&input.reviewer_set_root),
                HashPart::Str(input.decision.as_str()),
                HashPart::U64(input.decided_slot),
            ],
        );
        Ok(Self {
            quorum_id,
            appeal_id: input.appeal_id,
            reviewer_set_root: input.reviewer_set_root,
            vote_commitment_root: input.vote_commitment_root,
            quorum_certificate_root: input.quorum_certificate_root,
            decision: input.decision,
            reviewers: input.reviewers,
            threshold: input.threshold,
            decided_slot: input.decided_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "appeal_id": self.appeal_id,
            "reviewer_set_root": self.reviewer_set_root,
            "vote_commitment_root": self.vote_commitment_root,
            "quorum_certificate_root": self.quorum_certificate_root,
            "decision": self.decision.as_str(),
            "reviewers": self.reviewers,
            "threshold": self.threshold,
            "decided_slot": self.decided_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealEvidence {
    pub evidence_id: String,
    pub appeal_id: String,
    pub reinsurance_claim_evidence_root: String,
    pub exit_receipt_replay_root: String,
    pub reserve_transition_root: String,
    pub contract_trace_root: String,
    pub falcon_attestation_root: String,
    pub pq_transcript_root: String,
    pub privacy_redaction_root: String,
    pub anchored_slot: u64,
}

impl AppealEvidence {
    pub fn from_input(input: AppealEvidenceInput) -> Result<Self> {
        require_non_empty(&[
            (&input.appeal_id, "appeal id"),
            (
                &input.reinsurance_claim_evidence_root,
                "reinsurance claim evidence root",
            ),
            (&input.exit_receipt_replay_root, "exit receipt replay root"),
            (&input.reserve_transition_root, "reserve transition root"),
            (&input.contract_trace_root, "contract trace root"),
            (&input.falcon_attestation_root, "falcon attestation root"),
            (&input.pq_transcript_root, "pq transcript root"),
            (&input.privacy_redaction_root, "privacy redaction root"),
        ])?;
        let evidence_id = deterministic_id(
            "appeal-evidence",
            &[
                HashPart::Str(&input.appeal_id),
                HashPart::Str(&input.reinsurance_claim_evidence_root),
                HashPart::Str(&input.falcon_attestation_root),
                HashPart::U64(input.anchored_slot),
            ],
        );
        Ok(Self {
            evidence_id,
            appeal_id: input.appeal_id,
            reinsurance_claim_evidence_root: input.reinsurance_claim_evidence_root,
            exit_receipt_replay_root: input.exit_receipt_replay_root,
            reserve_transition_root: input.reserve_transition_root,
            contract_trace_root: input.contract_trace_root,
            falcon_attestation_root: input.falcon_attestation_root,
            pq_transcript_root: input.pq_transcript_root,
            privacy_redaction_root: input.privacy_redaction_root,
            anchored_slot: input.anchored_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "appeal_id": self.appeal_id,
            "reinsurance_claim_evidence_root": self.reinsurance_claim_evidence_root,
            "exit_receipt_replay_root": self.exit_receipt_replay_root,
            "reserve_transition_root": self.reserve_transition_root,
            "contract_trace_root": self.contract_trace_root,
            "falcon_attestation_root": self.falcon_attestation_root,
            "pq_transcript_root": self.pq_transcript_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "anchored_slot": self.anchored_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealRoute {
    pub route_id: String,
    pub appeal_id: String,
    pub route_kind: AppealRouteKind,
    pub router_commitment_root: String,
    pub destination_commitment_root: String,
    pub execution_budget_root: String,
    pub quarantine_reason_root: String,
    pub low_fee_lane: bool,
    pub routed_slot: u64,
}

impl AppealRoute {
    pub fn from_input(input: AppealRouteInput) -> Result<Self> {
        require_non_empty(&[
            (&input.appeal_id, "appeal id"),
            (&input.router_commitment_root, "router commitment root"),
            (
                &input.destination_commitment_root,
                "destination commitment root",
            ),
            (&input.execution_budget_root, "execution budget root"),
            (&input.quarantine_reason_root, "quarantine reason root"),
        ])?;
        let route_id = deterministic_id(
            "appeal-route",
            &[
                HashPart::Str(&input.appeal_id),
                HashPart::Str(input.route_kind.as_str()),
                HashPart::Str(&input.router_commitment_root),
                HashPart::U64(input.routed_slot),
            ],
        );
        Ok(Self {
            route_id,
            appeal_id: input.appeal_id,
            route_kind: input.route_kind,
            router_commitment_root: input.router_commitment_root,
            destination_commitment_root: input.destination_commitment_root,
            execution_budget_root: input.execution_budget_root,
            quarantine_reason_root: input.quarantine_reason_root,
            low_fee_lane: input.low_fee_lane,
            routed_slot: input.routed_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "appeal_id": self.appeal_id,
            "route_kind": self.route_kind.as_str(),
            "router_commitment_root": self.router_commitment_root,
            "destination_commitment_root": self.destination_commitment_root,
            "execution_budget_root": self.execution_budget_root,
            "quarantine_reason_root": self.quarantine_reason_root,
            "low_fee_lane": self.low_fee_lane,
            "routed_slot": self.routed_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAppealCredit {
    pub credit_id: String,
    pub appeal_id: String,
    pub sponsor_commitment_root: String,
    pub credit_commitment_root: String,
    pub fee_market_snapshot_root: String,
    pub credit_micro_units: u64,
    pub credited_slot: u64,
}

impl LowFeeAppealCredit {
    pub fn from_input(config: &Config, input: LowFeeAppealCreditInput) -> Result<Self> {
        require_non_empty(&[
            (&input.appeal_id, "appeal id"),
            (&input.sponsor_commitment_root, "sponsor commitment root"),
            (&input.credit_commitment_root, "credit commitment root"),
            (&input.fee_market_snapshot_root, "fee market snapshot root"),
        ])?;
        if input.credit_micro_units == 0
            || input.credit_micro_units > config.max_batch_fee_micro_units
        {
            return Err("appeal credit outside low-fee policy".to_string());
        }
        let credit_id = deterministic_id(
            "low-fee-appeal-credit",
            &[
                HashPart::Str(&input.appeal_id),
                HashPart::Str(&input.sponsor_commitment_root),
                HashPart::Str(&input.credit_commitment_root),
                HashPart::U64(input.credited_slot),
            ],
        );
        Ok(Self {
            credit_id,
            appeal_id: input.appeal_id,
            sponsor_commitment_root: input.sponsor_commitment_root,
            credit_commitment_root: input.credit_commitment_root,
            fee_market_snapshot_root: input.fee_market_snapshot_root,
            credit_micro_units: input.credit_micro_units,
            credited_slot: input.credited_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "appeal_id": self.appeal_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "credit_commitment_root": self.credit_commitment_root,
            "fee_market_snapshot_root": self.fee_market_snapshot_root,
            "credit_micro_units": self.credit_micro_units,
            "credited_slot": self.credited_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealSettlementOutcome {
    pub outcome_id: String,
    pub appeal_id: String,
    pub decision: AppealDecision,
    pub settlement_transition_root: String,
    pub redemption_adjustment_root: String,
    pub claimant_payout_root: String,
    pub reserve_release_root: String,
    pub refund_atomic: u64,
    pub settled_slot: u64,
}

impl AppealSettlementOutcome {
    pub fn from_input(input: AppealSettlementOutcomeInput) -> Result<Self> {
        require_non_empty(&[
            (&input.appeal_id, "appeal id"),
            (
                &input.settlement_transition_root,
                "settlement transition root",
            ),
            (
                &input.redemption_adjustment_root,
                "redemption adjustment root",
            ),
            (&input.claimant_payout_root, "claimant payout root"),
            (&input.reserve_release_root, "reserve release root"),
        ])?;
        let outcome_id = deterministic_id(
            "appeal-settlement-outcome",
            &[
                HashPart::Str(&input.appeal_id),
                HashPart::Str(input.decision.as_str()),
                HashPart::Str(&input.settlement_transition_root),
                HashPart::U64(input.settled_slot),
            ],
        );
        Ok(Self {
            outcome_id,
            appeal_id: input.appeal_id,
            decision: input.decision,
            settlement_transition_root: input.settlement_transition_root,
            redemption_adjustment_root: input.redemption_adjustment_root,
            claimant_payout_root: input.claimant_payout_root,
            reserve_release_root: input.reserve_release_root,
            refund_atomic: input.refund_atomic,
            settled_slot: input.settled_slot,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "outcome_id": self.outcome_id,
            "appeal_id": self.appeal_id,
            "decision": self.decision.as_str(),
            "settlement_transition_root": self.settlement_transition_root,
            "redemption_adjustment_root": self.redemption_adjustment_root,
            "claimant_payout_root": self.claimant_payout_root,
            "reserve_release_root": self.reserve_release_root,
            "refund_commitment_root": value_root("appeal-refund", &json!({
                "appeal_id": self.appeal_id,
                "refund_atomic": self.refund_atomic,
            })),
            "settled_slot": self.settled_slot,
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
    pub falcon_router_authorizations: BTreeMap<String, FalconRouterClaimAuthorization>,
    pub proof_anchors: BTreeMap<String, SettlementProofAnchor>,
    pub accounting_entries: BTreeMap<String, SettlementAccountingEntry>,
    pub settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub appeal_cases: BTreeMap<String, AppealCase>,
    pub appeal_reviewer_quorums: BTreeMap<String, AppealReviewerQuorum>,
    pub appeal_evidence: BTreeMap<String, AppealEvidence>,
    pub appeal_routes: BTreeMap<String, AppealRoute>,
    pub low_fee_appeal_credits: BTreeMap<String, LowFeeAppealCredit>,
    pub appeal_outcomes: BTreeMap<String, AppealSettlementOutcome>,
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
            falcon_router_authorizations: BTreeMap::new(),
            proof_anchors: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            appeal_cases: BTreeMap::new(),
            appeal_reviewer_quorums: BTreeMap::new(),
            appeal_evidence: BTreeMap::new(),
            appeal_routes: BTreeMap::new(),
            low_fee_appeal_credits: BTreeMap::new(),
            appeal_outcomes: BTreeMap::new(),
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
            .authorize_claim(FalconRouterClaimAuthorizationInput {
                settlement_id: settlement_id.clone(),
                falcon_public_key_root: sample_root("falcon-router-pk", 1),
                falcon_signature_root: sample_root("falcon-router-sig", 1),
                message_digest_root: sample_root("message-digest", 1),
                falcon_challenge_root: sample_root("falcon-challenge", 1),
                ntru_lattice_transcript_root: sample_root("ntru-lattice-transcript", 1),
                hint_commitment_root: sample_root("hint-commitment", 1),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                signature_bytes: 4_512,
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
        let appeal_id = state
            .intake_appeal(AppealIntakeInput {
                settlement_id: state
                    .settlement_claims
                    .keys()
                    .next()
                    .expect("devnet settlement exists")
                    .clone(),
                prior_outcome_root: sample_root("prior-outcome", 1),
                appellant_commitment_root: sample_root("appellant", 1),
                appeal_reason_commitment_root: sample_root("appeal-reason", 1),
                contract_call_root: sample_root("appeal-contract-call", 1),
                appeal_bond_atomic: 120_000_000,
                appeal_nullifier: sample_root("appeal-nullifier", 1),
                submitted_slot: DEVNET_SLOT + 40,
            })
            .expect("valid devnet appeal intake");
        state
            .anchor_appeal_evidence(AppealEvidenceInput {
                appeal_id: appeal_id.clone(),
                reinsurance_claim_evidence_root: sample_root("appeal-reinsurance-evidence", 1),
                exit_receipt_replay_root: sample_root("appeal-receipt-replay", 1),
                reserve_transition_root: sample_root("appeal-reserve-transition", 1),
                contract_trace_root: sample_root("appeal-contract-trace", 1),
                falcon_attestation_root: sample_root("appeal-falcon-attestation", 1),
                pq_transcript_root: sample_root("appeal-pq-transcript", 1),
                privacy_redaction_root: sample_root("appeal-evidence-redaction", 1),
                anchored_slot: DEVNET_SLOT + 44,
            })
            .expect("valid devnet appeal evidence");
        state
            .route_appeal(AppealRouteInput {
                appeal_id: appeal_id.clone(),
                route_kind: AppealRouteKind::ReinsurancePanel,
                router_commitment_root: sample_root("appeal-router", 1),
                destination_commitment_root: sample_root("appeal-panel", 1),
                execution_budget_root: sample_root("appeal-budget", 1),
                quarantine_reason_root: sample_root("appeal-no-quarantine", 1),
                low_fee_lane: true,
                routed_slot: DEVNET_SLOT + 45,
            })
            .expect("valid devnet appeal route");
        state
            .grant_low_fee_appeal_credit(LowFeeAppealCreditInput {
                appeal_id: appeal_id.clone(),
                sponsor_commitment_root: sample_root("appeal-credit-sponsor", 1),
                credit_commitment_root: sample_root("appeal-credit", 1),
                fee_market_snapshot_root: sample_root("appeal-fee-market", 1),
                credit_micro_units: 24,
                credited_slot: DEVNET_SLOT + 46,
            })
            .expect("valid devnet appeal credit");
        state
            .record_reviewer_quorum(AppealReviewerQuorumInput {
                appeal_id: appeal_id.clone(),
                reviewer_set_root: sample_root("appeal-reviewers", 1),
                vote_commitment_root: sample_root("appeal-votes", 1),
                quorum_certificate_root: sample_root("appeal-quorum-cert", 1),
                decision: AppealDecision::RemandForReinsuranceReview,
                reviewers: 7,
                threshold: 5,
                decided_slot: DEVNET_SLOT + 48,
            })
            .expect("valid devnet appeal quorum");
        state
            .settle_appeal(AppealSettlementOutcomeInput {
                appeal_id,
                decision: AppealDecision::RemandForReinsuranceReview,
                settlement_transition_root: sample_root("appeal-settlement-transition", 1),
                redemption_adjustment_root: sample_root("appeal-redemption-adjustment", 1),
                claimant_payout_root: sample_root("appeal-claimant-payout", 1),
                reserve_release_root: sample_root("appeal-reserve-release", 1),
                refund_atomic: 60_000_000,
                settled_slot: DEVNET_SLOT + 56,
            })
            .expect("valid devnet appeal outcome");
        state
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
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

    pub fn authorize_claim(
        &mut self,
        input: FalconRouterClaimAuthorizationInput,
    ) -> Result<String> {
        let authorization = FalconRouterClaimAuthorization::from_input(&self.config, input)?;
        let claim = self
            .settlement_claims
            .get_mut(&authorization.settlement_id)
            .ok_or_else(|| "unknown settlement for falcon-router authorization".to_string())?;
        if authorization.authorized_slot > claim.expires_slot {
            return Err("falcon-router authorization outside settlement window".to_string());
        }
        claim.status = SettlementStatus::ClaimAuthorized;
        let authorization_id = authorization.authorization_id.clone();
        self.counters.falcon_router_authorizations += 1;
        self.falcon_router_authorizations
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

    pub fn intake_appeal(&mut self, input: AppealIntakeInput) -> Result<String> {
        if !self.settlement_claims.contains_key(&input.settlement_id) {
            return Err("unknown settlement for appeal intake".to_string());
        }
        let appeal = AppealCase::from_input(&self.config, input)?;
        if self
            .appeal_cases
            .values()
            .any(|existing| existing.appeal_nullifier == appeal.appeal_nullifier)
        {
            return Err("appeal nullifier already spent".to_string());
        }
        let appeal_id = appeal.appeal_id.clone();
        self.counters.appeal_intakes += 1;
        self.counters.total_appeal_bond_atomic = self
            .counters
            .total_appeal_bond_atomic
            .saturating_add(appeal.appeal_bond_atomic);
        self.appeal_cases.insert(appeal_id.clone(), appeal);
        self.refresh_roots();
        Ok(appeal_id)
    }

    pub fn anchor_appeal_evidence(&mut self, input: AppealEvidenceInput) -> Result<String> {
        let evidence = AppealEvidence::from_input(input)?;
        let appeal = self
            .appeal_cases
            .get_mut(&evidence.appeal_id)
            .ok_or_else(|| "unknown appeal for evidence anchor".to_string())?;
        appeal.status = AppealStatus::EvidenceAnchored;
        let evidence_id = evidence.evidence_id.clone();
        self.counters.appeal_evidence_packets += 1;
        self.appeal_evidence.insert(evidence_id.clone(), evidence);
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn route_appeal(&mut self, input: AppealRouteInput) -> Result<String> {
        let route = AppealRoute::from_input(input)?;
        let appeal = self
            .appeal_cases
            .get_mut(&route.appeal_id)
            .ok_or_else(|| "unknown appeal for routing".to_string())?;
        appeal.status = if route.route_kind == AppealRouteKind::FraudQuarantine {
            self.counters.quarantined_appeals += 1;
            AppealStatus::Quarantined
        } else {
            AppealStatus::Routed
        };
        let route_id = route.route_id.clone();
        self.counters.appeal_routes += 1;
        self.appeal_routes.insert(route_id.clone(), route);
        self.refresh_roots();
        Ok(route_id)
    }

    pub fn quarantine_appeal(
        &mut self,
        appeal_id: &str,
        quarantine_reason_root: String,
        routed_slot: u64,
    ) -> Result<String> {
        self.route_appeal(AppealRouteInput {
            appeal_id: appeal_id.to_string(),
            route_kind: AppealRouteKind::FraudQuarantine,
            router_commitment_root: sample_root("fraud-quarantine-router", routed_slot),
            destination_commitment_root: sample_root("fraud-quarantine-vault", routed_slot),
            execution_budget_root: sample_root("fraud-quarantine-budget", routed_slot),
            quarantine_reason_root,
            low_fee_lane: false,
            routed_slot,
        })
    }

    pub fn grant_low_fee_appeal_credit(
        &mut self,
        input: LowFeeAppealCreditInput,
    ) -> Result<String> {
        let credit = LowFeeAppealCredit::from_input(&self.config, input)?;
        if !self.appeal_cases.contains_key(&credit.appeal_id) {
            return Err("unknown appeal for low-fee credit".to_string());
        }
        let credit_id = credit.credit_id.clone();
        self.counters.low_fee_appeal_credits += 1;
        self.counters.total_appeal_credit_micro_units = self
            .counters
            .total_appeal_credit_micro_units
            .saturating_add(credit.credit_micro_units);
        self.low_fee_appeal_credits
            .insert(credit_id.clone(), credit);
        self.refresh_roots();
        Ok(credit_id)
    }

    pub fn record_reviewer_quorum(&mut self, input: AppealReviewerQuorumInput) -> Result<String> {
        let quorum = AppealReviewerQuorum::from_input(input)?;
        let appeal = self
            .appeal_cases
            .get_mut(&quorum.appeal_id)
            .ok_or_else(|| "unknown appeal for reviewer quorum".to_string())?;
        appeal.status = match quorum.decision {
            AppealDecision::QuarantineForFraudProof => {
                self.counters.quarantined_appeals += 1;
                AppealStatus::Quarantined
            }
            _ => AppealStatus::ReviewerQuorumMet,
        };
        let quorum_id = quorum.quorum_id.clone();
        self.counters.reviewer_quorums += 1;
        self.appeal_reviewer_quorums
            .insert(quorum_id.clone(), quorum);
        self.refresh_roots();
        Ok(quorum_id)
    }

    pub fn settle_appeal(&mut self, input: AppealSettlementOutcomeInput) -> Result<String> {
        let outcome = AppealSettlementOutcome::from_input(input)?;
        let appeal = self
            .appeal_cases
            .get_mut(&outcome.appeal_id)
            .ok_or_else(|| "unknown appeal for settlement outcome".to_string())?;
        appeal.status = match outcome.decision {
            AppealDecision::UpholdClaimant => {
                self.counters.upheld_appeals += 1;
                AppealStatus::Upheld
            }
            AppealDecision::UpholdRouter => {
                self.counters.denied_appeals += 1;
                AppealStatus::Denied
            }
            AppealDecision::RemandForReinsuranceReview => {
                self.counters.remanded_appeals += 1;
                AppealStatus::Remanded
            }
            AppealDecision::QuarantineForFraudProof => {
                self.counters.quarantined_appeals += 1;
                AppealStatus::Quarantined
            }
        };
        self.counters.appeal_outcomes += 1;
        self.counters.total_appeal_refund_atomic = self
            .counters
            .total_appeal_refund_atomic
            .saturating_add(outcome.refund_atomic);
        let outcome_id = outcome.outcome_id.clone();
        self.appeal_outcomes.insert(outcome_id.clone(), outcome);
        self.refresh_roots();
        Ok(outcome_id)
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
        let falcon_router_authorization_root = record_root(
            "falcon-router-authorizations",
            self.falcon_router_authorizations
                .values()
                .map(FalconRouterClaimAuthorization::roots_only_record)
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
        let appeal_intake_root = record_root(
            "appeal-intakes",
            self.appeal_cases
                .values()
                .map(AppealCase::roots_only_record)
                .collect(),
        );
        let reviewer_quorum_root = record_root(
            "appeal-reviewer-quorums",
            self.appeal_reviewer_quorums
                .values()
                .map(AppealReviewerQuorum::roots_only_record)
                .collect(),
        );
        let appeal_evidence_root = record_root(
            "appeal-evidence",
            self.appeal_evidence
                .values()
                .map(AppealEvidence::roots_only_record)
                .collect(),
        );
        let appeal_route_root = record_root(
            "appeal-routes",
            self.appeal_routes
                .values()
                .map(AppealRoute::roots_only_record)
                .collect(),
        );
        let appeal_quarantine_root = record_root(
            "appeal-quarantines",
            self.appeal_routes
                .values()
                .filter(|route| route.route_kind == AppealRouteKind::FraudQuarantine)
                .map(AppealRoute::roots_only_record)
                .collect(),
        );
        let low_fee_appeal_credit_root = record_root(
            "low-fee-appeal-credits",
            self.low_fee_appeal_credits
                .values()
                .map(LowFeeAppealCredit::roots_only_record)
                .collect(),
        );
        let appeal_outcome_root = record_root(
            "appeal-outcomes",
            self.appeal_outcomes
                .values()
                .map(AppealSettlementOutcome::roots_only_record)
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
                .chain(self.appeal_evidence.values().map(|evidence| {
                    json!({
                        "evidence_id": &evidence.evidence_id,
                        "privacy_redaction_root": &evidence.privacy_redaction_root,
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
                "falcon_router_authorization_root": falcon_router_authorization_root,
                "proof_anchor_root": proof_anchor_root,
                "accounting_entry_root": accounting_entry_root,
                "settlement_batch_root": settlement_batch_root,
                "appeal_intake_root": appeal_intake_root,
                "reviewer_quorum_root": reviewer_quorum_root,
                "appeal_evidence_root": appeal_evidence_root,
                "appeal_route_root": appeal_route_root,
                "appeal_quarantine_root": appeal_quarantine_root,
                "low_fee_appeal_credit_root": low_fee_appeal_credit_root,
                "appeal_outcome_root": appeal_outcome_root,
                "claim_nullifier_root": claim_nullifier_root,
                "reserve_lock_root": reserve_lock_root,
                "solvency_reserve_root": solvency_reserve_root,
                "fee_market_root": fee_market_root,
                "privacy_redaction_root": privacy_redaction_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-Falcon-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&settlement_claim_root),
                HashPart::Str(&receipt_commitment_root),
                HashPart::Str(&falcon_router_authorization_root),
                HashPart::Str(&proof_anchor_root),
                HashPart::Str(&accounting_entry_root),
                HashPart::Str(&settlement_batch_root),
                HashPart::Str(&appeal_intake_root),
                HashPart::Str(&reviewer_quorum_root),
                HashPart::Str(&appeal_evidence_root),
                HashPart::Str(&appeal_route_root),
                HashPart::Str(&appeal_quarantine_root),
                HashPart::Str(&low_fee_appeal_credit_root),
                HashPart::Str(&appeal_outcome_root),
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
            falcon_router_authorization_root,
            proof_anchor_root,
            accounting_entry_root,
            settlement_batch_root,
            appeal_intake_root,
            reviewer_quorum_root,
            appeal_evidence_root,
            appeal_route_root,
            appeal_quarantine_root,
            low_fee_appeal_credit_root,
            appeal_outcome_root,
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
            falcon_router_authorizations: BTreeMap::new(),
            proof_anchors: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            appeal_cases: BTreeMap::new(),
            appeal_reviewer_quorums: BTreeMap::new(),
            appeal_evidence: BTreeMap::new(),
            appeal_routes: BTreeMap::new(),
            low_fee_appeal_credits: BTreeMap::new(),
            appeal_outcomes: BTreeMap::new(),
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
        "FALCON_ROUTER_APPEAL_SETTLEMENT_SUITE": FALCON_ROUTER_APPEAL_SETTLEMENT_SUITE,
        "confidential_exit_receipt_suite": CONFIDENTIAL_EXIT_RECEIPT_SUITE,
        "claim_redemption_auth_suite": CLAIM_REDEMPTION_AUTH_SUITE,
        "reinsurance_settlement_accounting_suite": REINSURANCE_SETTLEMENT_ACCOUNTING_SUITE,
        "low_fee_settlement_batch_suite": LOW_FEE_SETTLEMENT_BATCH_SUITE,
        "solvency_reserve_suite": SOLVENCY_RESERVE_SUITE,
        "roots_only_public_record_suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "redacted_private_records": {
            "settlement_claims": state.roots.settlement_claim_root,
            "receipt_commitments": state.roots.receipt_commitment_root,
            "falcon_router_authorizations": state.roots.falcon_router_authorization_root,
            "proof_anchors": state.roots.proof_anchor_root,
            "accounting_entries": state.roots.accounting_entry_root,
            "settlement_batches": state.roots.settlement_batch_root,
            "appeal_intakes": state.roots.appeal_intake_root,
            "reviewer_quorums": state.roots.reviewer_quorum_root,
            "appeal_evidence": state.roots.appeal_evidence_root,
            "appeal_routes": state.roots.appeal_route_root,
            "appeal_quarantines": state.roots.appeal_quarantine_root,
            "low_fee_appeal_credits": state.roots.low_fee_appeal_credit_root,
            "appeal_outcomes": state.roots.appeal_outcome_root,
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-Falcon-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-Falcon-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-Falcon-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-Falcon-ROUTER-EXIT-RECEIPT-REINSURANCE-CLAIM-REDEMPTION-SETTLEMENT-{domain}"),
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
