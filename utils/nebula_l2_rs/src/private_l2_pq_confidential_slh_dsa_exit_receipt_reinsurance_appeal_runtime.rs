use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSlhDsaExitReceiptReinsuranceAppealRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_EXIT_RECEIPT_REINSURANCE_APPEAL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-slh-dsa-exit-receipt-reinsurance-appeal-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_EXIT_RECEIPT_REINSURANCE_APPEAL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SLH_DSA_EXIT_RECEIPT_REINSURANCE_APPEAL_SUITE: &str =
    "slh-dsa-exit-receipt-reinsurance-appeal-v1";
pub const PQ_RECEIPT_COMMITMENT_SUITE: &str =
    "slh-dsa-pq-confidential-sealed-exit-receipt-claim-v1";
pub const REINSURANCE_APPEAL_WINDOW_SUITE: &str =
    "slh-dsa-exit-receipt-reinsurance-appeal-window-v1";
pub const REINSURANCE_BOND_SUITE: &str = "slh-dsa-confidential-reinsurance-bond-escrow-v1";
pub const LOW_FEE_REINSURANCE_APPEAL_BATCH_SUITE: &str =
    "low-fee-slh-dsa-exit-receipt-reinsurance-appeal-batch-v1";
pub const PRIVATE_RECORD_API_SUITE: &str =
    "privacy-preserving-slh-dsa-reinsurance-appeal-public-record-state-root-v1";
pub const DEVNET_HEIGHT: u64 = 8_704_000;
pub const DEVNET_EPOCH: u64 = 36_240;
pub const DEVNET_SLOT: u64 = 432;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SLH_DSA_TREE_HEIGHT: u8 = 22;
pub const DEFAULT_SLH_DSA_LAYER_COUNT: u8 = 4;
pub const DEFAULT_SLH_DSA_FORS_TREES: u16 = 35;
pub const DEFAULT_SLH_DSA_SIGNATURE_BYTES_CAP: u16 = 49_856;
pub const DEFAULT_NULLIFIER_BUCKETS: u32 = 196_608;
pub const DEFAULT_APPEAL_WINDOW_SLOTS: u64 = 3_120;
pub const DEFAULT_EVIDENCE_GRACE_SLOTS: u64 = 640;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 1_440;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 48;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 30_000_000_000;
pub const DEFAULT_APPEAL_BOND_ATOMIC: u64 = 2_100_000_000;
pub const DEFAULT_SUCCESS_REWARD_BPS: u16 = 1_500;
pub const DEFAULT_REINSURANCE_RESTORATION_BPS: u16 = 8_500;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 1_024;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 95;
pub const DEFAULT_EPOCH_BUCKET_TARGET_EXITS: u64 = 40_960;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitNullifierStatus {
    Pending,
    ReceiptCommitted,
    AppealWindowOpen,
    Appealed,
    Restored,
    Upheld,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Committed,
    Windowed,
    Appealed,
    Superseded,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealKind {
    DuplicateExitNullifier,
    InvalidSlhDsaHashAttestation,
    SlhDsaAppealDigestMismatch,
    ReceiptCommitmentMismatch,
    ReinsuranceSetOmission,
    ReinsuranceStateRootInconsistency,
    AppealWindowViolation,
}

impl AppealKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateExitNullifier => "duplicate_exit_nullifier",
            Self::InvalidSlhDsaHashAttestation => "invalid_slh_dsa_hash_attestation",
            Self::SlhDsaAppealDigestMismatch => "slh_dsa_appeal_digest_mismatch",
            Self::ReceiptCommitmentMismatch => "receipt_commitment_mismatch",
            Self::ReinsuranceSetOmission => "reinsurance_set_omission",
            Self::ReinsuranceStateRootInconsistency => "reinsurance_state_root_inconsistency",
            Self::AppealWindowViolation => "appeal_window_violation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    Submitted,
    EvidenceAnchored,
    Accepted,
    Rejected,
    Batched,
    Settled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Collecting,
    Posted,
    Settled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub slh_dsa_exit_receipt_reinsurance_appeal_suite: String,
    pub pq_receipt_commitment_suite: String,
    pub appeal_window_suite: String,
    pub appeal_bond_suite: String,
    pub low_fee_appeal_batch_suite: String,
    pub private_record_api_suite: String,
    pub min_pq_security_bits: u16,
    pub slh_dsa_tree_height: u8,
    pub slh_dsa_layer_count: u8,
    pub slh_dsa_fors_trees: u16,
    pub slh_dsa_signature_bytes_cap: u16,
    pub nullifier_buckets: u32,
    pub appeal_window_slots: u64,
    pub evidence_grace_slots: u64,
    pub settlement_delay_slots: u64,
    pub receipt_retention_epochs: u64,
    pub exit_bond_atomic: u64,
    pub appeal_bond_atomic: u64,
    pub success_reward_bps: u16,
    pub reinsurance_restoration_bps: u16,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_exits: u64,
    pub pq_receipt_commitments_required: bool,
    pub slh_dsa_hash_attestations_required: bool,
    pub appeal_windows_required: bool,
    pub appeal_bonds_required: bool,
    pub low_fee_batching_enabled: bool,
    pub privacy_preserving_public_records_required: bool,
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
            slh_dsa_exit_receipt_reinsurance_appeal_suite:
                SLH_DSA_EXIT_RECEIPT_REINSURANCE_APPEAL_SUITE.to_string(),
            pq_receipt_commitment_suite: PQ_RECEIPT_COMMITMENT_SUITE.to_string(),
            appeal_window_suite: REINSURANCE_APPEAL_WINDOW_SUITE.to_string(),
            appeal_bond_suite: REINSURANCE_BOND_SUITE.to_string(),
            low_fee_appeal_batch_suite: LOW_FEE_REINSURANCE_APPEAL_BATCH_SUITE.to_string(),
            private_record_api_suite: PRIVATE_RECORD_API_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            slh_dsa_tree_height: DEFAULT_SLH_DSA_TREE_HEIGHT,
            slh_dsa_layer_count: DEFAULT_SLH_DSA_LAYER_COUNT,
            slh_dsa_fors_trees: DEFAULT_SLH_DSA_FORS_TREES,
            slh_dsa_signature_bytes_cap: DEFAULT_SLH_DSA_SIGNATURE_BYTES_CAP,
            nullifier_buckets: DEFAULT_NULLIFIER_BUCKETS,
            appeal_window_slots: DEFAULT_APPEAL_WINDOW_SLOTS,
            evidence_grace_slots: DEFAULT_EVIDENCE_GRACE_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            appeal_bond_atomic: DEFAULT_APPEAL_BOND_ATOMIC,
            success_reward_bps: DEFAULT_SUCCESS_REWARD_BPS,
            reinsurance_restoration_bps: DEFAULT_REINSURANCE_RESTORATION_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_exits: DEFAULT_EPOCH_BUCKET_TARGET_EXITS,
            pq_receipt_commitments_required: true,
            slh_dsa_hash_attestations_required: true,
            appeal_windows_required: true,
            appeal_bonds_required: true,
            low_fee_batching_enabled: true,
            privacy_preserving_public_records_required: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below slh-dsa appeal minimum".to_string());
        }
        if self.slh_dsa_tree_height < 12 || self.slh_dsa_layer_count == 0 {
            return Err("invalid slh-dsa hypertree parameter schedule".to_string());
        }
        if self.slh_dsa_fors_trees == 0 || self.slh_dsa_signature_bytes_cap < 16_000 {
            return Err("invalid slh-dsa fors or signature policy".to_string());
        }
        if self.nullifier_buckets == 0 || self.epoch_bucket_target_exits == 0 {
            return Err("nullifier buckets and epoch target exits must be positive".to_string());
        }
        if self.appeal_window_slots == 0
            || self.evidence_grace_slots == 0
            || self.settlement_delay_slots == 0
        {
            return Err("slh-dsa appeal windows must be positive".to_string());
        }
        if self.evidence_grace_slots > self.appeal_window_slots {
            return Err("evidence grace cannot exceed appeal window".to_string());
        }
        if self.exit_bond_atomic == 0 || self.appeal_bond_atomic == 0 {
            return Err("slh-dsa appeal bonds must be positive".to_string());
        }
        if self.appeal_bond_atomic >= self.exit_bond_atomic {
            return Err("appeal bond must be smaller than exit bond".to_string());
        }
        if u32::from(self.success_reward_bps) + u32::from(self.reinsurance_restoration_bps)
            != 10_000
        {
            return Err("slh-dsa appeal restoration basis points must sum to 10000".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
            || self.max_batch_fee_micro_units == 0
        {
            return Err("invalid low-fee slh-dsa appeal batching policy".to_string());
        }
        if !self.pq_receipt_commitments_required
            || !self.slh_dsa_hash_attestations_required
            || !self.appeal_windows_required
            || !self.appeal_bonds_required
            || !self.privacy_preserving_public_records_required
        {
            return Err(
                "slh-dsa privacy, receipt, window, and bond gates are mandatory".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub exit_nullifier_entries: u64,
    pub pq_receipt_commitments: u64,
    pub appeal_windows: u64,
    pub slh_dsa_appeals: u64,
    pub appeal_evidence: u64,
    pub low_fee_appeal_batches: u64,
    pub pq_witness_bundles: u64,
    pub sealed_exit_receipt_claims: u64,
    pub appeal_nullifiers: u64,
    pub pending_nullifiers: u64,
    pub appealed_nullifiers: u64,
    pub restored_nullifiers: u64,
    pub upheld_nullifiers: u64,
    pub finalized_nullifiers: u64,
    pub total_exit_bond_atomic: u64,
    pub total_appeal_bond_atomic: u64,
    pub total_reward_atomic: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_batched_appeals: u64,
}

impl Counters {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub exit_nullifier_entry_root: String,
    pub pq_receipt_commitment_root: String,
    pub appeal_window_root: String,
    pub slh_dsa_appeal_root: String,
    pub appeal_evidence_root: String,
    pub low_fee_appeal_batch_root: String,
    pub pq_witness_bundle_root: String,
    pub sealed_exit_receipt_claim_root: String,
    pub appeal_nullifier_root: String,
    pub privacy_redaction_root: String,
    pub private_accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitNullifierEntryInput {
    pub account_commitment: String,
    pub exit_nullifier: String,
    pub slh_dsa_public_root: String,
    pub nullifier_bucket_root: String,
    pub encrypted_destination_root: String,
    pub nullifier_bucket: u32,
    pub epoch: u64,
    pub requested_slot: u64,
    pub exit_bond_atomic: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitmentInput {
    pub exit_entry_id: String,
    pub receipt_commitment_root: String,
    pub sealed_claim_root: String,
    pub slh_dsa_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_nullifier: String,
    pub privacy_redaction_root: String,
    pub observed_state_root: String,
    pub committed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealWindowInput {
    pub exit_entry_id: String,
    pub receipt_id: String,
    pub nullifier_bucket: u32,
    pub nullifier_set_root: String,
    pub pq_receipt_set_root: String,
    pub state_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlhDsaAppealInput {
    pub window_id: String,
    pub appellant_commitment: String,
    pub appeal_kind: AppealKind,
    pub slh_dsa_layer_index: u8,
    pub fors_tree_index: u64,
    pub appealed_nullifier_commitment: String,
    pub appeal_nullifier: String,
    pub evidence_commitment_root: String,
    pub appeal_bond_atomic: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealEvidenceInput {
    pub appeal_id: String,
    pub hash_based_attestation_root: String,
    pub appeal_digest_root: String,
    pub signature_transcript_root: String,
    pub pq_witness_bundle_root: String,
    pub nullifier_membership_witness_root: String,
    pub sealed_receipt_claim_opening_root: String,
    pub state_transition_witness_root: String,
    pub privacy_redaction_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAppealBatchInput {
    pub sequencer_commitment: String,
    pub appeal_ids: BTreeSet<String>,
    pub aggregation_root: String,
    pub fee_sponsor_commitment: String,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitNullifierEntry {
    pub exit_entry_id: String,
    pub account_commitment: String,
    pub exit_nullifier: String,
    pub slh_dsa_public_root: String,
    pub nullifier_bucket_root: String,
    pub encrypted_destination_root: String,
    pub nullifier_bucket: u32,
    pub epoch: u64,
    pub requested_slot: u64,
    pub appeal_open_slot: u64,
    pub appeal_close_slot: u64,
    pub finality_slot: u64,
    pub exit_bond_atomic: u64,
    pub reward_locked_atomic: u64,
    pub status: ExitNullifierStatus,
}

impl ExitNullifierEntry {
    pub fn from_input(config: &Config, input: ExitNullifierEntryInput) -> Result<Self> {
        require_non_empty(&[
            (&input.account_commitment, "account commitment"),
            (&input.exit_nullifier, "exit nullifier"),
            (&input.slh_dsa_public_root, "slh-dsa public root"),
            (&input.nullifier_bucket_root, "nullifier bucket root"),
            (
                &input.encrypted_destination_root,
                "encrypted destination root",
            ),
        ])?;
        if input.nullifier_bucket >= config.nullifier_buckets {
            return Err("nullifier bucket exceeds configured bucket count".to_string());
        }
        if input.exit_bond_atomic < config.appeal_bond_atomic
            || input.exit_bond_atomic > config.exit_bond_atomic
        {
            return Err("exit bond amount outside slh-dsa appeal policy".to_string());
        }
        let exit_entry_id = deterministic_id(
            "exit-nullifier-entry",
            &[
                HashPart::Str(&input.account_commitment),
                HashPart::Str(&input.exit_nullifier),
                HashPart::Str(&input.slh_dsa_public_root),
                HashPart::U64(u64::from(input.nullifier_bucket)),
                HashPart::U64(input.epoch),
                HashPart::U64(input.requested_slot),
            ],
        );
        let appeal_open_slot = input.requested_slot;
        let appeal_close_slot = appeal_open_slot + config.appeal_window_slots;
        Ok(Self {
            exit_entry_id,
            account_commitment: input.account_commitment,
            exit_nullifier: input.exit_nullifier,
            slh_dsa_public_root: input.slh_dsa_public_root,
            nullifier_bucket_root: input.nullifier_bucket_root,
            encrypted_destination_root: input.encrypted_destination_root,
            nullifier_bucket: input.nullifier_bucket,
            epoch: input.epoch,
            requested_slot: input.requested_slot,
            appeal_open_slot,
            appeal_close_slot,
            finality_slot: appeal_close_slot + config.settlement_delay_slots,
            exit_bond_atomic: input.exit_bond_atomic,
            reward_locked_atomic: 0,
            status: ExitNullifierStatus::Pending,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitment {
    pub receipt_id: String,
    pub exit_entry_id: String,
    pub receipt_commitment_root: String,
    pub sealed_claim_root: String,
    pub slh_dsa_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_nullifier: String,
    pub privacy_redaction_root: String,
    pub observed_state_root: String,
    pub receipt_state_root: String,
    pub committed_slot: u64,
    pub retained_until_epoch: u64,
    pub pq_security_bits: u16,
    pub status: ReceiptStatus,
}

impl PqReceiptCommitment {
    pub fn from_input(
        config: &Config,
        epoch: u64,
        input: PqReceiptCommitmentInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.exit_entry_id, "exit entry id"),
            (&input.receipt_commitment_root, "receipt commitment root"),
            (&input.sealed_claim_root, "sealed exit receipt claim root"),
            (
                &input.slh_dsa_signature_commitment_root,
                "slh-dsa signature commitment root",
            ),
            (
                &input.encrypted_receipt_payload_root,
                "encrypted receipt payload root",
            ),
            (&input.receipt_nullifier, "receipt nullifier"),
            (&input.privacy_redaction_root, "privacy redaction root"),
            (&input.observed_state_root, "observed state root"),
        ])?;
        let receipt_id = deterministic_id(
            "pq-receipt-commitment",
            &[
                HashPart::Str(&input.exit_entry_id),
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::Str(&input.sealed_claim_root),
                HashPart::Str(&input.slh_dsa_signature_commitment_root),
                HashPart::Str(&input.receipt_nullifier),
                HashPart::U64(input.committed_slot),
            ],
        );
        let receipt_state_root = value_root(
            "pq-receipt-state",
            &json!({
                "receipt_id": receipt_id,
                "receipt_commitment_root": input.receipt_commitment_root,
                "sealed_claim_root": input.sealed_claim_root,
                "slh_dsa_signature_commitment_root": input.slh_dsa_signature_commitment_root,
                "encrypted_receipt_payload_root": input.encrypted_receipt_payload_root,
                "privacy_redaction_root": input.privacy_redaction_root,
                "observed_state_root": input.observed_state_root,
            }),
        );
        Ok(Self {
            receipt_id,
            exit_entry_id: input.exit_entry_id,
            receipt_commitment_root: input.receipt_commitment_root,
            sealed_claim_root: input.sealed_claim_root,
            slh_dsa_signature_commitment_root: input.slh_dsa_signature_commitment_root,
            encrypted_receipt_payload_root: input.encrypted_receipt_payload_root,
            receipt_nullifier: input.receipt_nullifier,
            privacy_redaction_root: input.privacy_redaction_root,
            observed_state_root: input.observed_state_root,
            receipt_state_root,
            committed_slot: input.committed_slot,
            retained_until_epoch: epoch + config.receipt_retention_epochs,
            pq_security_bits: config.min_pq_security_bits,
            status: ReceiptStatus::Committed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealWindow {
    pub window_id: String,
    pub exit_entry_id: String,
    pub receipt_id: String,
    pub nullifier_bucket: u32,
    pub nullifier_set_root: String,
    pub pq_receipt_set_root: String,
    pub state_root: String,
    pub window_open_slot: u64,
    pub window_close_slot: u64,
    pub evidence_deadline_slot: u64,
    pub settlement_slot: u64,
    pub status: ExitNullifierStatus,
}

impl AppealWindow {
    pub fn from_input(config: &Config, input: AppealWindowInput) -> Result<Self> {
        require_non_empty(&[
            (&input.exit_entry_id, "exit entry id"),
            (&input.receipt_id, "receipt id"),
            (&input.nullifier_set_root, "nullifier set root"),
            (&input.pq_receipt_set_root, "pq receipt set root"),
            (&input.state_root, "state root"),
        ])?;
        if input.nullifier_bucket >= config.nullifier_buckets {
            return Err("nullifier bucket exceeds configured bucket count".to_string());
        }
        let window_id = deterministic_id(
            "appeal-window",
            &[
                HashPart::Str(&input.exit_entry_id),
                HashPart::Str(&input.receipt_id),
                HashPart::U64(u64::from(input.nullifier_bucket)),
                HashPart::Str(&input.nullifier_set_root),
                HashPart::Str(&input.pq_receipt_set_root),
            ],
        );
        let window_close_slot = input.opened_slot + config.appeal_window_slots;
        Ok(Self {
            window_id,
            exit_entry_id: input.exit_entry_id,
            receipt_id: input.receipt_id,
            nullifier_bucket: input.nullifier_bucket,
            nullifier_set_root: input.nullifier_set_root,
            pq_receipt_set_root: input.pq_receipt_set_root,
            state_root: input.state_root,
            window_open_slot: input.opened_slot,
            window_close_slot,
            evidence_deadline_slot: window_close_slot + config.evidence_grace_slots,
            settlement_slot: window_close_slot + config.settlement_delay_slots,
            status: ExitNullifierStatus::AppealWindowOpen,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlhDsaAppeal {
    pub appeal_id: String,
    pub window_id: String,
    pub exit_entry_id: String,
    pub receipt_id: String,
    pub appellant_commitment: String,
    pub appeal_kind: AppealKind,
    pub slh_dsa_layer_index: u8,
    pub fors_tree_index: u64,
    pub appealed_nullifier_commitment: String,
    pub appeal_nullifier: String,
    pub evidence_commitment_root: String,
    pub appeal_bond_atomic: u64,
    pub reward_atomic: u64,
    pub opened_slot: u64,
    pub batch_id: Option<String>,
    pub status: AppealStatus,
}

impl SlhDsaAppeal {
    pub fn from_input(
        config: &Config,
        windows: &BTreeMap<String, AppealWindow>,
        input: SlhDsaAppealInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.window_id, "window id"),
            (&input.appellant_commitment, "appellant commitment"),
            (
                &input.appealed_nullifier_commitment,
                "appealed nullifier commitment",
            ),
            (&input.appeal_nullifier, "appeal nullifier"),
            (&input.evidence_commitment_root, "evidence commitment root"),
        ])?;
        if input.slh_dsa_layer_index >= config.slh_dsa_layer_count {
            return Err("slh-dsa layer exceeds configured layer count".to_string());
        }
        if input.fors_tree_index >= u64::from(config.slh_dsa_fors_trees) {
            return Err("slh-dsa fors tree exceeds configured tree count".to_string());
        }
        if input.appeal_bond_atomic < config.appeal_bond_atomic {
            return Err("appeal bond below configured minimum".to_string());
        }
        let window = windows
            .get(&input.window_id)
            .ok_or_else(|| "unknown slh-dsa appeal window".to_string())?;
        if input.opened_slot < window.window_open_slot
            || input.opened_slot > window.window_close_slot
        {
            return Err("slh-dsa appeal opened outside appeal window".to_string());
        }
        let appeal_id = deterministic_id(
            "slh-dsa-appeal",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.appellant_commitment),
                HashPart::Str(input.appeal_kind.as_str()),
                HashPart::U64(u64::from(input.slh_dsa_layer_index)),
                HashPart::U64(input.fors_tree_index),
                HashPart::Str(&input.appealed_nullifier_commitment),
                HashPart::Str(&input.appeal_nullifier),
                HashPart::U64(input.opened_slot),
            ],
        );
        let reward_atomic =
            input.appeal_bond_atomic * u64::from(config.success_reward_bps) / 10_000;
        Ok(Self {
            appeal_id,
            window_id: input.window_id,
            exit_entry_id: window.exit_entry_id.clone(),
            receipt_id: window.receipt_id.clone(),
            appellant_commitment: input.appellant_commitment,
            appeal_kind: input.appeal_kind,
            slh_dsa_layer_index: input.slh_dsa_layer_index,
            fors_tree_index: input.fors_tree_index,
            appealed_nullifier_commitment: input.appealed_nullifier_commitment,
            appeal_nullifier: input.appeal_nullifier,
            evidence_commitment_root: input.evidence_commitment_root,
            appeal_bond_atomic: input.appeal_bond_atomic,
            reward_atomic,
            opened_slot: input.opened_slot,
            batch_id: None,
            status: AppealStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppealEvidence {
    pub evidence_id: String,
    pub appeal_id: String,
    pub hash_based_attestation_root: String,
    pub appeal_digest_root: String,
    pub signature_transcript_root: String,
    pub pq_witness_bundle_root: String,
    pub nullifier_membership_witness_root: String,
    pub sealed_receipt_claim_opening_root: String,
    pub state_transition_witness_root: String,
    pub privacy_redaction_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
    pub evidence_state_root: String,
}

impl AppealEvidence {
    pub fn from_input(
        windows: &BTreeMap<String, AppealWindow>,
        appeals: &BTreeMap<String, SlhDsaAppeal>,
        input: AppealEvidenceInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.appeal_id, "appeal id"),
            (
                &input.hash_based_attestation_root,
                "hash-based appeal attestation root",
            ),
            (&input.appeal_digest_root, "appeal digest root"),
            (
                &input.signature_transcript_root,
                "signature transcript root",
            ),
            (&input.pq_witness_bundle_root, "pq witness bundle root"),
            (
                &input.nullifier_membership_witness_root,
                "nullifier membership witness root",
            ),
            (
                &input.sealed_receipt_claim_opening_root,
                "sealed receipt claim opening root",
            ),
            (
                &input.state_transition_witness_root,
                "state transition witness root",
            ),
            (&input.privacy_redaction_root, "privacy redaction root"),
        ])?;
        let appeal = appeals
            .get(&input.appeal_id)
            .ok_or_else(|| "unknown slh-dsa appeal".to_string())?;
        let window = windows
            .get(&appeal.window_id)
            .ok_or_else(|| "slh-dsa appeal lost window reference".to_string())?;
        if input.anchored_slot > window.evidence_deadline_slot {
            return Err("slh-dsa appeal evidence anchored after deadline".to_string());
        }
        let evidence_id = deterministic_id(
            "appeal-evidence",
            &[
                HashPart::Str(&input.appeal_id),
                HashPart::Str(&input.hash_based_attestation_root),
                HashPart::Str(&input.appeal_digest_root),
                HashPart::Str(&input.pq_witness_bundle_root),
                HashPart::Str(&input.sealed_receipt_claim_opening_root),
                HashPart::U64(input.anchored_slot),
            ],
        );
        let evidence_state_root = value_root(
            "appeal-evidence-state",
            &json!({
                "evidence_id": evidence_id,
                "appeal_id": input.appeal_id,
                "hash_based_attestation_root": input.hash_based_attestation_root,
                "appeal_digest_root": input.appeal_digest_root,
                "signature_transcript_root": input.signature_transcript_root,
                "pq_witness_bundle_root": input.pq_witness_bundle_root,
                "nullifier_membership_witness_root": input.nullifier_membership_witness_root,
                "sealed_receipt_claim_opening_root": input.sealed_receipt_claim_opening_root,
                "state_transition_witness_root": input.state_transition_witness_root,
                "privacy_redaction_root": input.privacy_redaction_root,
                "accepted": input.accepted,
            }),
        );
        Ok(Self {
            evidence_id,
            appeal_id: input.appeal_id,
            hash_based_attestation_root: input.hash_based_attestation_root,
            appeal_digest_root: input.appeal_digest_root,
            signature_transcript_root: input.signature_transcript_root,
            pq_witness_bundle_root: input.pq_witness_bundle_root,
            nullifier_membership_witness_root: input.nullifier_membership_witness_root,
            sealed_receipt_claim_opening_root: input.sealed_receipt_claim_opening_root,
            state_transition_witness_root: input.state_transition_witness_root,
            privacy_redaction_root: input.privacy_redaction_root,
            accepted: input.accepted,
            anchored_slot: input.anchored_slot,
            evidence_state_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAppealBatch {
    pub batch_id: String,
    pub sequencer_commitment: String,
    pub appeal_ids: BTreeSet<String>,
    pub aggregation_root: String,
    pub fee_sponsor_commitment: String,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
    pub appeal_count: u16,
    pub status: BatchStatus,
}

impl LowFeeAppealBatch {
    pub fn from_input(
        config: &Config,
        appeals: &BTreeMap<String, SlhDsaAppeal>,
        input: LowFeeAppealBatchInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.sequencer_commitment, "sequencer commitment"),
            (&input.aggregation_root, "aggregation root"),
            (&input.fee_sponsor_commitment, "fee sponsor commitment"),
        ])?;
        let appeal_count = input.appeal_ids.len();
        if appeal_count < usize::from(config.min_batch_size)
            || appeal_count > usize::from(config.low_fee_batch_limit)
        {
            return Err("slh-dsa appeal batch size outside configured policy".to_string());
        }
        if input.batch_fee_micro_units > config.max_batch_fee_micro_units {
            return Err("slh-dsa appeal batch fee exceeds low-fee cap".to_string());
        }
        for appeal_id in &input.appeal_ids {
            let appeal = appeals
                .get(appeal_id)
                .ok_or_else(|| "unknown appeal in low-fee batch".to_string())?;
            if !matches!(appeal.status, AppealStatus::Accepted) {
                return Err("only accepted appeals can enter low-fee batch".to_string());
            }
        }
        let batch_id = deterministic_id(
            "low-fee-appeal-batch",
            &[
                HashPart::Str(&input.sequencer_commitment),
                HashPart::Str(&input.aggregation_root),
                HashPart::Str(&input.fee_sponsor_commitment),
                HashPart::U64(appeal_count as u64),
                HashPart::U64(input.posted_slot),
            ],
        );
        Ok(Self {
            batch_id,
            sequencer_commitment: input.sequencer_commitment,
            appeal_ids: input.appeal_ids,
            aggregation_root: input.aggregation_root,
            fee_sponsor_commitment: input.fee_sponsor_commitment,
            batch_fee_micro_units: input.batch_fee_micro_units,
            posted_slot: input.posted_slot,
            appeal_count: appeal_count as u16,
            status: BatchStatus::Posted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
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
    pub exit_nullifier_entries: BTreeMap<String, ExitNullifierEntry>,
    pub pq_receipt_commitments: BTreeMap<String, PqReceiptCommitment>,
    pub appeal_windows: BTreeMap<String, AppealWindow>,
    pub slh_dsa_appeals: BTreeMap<String, SlhDsaAppeal>,
    pub appeal_evidence: BTreeMap<String, AppealEvidence>,
    pub low_fee_appeal_batches: BTreeMap<String, LowFeeAppealBatch>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::empty_devnet();
        state.seed_devnet();
        state
    }

    pub fn with_config(config: Config, height: u64, epoch: u64, slot: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            slot,
            counters: Counters::default(),
            roots: Roots::default(),
            exit_nullifier_entries: BTreeMap::new(),
            pq_receipt_commitments: BTreeMap::new(),
            appeal_windows: BTreeMap::new(),
            slh_dsa_appeals: BTreeMap::new(),
            appeal_evidence: BTreeMap::new(),
            low_fee_appeal_batches: BTreeMap::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn register_exit_nullifier_entry(
        &mut self,
        input: ExitNullifierEntryInput,
    ) -> Result<String> {
        let entry = ExitNullifierEntry::from_input(&self.config, input)?;
        if self
            .exit_nullifier_entries
            .contains_key(&entry.exit_entry_id)
        {
            return Err("slh-dsa exit nullifier entry already exists".to_string());
        }
        let entry_id = entry.exit_entry_id.clone();
        self.exit_nullifier_entries.insert(entry_id.clone(), entry);
        self.refresh();
        Ok(entry_id)
    }

    pub fn commit_pq_receipt(&mut self, input: PqReceiptCommitmentInput) -> Result<String> {
        let receipt = PqReceiptCommitment::from_input(&self.config, self.epoch, input)?;
        if self
            .pq_receipt_commitments
            .contains_key(&receipt.receipt_id)
        {
            return Err("slh-dsa pq receipt commitment already exists".to_string());
        }
        let entry = self
            .exit_nullifier_entries
            .get_mut(&receipt.exit_entry_id)
            .ok_or_else(|| "unknown exit nullifier entry for pq receipt".to_string())?;
        entry.status = ExitNullifierStatus::ReceiptCommitted;
        let receipt_id = receipt.receipt_id.clone();
        self.pq_receipt_commitments
            .insert(receipt_id.clone(), receipt);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn open_appeal_window(&mut self, input: AppealWindowInput) -> Result<String> {
        let window = AppealWindow::from_input(&self.config, input)?;
        if self.appeal_windows.contains_key(&window.window_id) {
            return Err("slh-dsa appeal window already exists".to_string());
        }
        let entry = self
            .exit_nullifier_entries
            .get_mut(&window.exit_entry_id)
            .ok_or_else(|| "unknown exit nullifier entry for appeal window".to_string())?;
        let receipt = self
            .pq_receipt_commitments
            .get_mut(&window.receipt_id)
            .ok_or_else(|| "unknown pq receipt for appeal window".to_string())?;
        if receipt.exit_entry_id != window.exit_entry_id {
            return Err("pq receipt does not belong to exit nullifier entry".to_string());
        }
        if entry.nullifier_bucket != window.nullifier_bucket {
            return Err("appeal window bucket does not match exit entry".to_string());
        }
        entry.status = ExitNullifierStatus::AppealWindowOpen;
        receipt.status = ReceiptStatus::Windowed;
        let window_id = window.window_id.clone();
        self.appeal_windows.insert(window_id.clone(), window);
        self.refresh();
        Ok(window_id)
    }

    pub fn submit_slh_dsa_appeal(&mut self, input: SlhDsaAppealInput) -> Result<String> {
        let appeal = SlhDsaAppeal::from_input(&self.config, &self.appeal_windows, input)?;
        if self.slh_dsa_appeals.contains_key(&appeal.appeal_id) {
            return Err("slh-dsa appeal already exists".to_string());
        }
        if let Some(entry) = self.exit_nullifier_entries.get_mut(&appeal.exit_entry_id) {
            entry.status = ExitNullifierStatus::Appealed;
            entry.reward_locked_atomic = entry
                .reward_locked_atomic
                .saturating_add(appeal.reward_atomic);
        }
        if let Some(receipt) = self.pq_receipt_commitments.get_mut(&appeal.receipt_id) {
            receipt.status = ReceiptStatus::Appealed;
        }
        if let Some(window) = self.appeal_windows.get_mut(&appeal.window_id) {
            window.status = ExitNullifierStatus::Appealed;
        }
        let appeal_id = appeal.appeal_id.clone();
        self.slh_dsa_appeals.insert(appeal_id.clone(), appeal);
        self.refresh();
        Ok(appeal_id)
    }

    pub fn anchor_appeal_evidence(&mut self, input: AppealEvidenceInput) -> Result<String> {
        let evidence =
            AppealEvidence::from_input(&self.appeal_windows, &self.slh_dsa_appeals, input)?;
        if self.appeal_evidence.contains_key(&evidence.evidence_id) {
            return Err("slh-dsa appeal evidence already exists".to_string());
        }
        {
            let appeal = self
                .slh_dsa_appeals
                .get_mut(&evidence.appeal_id)
                .ok_or_else(|| "unknown slh-dsa appeal for evidence".to_string())?;
            appeal.status = if evidence.accepted {
                AppealStatus::Accepted
            } else {
                AppealStatus::Rejected
            };
        }
        let appeal = self
            .slh_dsa_appeals
            .get(&evidence.appeal_id)
            .ok_or_else(|| "slh-dsa evidence lost appeal reference".to_string())?;
        if evidence.accepted {
            if let Some(entry) = self.exit_nullifier_entries.get_mut(&appeal.exit_entry_id) {
                entry.status = ExitNullifierStatus::Restored;
            }
            if let Some(receipt) = self.pq_receipt_commitments.get_mut(&appeal.receipt_id) {
                receipt.status = ReceiptStatus::Superseded;
            }
            if let Some(window) = self.appeal_windows.get_mut(&appeal.window_id) {
                window.status = ExitNullifierStatus::Restored;
            }
        } else if let Some(entry) = self.exit_nullifier_entries.get_mut(&appeal.exit_entry_id) {
            entry.status = ExitNullifierStatus::Upheld;
        }
        let evidence_id = evidence.evidence_id.clone();
        self.appeal_evidence.insert(evidence_id.clone(), evidence);
        self.refresh();
        Ok(evidence_id)
    }

    pub fn post_low_fee_appeal_batch(&mut self, input: LowFeeAppealBatchInput) -> Result<String> {
        let batch = LowFeeAppealBatch::from_input(&self.config, &self.slh_dsa_appeals, input)?;
        if self.low_fee_appeal_batches.contains_key(&batch.batch_id) {
            return Err("low-fee slh-dsa appeal batch already exists".to_string());
        }
        for appeal_id in &batch.appeal_ids {
            if let Some(appeal) = self.slh_dsa_appeals.get_mut(appeal_id) {
                appeal.status = AppealStatus::Batched;
                appeal.batch_id = Some(batch.batch_id.clone());
            }
        }
        let batch_id = batch.batch_id.clone();
        self.low_fee_appeal_batches.insert(batch_id.clone(), batch);
        self.refresh();
        Ok(batch_id)
    }

    pub fn settle_low_fee_appeal_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .low_fee_appeal_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown low-fee slh-dsa appeal batch".to_string())?;
        batch.status = BatchStatus::Settled;
        for appeal_id in &batch.appeal_ids {
            if let Some(appeal) = self.slh_dsa_appeals.get_mut(appeal_id) {
                appeal.status = AppealStatus::Settled;
                if let Some(entry) = self.exit_nullifier_entries.get_mut(&appeal.exit_entry_id) {
                    if entry.status == ExitNullifierStatus::Restored {
                        entry.reward_locked_atomic = entry
                            .reward_locked_atomic
                            .saturating_sub(appeal.reward_atomic);
                    }
                }
            }
        }
        self.refresh();
        Ok(())
    }

    pub fn finalize_appeal_window(&mut self, window_id: &str, finalized_slot: u64) -> Result<()> {
        let window = self
            .appeal_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown slh-dsa appeal window".to_string())?;
        if finalized_slot < window.settlement_slot {
            return Err("slh-dsa appeal window cannot finalize before settlement".to_string());
        }
        let has_accepted_appeal = self.slh_dsa_appeals.values().any(|appeal| {
            appeal.window_id == window.window_id
                && matches!(
                    appeal.status,
                    AppealStatus::Accepted | AppealStatus::Batched | AppealStatus::Settled
                )
        });
        if has_accepted_appeal {
            return Err("slh-dsa appeal window has accepted appeal".to_string());
        }
        window.status = ExitNullifierStatus::Finalized;
        if let Some(entry) = self.exit_nullifier_entries.get_mut(&window.exit_entry_id) {
            entry.status = ExitNullifierStatus::Finalized;
        }
        if let Some(receipt) = self.pq_receipt_commitments.get_mut(&window.receipt_id) {
            receipt.status = ReceiptStatus::Finalized;
        }
        self.refresh();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn seed_devnet(&mut self) {
        let mut appeal_ids = BTreeSet::new();
        for index in 0_u64..8 {
            let exit_entry_id = self
                .register_exit_nullifier_entry(ExitNullifierEntryInput {
                    account_commitment: sample_root("account-commitment", index),
                    exit_nullifier: sample_root("exit-nullifier", index),
                    slh_dsa_public_root: sample_root("slh-dsa-public-root", index),
                    nullifier_bucket_root: sample_root("nullifier-bucket-root", index),
                    encrypted_destination_root: sample_root("encrypted-destination", index),
                    nullifier_bucket: (index as u32) % self.config.nullifier_buckets,
                    epoch: self.epoch,
                    requested_slot: self.slot + index * 8,
                    exit_bond_atomic: self.config.exit_bond_atomic,
                })
                .expect("devnet slh-dsa exit nullifier entry must register");
            let receipt_id = self
                .commit_pq_receipt(PqReceiptCommitmentInput {
                    exit_entry_id: exit_entry_id.clone(),
                    receipt_commitment_root: sample_root("pq-receipt-commitment", index),
                    sealed_claim_root: sample_root("sealed-exit-receipt-claim", index),
                    slh_dsa_signature_commitment_root: sample_root(
                        "slh-dsa-signature-commitment",
                        index,
                    ),
                    encrypted_receipt_payload_root: sample_root("encrypted-receipt", index),
                    receipt_nullifier: sample_root("receipt-nullifier", index),
                    privacy_redaction_root: sample_root("receipt-redaction", index),
                    observed_state_root: sample_root("observed-state-root", index),
                    committed_slot: self.slot + index * 8 + 1,
                })
                .expect("devnet slh-dsa pq receipt must commit");
            let window_id = self
                .open_appeal_window(AppealWindowInput {
                    exit_entry_id: exit_entry_id.clone(),
                    receipt_id: receipt_id.clone(),
                    nullifier_bucket: (index as u32) % self.config.nullifier_buckets,
                    nullifier_set_root: sample_root("nullifier-set-root", index),
                    pq_receipt_set_root: sample_root("pq-receipt-set-root", index),
                    state_root: sample_root("appeal-window-state", index),
                    opened_slot: self.slot + index * 8 + 2,
                })
                .expect("devnet slh-dsa appeal window must open");
            if index % 2 == 0 {
                let appeal_id = self
                    .submit_slh_dsa_appeal(SlhDsaAppealInput {
                        window_id,
                        appellant_commitment: sample_root("appellant", index),
                        appeal_kind: match index {
                            0 => AppealKind::DuplicateExitNullifier,
                            2 => AppealKind::InvalidSlhDsaHashAttestation,
                            4 => AppealKind::ReceiptCommitmentMismatch,
                            _ => AppealKind::ReinsuranceStateRootInconsistency,
                        },
                        slh_dsa_layer_index: (index as u8) % self.config.slh_dsa_layer_count,
                        fors_tree_index: index % u64::from(self.config.slh_dsa_fors_trees),
                        appealed_nullifier_commitment: sample_root("appealed-nullifier", index),
                        appeal_nullifier: sample_root("appeal-nullifier", index),
                        evidence_commitment_root: sample_root("evidence-commitment", index),
                        appeal_bond_atomic: self.config.appeal_bond_atomic,
                        opened_slot: self.slot + index * 8 + 9,
                    })
                    .expect("devnet slh-dsa appeal must submit");
                self.anchor_appeal_evidence(AppealEvidenceInput {
                    appeal_id: appeal_id.clone(),
                    hash_based_attestation_root: sample_root(
                        "hash-based-appeal-attestation",
                        index,
                    ),
                    appeal_digest_root: sample_root("appeal-digest", index),
                    signature_transcript_root: sample_root("signature-transcript", index),
                    pq_witness_bundle_root: sample_root("pq-witness-bundle", index),
                    nullifier_membership_witness_root: sample_root("nullifier-membership", index),
                    sealed_receipt_claim_opening_root: sample_root("sealed-claim-opening", index),
                    state_transition_witness_root: sample_root("state-transition-witness", index),
                    privacy_redaction_root: sample_root("evidence-redaction", index),
                    accepted: index != 4,
                    anchored_slot: self.slot + index * 8 + 20,
                })
                .expect("devnet slh-dsa appeal evidence must anchor");
                if index != 4 {
                    appeal_ids.insert(appeal_id);
                }
            }
        }
        if appeal_ids.len() >= usize::from(self.config.min_batch_size) {
            let batch_id = self
                .post_low_fee_appeal_batch(LowFeeAppealBatchInput {
                    sequencer_commitment: sample_root("appeal-batch-sequencer", 0),
                    appeal_ids,
                    aggregation_root: sample_root("appeal-batch-aggregation", 0),
                    fee_sponsor_commitment: sample_root("batch-fee-sponsor", 0),
                    batch_fee_micro_units: self.config.max_batch_fee_micro_units / 2,
                    posted_slot: self.slot + 256,
                })
                .expect("devnet low-fee slh-dsa appeal batch must post");
            self.settle_low_fee_appeal_batch(&batch_id)
                .expect("devnet low-fee slh-dsa appeal batch must settle");
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            exit_nullifier_entries: self.exit_nullifier_entries.len() as u64,
            pq_receipt_commitments: self.pq_receipt_commitments.len() as u64,
            appeal_windows: self.appeal_windows.len() as u64,
            slh_dsa_appeals: self.slh_dsa_appeals.len() as u64,
            appeal_evidence: self.appeal_evidence.len() as u64,
            low_fee_appeal_batches: self.low_fee_appeal_batches.len() as u64,
            pq_witness_bundles: self.appeal_evidence.len() as u64,
            sealed_exit_receipt_claims: self.pq_receipt_commitments.len() as u64,
            appeal_nullifiers: self.slh_dsa_appeals.len() as u64,
            pending_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| {
                    matches!(
                        entry.status,
                        ExitNullifierStatus::Pending
                            | ExitNullifierStatus::ReceiptCommitted
                            | ExitNullifierStatus::AppealWindowOpen
                    )
                })
                .count() as u64,
            appealed_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| entry.status == ExitNullifierStatus::Appealed)
                .count() as u64,
            restored_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| entry.status == ExitNullifierStatus::Restored)
                .count() as u64,
            upheld_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| entry.status == ExitNullifierStatus::Upheld)
                .count() as u64,
            finalized_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| entry.status == ExitNullifierStatus::Finalized)
                .count() as u64,
            total_exit_bond_atomic: self
                .exit_nullifier_entries
                .values()
                .map(|entry| entry.exit_bond_atomic)
                .sum(),
            total_appeal_bond_atomic: self
                .slh_dsa_appeals
                .values()
                .map(|appeal| appeal.appeal_bond_atomic)
                .sum(),
            total_reward_atomic: self
                .slh_dsa_appeals
                .values()
                .filter(|appeal| {
                    matches!(
                        appeal.status,
                        AppealStatus::Accepted | AppealStatus::Batched | AppealStatus::Settled
                    )
                })
                .map(|appeal| appeal.reward_atomic)
                .sum(),
            total_batch_fee_micro_units: self
                .low_fee_appeal_batches
                .values()
                .map(|batch| batch.batch_fee_micro_units)
                .sum(),
            total_batched_appeals: self
                .low_fee_appeal_batches
                .values()
                .map(|batch| batch.appeal_ids.len() as u64)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let exit_nullifier_entry_root = record_root(
            "exit-nullifier-entries",
            self.exit_nullifier_entries
                .values()
                .map(ExitNullifierEntry::public_record)
                .collect(),
        );
        let pq_receipt_commitment_root = record_root(
            "pq-receipt-commitments",
            self.pq_receipt_commitments
                .values()
                .map(PqReceiptCommitment::public_record)
                .collect(),
        );
        let appeal_window_root = record_root(
            "appeal-windows",
            self.appeal_windows
                .values()
                .map(AppealWindow::public_record)
                .collect(),
        );
        let slh_dsa_appeal_root = record_root(
            "slh-dsa-appeals",
            self.slh_dsa_appeals
                .values()
                .map(SlhDsaAppeal::public_record)
                .collect(),
        );
        let appeal_evidence_root = record_root(
            "appeal-evidence",
            self.appeal_evidence
                .values()
                .map(AppealEvidence::public_record)
                .collect(),
        );
        let low_fee_appeal_batch_root = record_root(
            "low-fee-appeal-batches",
            self.low_fee_appeal_batches
                .values()
                .map(LowFeeAppealBatch::public_record)
                .collect(),
        );
        let pq_witness_bundle_root = record_root(
            "pq-witness-bundles",
            self.appeal_evidence
                .values()
                .map(|evidence| {
                    json!({
                        "appeal_id": &evidence.appeal_id,
                        "pq_witness_bundle_root": &evidence.pq_witness_bundle_root,
                        "hash_based_attestation_root": &evidence.hash_based_attestation_root,
                    })
                })
                .collect(),
        );
        let sealed_exit_receipt_claim_root = record_root(
            "sealed-exit-receipt-claims",
            self.pq_receipt_commitments
                .values()
                .map(|receipt| {
                    json!({
                        "receipt_id": &receipt.receipt_id,
                        "sealed_claim_root": &receipt.sealed_claim_root,
                        "receipt_commitment_root": &receipt.receipt_commitment_root,
                    })
                })
                .collect(),
        );
        let appeal_nullifier_root = record_root(
            "appeal-nullifiers",
            self.slh_dsa_appeals
                .values()
                .map(|appeal| {
                    json!({
                        "appeal_id": &appeal.appeal_id,
                        "appeal_nullifier": &appeal.appeal_nullifier,
                    })
                })
                .collect(),
        );
        let privacy_redaction_root = record_root(
            "privacy-redactions",
            self.pq_receipt_commitments
                .values()
                .map(|receipt| {
                    json!({
                        "receipt_id": &receipt.receipt_id,
                        "privacy_redaction_root": &receipt.privacy_redaction_root,
                    })
                })
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
                "exit_nullifier_entry_root": exit_nullifier_entry_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "appeal_window_root": appeal_window_root,
                "slh_dsa_appeal_root": slh_dsa_appeal_root,
                "appeal_evidence_root": appeal_evidence_root,
                "low_fee_appeal_batch_root": low_fee_appeal_batch_root,
                "pq_witness_bundle_root": pq_witness_bundle_root,
                "sealed_exit_receipt_claim_root": sealed_exit_receipt_claim_root,
                "appeal_nullifier_root": appeal_nullifier_root,
                "privacy_redaction_root": privacy_redaction_root,
                "redacted_totals": json!(self.counters),
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": json!(self.config),
                "counters": json!(self.counters),
                "exit_nullifier_entry_root": exit_nullifier_entry_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "appeal_window_root": appeal_window_root,
                "slh_dsa_appeal_root": slh_dsa_appeal_root,
                "appeal_evidence_root": appeal_evidence_root,
                "low_fee_appeal_batch_root": low_fee_appeal_batch_root,
                "pq_witness_bundle_root": pq_witness_bundle_root,
                "sealed_exit_receipt_claim_root": sealed_exit_receipt_claim_root,
                "appeal_nullifier_root": appeal_nullifier_root,
                "privacy_redaction_root": privacy_redaction_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-RECEIPT-REINSURANCE-APPEAL-STATE",
            &[
                HashPart::Json(&json!(self.config)),
                HashPart::Json(&json!(self.counters)),
                HashPart::Str(&exit_nullifier_entry_root),
                HashPart::Str(&pq_receipt_commitment_root),
                HashPart::Str(&appeal_window_root),
                HashPart::Str(&slh_dsa_appeal_root),
                HashPart::Str(&appeal_evidence_root),
                HashPart::Str(&low_fee_appeal_batch_root),
                HashPart::Str(&pq_witness_bundle_root),
                HashPart::Str(&sealed_exit_receipt_claim_root),
                HashPart::Str(&appeal_nullifier_root),
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
            exit_nullifier_entry_root,
            pq_receipt_commitment_root,
            appeal_window_root,
            slh_dsa_appeal_root,
            appeal_evidence_root,
            low_fee_appeal_batch_root,
            pq_witness_bundle_root,
            sealed_exit_receipt_claim_root,
            appeal_nullifier_root,
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
            exit_nullifier_entries: BTreeMap::new(),
            pq_receipt_commitments: BTreeMap::new(),
            appeal_windows: BTreeMap::new(),
            slh_dsa_appeals: BTreeMap::new(),
            appeal_evidence: BTreeMap::new(),
            low_fee_appeal_batches: BTreeMap::new(),
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
        "slh_dsa_exit_receipt_reinsurance_appeal_suite": SLH_DSA_EXIT_RECEIPT_REINSURANCE_APPEAL_SUITE,
        "pq_receipt_commitment_suite": PQ_RECEIPT_COMMITMENT_SUITE,
        "appeal_window_suite": REINSURANCE_APPEAL_WINDOW_SUITE,
        "appeal_bond_suite": REINSURANCE_BOND_SUITE,
        "low_fee_appeal_batch_suite": LOW_FEE_REINSURANCE_APPEAL_BATCH_SUITE,
        "private_record_api_suite": PRIVATE_RECORD_API_SUITE,
        "config": json!(state.config),
        "counters": json!(state.counters),
        "roots": json!(state.roots),
        "roots_only_public_records": true,
        "redacted_private_records": {
            "exit_nullifier_entries": state.roots.exit_nullifier_entry_root,
            "sealed_exit_receipt_claims": state.roots.sealed_exit_receipt_claim_root,
            "pq_receipt_commitments": state.roots.pq_receipt_commitment_root,
            "appeal_windows": state.roots.appeal_window_root,
            "slh_dsa_appeals": state.roots.slh_dsa_appeal_root,
            "appeal_evidence": state.roots.appeal_evidence_root,
            "pq_witness_bundles": state.roots.pq_witness_bundle_root,
            "appeal_nullifiers": state.roots.appeal_nullifier_root,
            "low_fee_appeal_batches": state.roots.low_fee_appeal_batch_root,
            "privacy_redactions": state.roots.privacy_redaction_root,
        },
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-RECEIPT-REINSURANCE-APPEAL-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-RECEIPT-REINSURANCE-APPEAL-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-RECEIPT-REINSURANCE-APPEAL-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-RECEIPT-REINSURANCE-APPEAL-{domain}"),
        &values,
    )
}

fn require_non_empty(values: &[(&String, &str)]) -> Result<()> {
    for (value, label) in values {
        if value.is_empty() {
            return Err(format!("{label} must be non-empty"));
        }
    }
    Ok(())
}
