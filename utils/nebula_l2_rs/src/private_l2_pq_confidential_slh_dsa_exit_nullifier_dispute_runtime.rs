use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSlhDsaExitNullifierDisputeRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_EXIT_NULLIFIER_DISPUTE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-slh-dsa-exit-nullifier-dispute-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_EXIT_NULLIFIER_DISPUTE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SLH_DSA_EXIT_NULLIFIER_SUITE: &str = "slh-dsa-exit-nullifier-dispute-v1";
pub const PQ_RECEIPT_COMMITMENT_SUITE: &str = "slh-dsa-pq-confidential-exit-receipt-commitment-v1";
pub const DISPUTE_WINDOW_SUITE: &str = "slh-dsa-exit-nullifier-dispute-window-v1";
pub const DISPUTE_BOND_SUITE: &str = "slh-dsa-confidential-dispute-bond-escrow-v1";
pub const LOW_FEE_CHALLENGE_BATCH_SUITE: &str = "low-fee-slh-dsa-exit-nullifier-dispute-batch-v1";
pub const PRIVATE_RECORD_API_SUITE: &str =
    "privacy-preserving-slh-dsa-exit-nullifier-public-record-state-root-v1";
pub const DEVNET_HEIGHT: u64 = 8_704_000;
pub const DEVNET_EPOCH: u64 = 36_240;
pub const DEVNET_SLOT: u64 = 432;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SLH_DSA_TREE_HEIGHT: u8 = 22;
pub const DEFAULT_SLH_DSA_LAYER_COUNT: u8 = 4;
pub const DEFAULT_SLH_DSA_FORS_TREES: u16 = 35;
pub const DEFAULT_SLH_DSA_SIGNATURE_BYTES_CAP: u16 = 49_856;
pub const DEFAULT_NULLIFIER_BUCKETS: u32 = 196_608;
pub const DEFAULT_DISPUTE_WINDOW_SLOTS: u64 = 3_120;
pub const DEFAULT_EVIDENCE_GRACE_SLOTS: u64 = 640;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 1_440;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 48;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 30_000_000_000;
pub const DEFAULT_DISPUTE_BOND_ATOMIC: u64 = 2_100_000_000;
pub const DEFAULT_SUCCESS_REWARD_BPS: u16 = 1_500;
pub const DEFAULT_NULLIFIER_REPAIR_BPS: u16 = 8_500;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 1_024;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 95;
pub const DEFAULT_EPOCH_BUCKET_TARGET_EXITS: u64 = 40_960;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitNullifierStatus {
    Pending,
    ReceiptCommitted,
    DisputeWindowOpen,
    Disputed,
    Repaired,
    Cleared,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Committed,
    Windowed,
    Disputed,
    Superseded,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeKind {
    DuplicateExitNullifier,
    InvalidSlhDsaHypertreePath,
    ForsMessageDigestMismatch,
    ReceiptCommitmentMismatch,
    NullifierBucketOmission,
    StateRootInconsistency,
    DisputeWindowViolation,
}

impl DisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateExitNullifier => "duplicate_exit_nullifier",
            Self::InvalidSlhDsaHypertreePath => "invalid_slh_dsa_hypertree_path",
            Self::ForsMessageDigestMismatch => "fors_message_digest_mismatch",
            Self::ReceiptCommitmentMismatch => "receipt_commitment_mismatch",
            Self::NullifierBucketOmission => "nullifier_bucket_omission",
            Self::StateRootInconsistency => "state_root_inconsistency",
            Self::DisputeWindowViolation => "dispute_window_violation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
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
    pub slh_dsa_exit_nullifier_suite: String,
    pub pq_receipt_commitment_suite: String,
    pub dispute_window_suite: String,
    pub dispute_bond_suite: String,
    pub low_fee_challenge_batch_suite: String,
    pub private_record_api_suite: String,
    pub min_pq_security_bits: u16,
    pub slh_dsa_tree_height: u8,
    pub slh_dsa_layer_count: u8,
    pub slh_dsa_fors_trees: u16,
    pub slh_dsa_signature_bytes_cap: u16,
    pub nullifier_buckets: u32,
    pub dispute_window_slots: u64,
    pub evidence_grace_slots: u64,
    pub settlement_delay_slots: u64,
    pub receipt_retention_epochs: u64,
    pub exit_bond_atomic: u64,
    pub dispute_bond_atomic: u64,
    pub success_reward_bps: u16,
    pub nullifier_repair_bps: u16,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_exits: u64,
    pub pq_receipt_commitments_required: bool,
    pub slh_dsa_auth_paths_required: bool,
    pub dispute_windows_required: bool,
    pub dispute_bonds_required: bool,
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
            slh_dsa_exit_nullifier_suite: SLH_DSA_EXIT_NULLIFIER_SUITE.to_string(),
            pq_receipt_commitment_suite: PQ_RECEIPT_COMMITMENT_SUITE.to_string(),
            dispute_window_suite: DISPUTE_WINDOW_SUITE.to_string(),
            dispute_bond_suite: DISPUTE_BOND_SUITE.to_string(),
            low_fee_challenge_batch_suite: LOW_FEE_CHALLENGE_BATCH_SUITE.to_string(),
            private_record_api_suite: PRIVATE_RECORD_API_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            slh_dsa_tree_height: DEFAULT_SLH_DSA_TREE_HEIGHT,
            slh_dsa_layer_count: DEFAULT_SLH_DSA_LAYER_COUNT,
            slh_dsa_fors_trees: DEFAULT_SLH_DSA_FORS_TREES,
            slh_dsa_signature_bytes_cap: DEFAULT_SLH_DSA_SIGNATURE_BYTES_CAP,
            nullifier_buckets: DEFAULT_NULLIFIER_BUCKETS,
            dispute_window_slots: DEFAULT_DISPUTE_WINDOW_SLOTS,
            evidence_grace_slots: DEFAULT_EVIDENCE_GRACE_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            dispute_bond_atomic: DEFAULT_DISPUTE_BOND_ATOMIC,
            success_reward_bps: DEFAULT_SUCCESS_REWARD_BPS,
            nullifier_repair_bps: DEFAULT_NULLIFIER_REPAIR_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_exits: DEFAULT_EPOCH_BUCKET_TARGET_EXITS,
            pq_receipt_commitments_required: true,
            slh_dsa_auth_paths_required: true,
            dispute_windows_required: true,
            dispute_bonds_required: true,
            low_fee_batching_enabled: true,
            privacy_preserving_public_records_required: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below slh-dsa dispute minimum".to_string());
        }
        if self.slh_dsa_tree_height < 12 || self.slh_dsa_layer_count == 0 {
            return Err("invalid slh-dsa hypertree schedule".to_string());
        }
        if self.slh_dsa_fors_trees == 0 || self.slh_dsa_signature_bytes_cap < 16_000 {
            return Err("invalid slh-dsa fors or signature policy".to_string());
        }
        if self.nullifier_buckets == 0 || self.epoch_bucket_target_exits == 0 {
            return Err("nullifier buckets and epoch target exits must be positive".to_string());
        }
        if self.dispute_window_slots == 0
            || self.evidence_grace_slots == 0
            || self.settlement_delay_slots == 0
        {
            return Err("slh-dsa dispute windows must be positive".to_string());
        }
        if self.evidence_grace_slots > self.dispute_window_slots {
            return Err("evidence grace cannot exceed dispute window".to_string());
        }
        if self.exit_bond_atomic == 0 || self.dispute_bond_atomic == 0 {
            return Err("slh-dsa dispute bonds must be positive".to_string());
        }
        if self.dispute_bond_atomic >= self.exit_bond_atomic {
            return Err("dispute bond must be smaller than exit bond".to_string());
        }
        if u32::from(self.success_reward_bps) + u32::from(self.nullifier_repair_bps) != 10_000 {
            return Err("slh-dsa dispute reward basis points must sum to 10000".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
            || self.max_batch_fee_micro_units == 0
        {
            return Err("invalid low-fee slh-dsa dispute batching policy".to_string());
        }
        if !self.pq_receipt_commitments_required
            || !self.slh_dsa_auth_paths_required
            || !self.dispute_windows_required
            || !self.dispute_bonds_required
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
    pub dispute_windows: u64,
    pub slh_dsa_disputes: u64,
    pub dispute_evidence: u64,
    pub low_fee_challenge_batches: u64,
    pub pending_nullifiers: u64,
    pub disputed_nullifiers: u64,
    pub repaired_nullifiers: u64,
    pub cleared_nullifiers: u64,
    pub finalized_nullifiers: u64,
    pub total_exit_bond_atomic: u64,
    pub total_dispute_bond_atomic: u64,
    pub total_reward_atomic: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_batched_disputes: u64,
}

impl Counters {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub exit_nullifier_entry_root: String,
    pub pq_receipt_commitment_root: String,
    pub dispute_window_root: String,
    pub slh_dsa_dispute_root: String,
    pub dispute_evidence_root: String,
    pub low_fee_challenge_batch_root: String,
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
    pub slh_dsa_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_nullifier: String,
    pub observed_state_root: String,
    pub committed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeWindowInput {
    pub exit_entry_id: String,
    pub receipt_id: String,
    pub nullifier_bucket: u32,
    pub nullifier_set_root: String,
    pub pq_receipt_set_root: String,
    pub state_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlhDsaDisputeInput {
    pub window_id: String,
    pub challenger_commitment: String,
    pub dispute_kind: DisputeKind,
    pub slh_dsa_layer: u8,
    pub hypertree_leaf_index: u64,
    pub disputed_nullifier_commitment: String,
    pub evidence_commitment_root: String,
    pub dispute_bond_atomic: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeEvidenceInput {
    pub dispute_id: String,
    pub slh_dsa_auth_path_root: String,
    pub fors_digest_root: String,
    pub signature_transcript_root: String,
    pub nullifier_membership_witness_root: String,
    pub receipt_opening_root: String,
    pub state_transition_witness_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeChallengeBatchInput {
    pub sequencer_commitment: String,
    pub dispute_ids: BTreeSet<String>,
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
    pub dispute_open_slot: u64,
    pub dispute_close_slot: u64,
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
        if input.exit_bond_atomic < config.dispute_bond_atomic
            || input.exit_bond_atomic > config.exit_bond_atomic
        {
            return Err("exit bond amount outside slh-dsa dispute policy".to_string());
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
        let dispute_open_slot = input.requested_slot;
        let dispute_close_slot = dispute_open_slot + config.dispute_window_slots;
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
            dispute_open_slot,
            dispute_close_slot,
            finality_slot: dispute_close_slot + config.settlement_delay_slots,
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
    pub slh_dsa_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_nullifier: String,
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
            (
                &input.slh_dsa_signature_commitment_root,
                "slh-dsa signature commitment root",
            ),
            (
                &input.encrypted_receipt_payload_root,
                "encrypted receipt payload root",
            ),
            (&input.receipt_nullifier, "receipt nullifier"),
            (&input.observed_state_root, "observed state root"),
        ])?;
        let receipt_id = deterministic_id(
            "pq-receipt-commitment",
            &[
                HashPart::Str(&input.exit_entry_id),
                HashPart::Str(&input.receipt_commitment_root),
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
                "slh_dsa_signature_commitment_root": input.slh_dsa_signature_commitment_root,
                "encrypted_receipt_payload_root": input.encrypted_receipt_payload_root,
                "observed_state_root": input.observed_state_root,
            }),
        );
        Ok(Self {
            receipt_id,
            exit_entry_id: input.exit_entry_id,
            receipt_commitment_root: input.receipt_commitment_root,
            slh_dsa_signature_commitment_root: input.slh_dsa_signature_commitment_root,
            encrypted_receipt_payload_root: input.encrypted_receipt_payload_root,
            receipt_nullifier: input.receipt_nullifier,
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
pub struct DisputeWindow {
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

impl DisputeWindow {
    pub fn from_input(config: &Config, input: DisputeWindowInput) -> Result<Self> {
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
            "dispute-window",
            &[
                HashPart::Str(&input.exit_entry_id),
                HashPart::Str(&input.receipt_id),
                HashPart::U64(u64::from(input.nullifier_bucket)),
                HashPart::Str(&input.nullifier_set_root),
                HashPart::Str(&input.pq_receipt_set_root),
            ],
        );
        let window_close_slot = input.opened_slot + config.dispute_window_slots;
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
            status: ExitNullifierStatus::DisputeWindowOpen,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlhDsaDispute {
    pub dispute_id: String,
    pub window_id: String,
    pub exit_entry_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub dispute_kind: DisputeKind,
    pub slh_dsa_layer: u8,
    pub hypertree_leaf_index: u64,
    pub disputed_nullifier_commitment: String,
    pub evidence_commitment_root: String,
    pub dispute_bond_atomic: u64,
    pub reward_atomic: u64,
    pub opened_slot: u64,
    pub batch_id: Option<String>,
    pub status: DisputeStatus,
}

impl SlhDsaDispute {
    pub fn from_input(
        config: &Config,
        windows: &BTreeMap<String, DisputeWindow>,
        input: SlhDsaDisputeInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.window_id, "window id"),
            (&input.challenger_commitment, "challenger commitment"),
            (
                &input.disputed_nullifier_commitment,
                "disputed nullifier commitment",
            ),
            (&input.evidence_commitment_root, "evidence commitment root"),
        ])?;
        if input.slh_dsa_layer >= config.slh_dsa_layer_count {
            return Err("slh-dsa layer exceeds configured layer count".to_string());
        }
        if input.dispute_bond_atomic < config.dispute_bond_atomic {
            return Err("dispute bond below configured minimum".to_string());
        }
        let window = windows
            .get(&input.window_id)
            .ok_or_else(|| "unknown slh-dsa dispute window".to_string())?;
        if input.opened_slot < window.window_open_slot
            || input.opened_slot > window.window_close_slot
        {
            return Err("slh-dsa dispute opened outside dispute window".to_string());
        }
        let dispute_id = deterministic_id(
            "slh-dsa-dispute",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.challenger_commitment),
                HashPart::Str(input.dispute_kind.as_str()),
                HashPart::U64(u64::from(input.slh_dsa_layer)),
                HashPart::U64(input.hypertree_leaf_index),
                HashPart::Str(&input.disputed_nullifier_commitment),
                HashPart::U64(input.opened_slot),
            ],
        );
        let reward_atomic =
            input.dispute_bond_atomic * u64::from(config.success_reward_bps) / 10_000;
        Ok(Self {
            dispute_id,
            window_id: input.window_id,
            exit_entry_id: window.exit_entry_id.clone(),
            receipt_id: window.receipt_id.clone(),
            challenger_commitment: input.challenger_commitment,
            dispute_kind: input.dispute_kind,
            slh_dsa_layer: input.slh_dsa_layer,
            hypertree_leaf_index: input.hypertree_leaf_index,
            disputed_nullifier_commitment: input.disputed_nullifier_commitment,
            evidence_commitment_root: input.evidence_commitment_root,
            dispute_bond_atomic: input.dispute_bond_atomic,
            reward_atomic,
            opened_slot: input.opened_slot,
            batch_id: None,
            status: DisputeStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeEvidence {
    pub evidence_id: String,
    pub dispute_id: String,
    pub slh_dsa_auth_path_root: String,
    pub fors_digest_root: String,
    pub signature_transcript_root: String,
    pub nullifier_membership_witness_root: String,
    pub receipt_opening_root: String,
    pub state_transition_witness_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
    pub evidence_state_root: String,
}

impl DisputeEvidence {
    pub fn from_input(
        windows: &BTreeMap<String, DisputeWindow>,
        disputes: &BTreeMap<String, SlhDsaDispute>,
        input: DisputeEvidenceInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.dispute_id, "dispute id"),
            (&input.slh_dsa_auth_path_root, "slh-dsa auth path root"),
            (&input.fors_digest_root, "fors digest root"),
            (
                &input.signature_transcript_root,
                "signature transcript root",
            ),
            (
                &input.nullifier_membership_witness_root,
                "nullifier membership witness root",
            ),
            (&input.receipt_opening_root, "receipt opening root"),
            (
                &input.state_transition_witness_root,
                "state transition witness root",
            ),
        ])?;
        let dispute = disputes
            .get(&input.dispute_id)
            .ok_or_else(|| "unknown slh-dsa dispute".to_string())?;
        let window = windows
            .get(&dispute.window_id)
            .ok_or_else(|| "slh-dsa dispute lost window reference".to_string())?;
        if input.anchored_slot > window.evidence_deadline_slot {
            return Err("slh-dsa dispute evidence anchored after deadline".to_string());
        }
        let evidence_id = deterministic_id(
            "dispute-evidence",
            &[
                HashPart::Str(&input.dispute_id),
                HashPart::Str(&input.slh_dsa_auth_path_root),
                HashPart::Str(&input.fors_digest_root),
                HashPart::Str(&input.receipt_opening_root),
                HashPart::U64(input.anchored_slot),
            ],
        );
        let evidence_state_root = value_root(
            "dispute-evidence-state",
            &json!({
                "evidence_id": evidence_id,
                "dispute_id": input.dispute_id,
                "slh_dsa_auth_path_root": input.slh_dsa_auth_path_root,
                "fors_digest_root": input.fors_digest_root,
                "signature_transcript_root": input.signature_transcript_root,
                "nullifier_membership_witness_root": input.nullifier_membership_witness_root,
                "receipt_opening_root": input.receipt_opening_root,
                "state_transition_witness_root": input.state_transition_witness_root,
                "accepted": input.accepted,
            }),
        );
        Ok(Self {
            evidence_id,
            dispute_id: input.dispute_id,
            slh_dsa_auth_path_root: input.slh_dsa_auth_path_root,
            fors_digest_root: input.fors_digest_root,
            signature_transcript_root: input.signature_transcript_root,
            nullifier_membership_witness_root: input.nullifier_membership_witness_root,
            receipt_opening_root: input.receipt_opening_root,
            state_transition_witness_root: input.state_transition_witness_root,
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
pub struct LowFeeChallengeBatch {
    pub batch_id: String,
    pub sequencer_commitment: String,
    pub dispute_ids: BTreeSet<String>,
    pub aggregation_root: String,
    pub fee_sponsor_commitment: String,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
    pub dispute_count: u16,
    pub status: BatchStatus,
}

impl LowFeeChallengeBatch {
    pub fn from_input(
        config: &Config,
        disputes: &BTreeMap<String, SlhDsaDispute>,
        input: LowFeeChallengeBatchInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.sequencer_commitment, "sequencer commitment"),
            (&input.aggregation_root, "aggregation root"),
            (&input.fee_sponsor_commitment, "fee sponsor commitment"),
        ])?;
        let dispute_count = input.dispute_ids.len();
        if dispute_count < usize::from(config.min_batch_size)
            || dispute_count > usize::from(config.low_fee_batch_limit)
        {
            return Err("slh-dsa dispute batch size outside configured policy".to_string());
        }
        if input.batch_fee_micro_units > config.max_batch_fee_micro_units {
            return Err("slh-dsa dispute batch fee exceeds low-fee cap".to_string());
        }
        for dispute_id in &input.dispute_ids {
            let dispute = disputes
                .get(dispute_id)
                .ok_or_else(|| "unknown dispute in low-fee batch".to_string())?;
            if !matches!(dispute.status, DisputeStatus::Accepted) {
                return Err("only accepted disputes can enter low-fee batch".to_string());
            }
        }
        let batch_id = deterministic_id(
            "low-fee-challenge-batch",
            &[
                HashPart::Str(&input.sequencer_commitment),
                HashPart::Str(&input.aggregation_root),
                HashPart::Str(&input.fee_sponsor_commitment),
                HashPart::U64(dispute_count as u64),
                HashPart::U64(input.posted_slot),
            ],
        );
        Ok(Self {
            batch_id,
            sequencer_commitment: input.sequencer_commitment,
            dispute_ids: input.dispute_ids,
            aggregation_root: input.aggregation_root,
            fee_sponsor_commitment: input.fee_sponsor_commitment,
            batch_fee_micro_units: input.batch_fee_micro_units,
            posted_slot: input.posted_slot,
            dispute_count: dispute_count as u16,
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
    pub dispute_windows: BTreeMap<String, DisputeWindow>,
    pub slh_dsa_disputes: BTreeMap<String, SlhDsaDispute>,
    pub dispute_evidence: BTreeMap<String, DisputeEvidence>,
    pub low_fee_challenge_batches: BTreeMap<String, LowFeeChallengeBatch>,
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
            dispute_windows: BTreeMap::new(),
            slh_dsa_disputes: BTreeMap::new(),
            dispute_evidence: BTreeMap::new(),
            low_fee_challenge_batches: BTreeMap::new(),
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

    pub fn open_dispute_window(&mut self, input: DisputeWindowInput) -> Result<String> {
        let window = DisputeWindow::from_input(&self.config, input)?;
        if self.dispute_windows.contains_key(&window.window_id) {
            return Err("slh-dsa dispute window already exists".to_string());
        }
        let entry = self
            .exit_nullifier_entries
            .get_mut(&window.exit_entry_id)
            .ok_or_else(|| "unknown exit nullifier entry for dispute window".to_string())?;
        let receipt = self
            .pq_receipt_commitments
            .get_mut(&window.receipt_id)
            .ok_or_else(|| "unknown pq receipt for dispute window".to_string())?;
        if receipt.exit_entry_id != window.exit_entry_id {
            return Err("pq receipt does not belong to exit nullifier entry".to_string());
        }
        if entry.nullifier_bucket != window.nullifier_bucket {
            return Err("dispute window bucket does not match exit entry".to_string());
        }
        entry.status = ExitNullifierStatus::DisputeWindowOpen;
        receipt.status = ReceiptStatus::Windowed;
        let window_id = window.window_id.clone();
        self.dispute_windows.insert(window_id.clone(), window);
        self.refresh();
        Ok(window_id)
    }

    pub fn submit_slh_dsa_dispute(&mut self, input: SlhDsaDisputeInput) -> Result<String> {
        let dispute = SlhDsaDispute::from_input(&self.config, &self.dispute_windows, input)?;
        if self.slh_dsa_disputes.contains_key(&dispute.dispute_id) {
            return Err("slh-dsa dispute already exists".to_string());
        }
        if let Some(entry) = self.exit_nullifier_entries.get_mut(&dispute.exit_entry_id) {
            entry.status = ExitNullifierStatus::Disputed;
            entry.reward_locked_atomic = entry
                .reward_locked_atomic
                .saturating_add(dispute.reward_atomic);
        }
        if let Some(receipt) = self.pq_receipt_commitments.get_mut(&dispute.receipt_id) {
            receipt.status = ReceiptStatus::Disputed;
        }
        if let Some(window) = self.dispute_windows.get_mut(&dispute.window_id) {
            window.status = ExitNullifierStatus::Disputed;
        }
        let dispute_id = dispute.dispute_id.clone();
        self.slh_dsa_disputes.insert(dispute_id.clone(), dispute);
        self.refresh();
        Ok(dispute_id)
    }

    pub fn anchor_dispute_evidence(&mut self, input: DisputeEvidenceInput) -> Result<String> {
        let evidence =
            DisputeEvidence::from_input(&self.dispute_windows, &self.slh_dsa_disputes, input)?;
        if self.dispute_evidence.contains_key(&evidence.evidence_id) {
            return Err("slh-dsa dispute evidence already exists".to_string());
        }
        {
            let dispute = self
                .slh_dsa_disputes
                .get_mut(&evidence.dispute_id)
                .ok_or_else(|| "unknown slh-dsa dispute for evidence".to_string())?;
            dispute.status = if evidence.accepted {
                DisputeStatus::Accepted
            } else {
                DisputeStatus::Rejected
            };
        }
        let dispute = self
            .slh_dsa_disputes
            .get(&evidence.dispute_id)
            .ok_or_else(|| "slh-dsa evidence lost dispute reference".to_string())?;
        if evidence.accepted {
            if let Some(entry) = self.exit_nullifier_entries.get_mut(&dispute.exit_entry_id) {
                entry.status = ExitNullifierStatus::Repaired;
            }
            if let Some(receipt) = self.pq_receipt_commitments.get_mut(&dispute.receipt_id) {
                receipt.status = ReceiptStatus::Superseded;
            }
            if let Some(window) = self.dispute_windows.get_mut(&dispute.window_id) {
                window.status = ExitNullifierStatus::Repaired;
            }
        } else if let Some(entry) = self.exit_nullifier_entries.get_mut(&dispute.exit_entry_id) {
            entry.status = ExitNullifierStatus::Cleared;
        }
        let evidence_id = evidence.evidence_id.clone();
        self.dispute_evidence.insert(evidence_id.clone(), evidence);
        self.refresh();
        Ok(evidence_id)
    }

    pub fn post_low_fee_challenge_batch(
        &mut self,
        input: LowFeeChallengeBatchInput,
    ) -> Result<String> {
        let batch = LowFeeChallengeBatch::from_input(&self.config, &self.slh_dsa_disputes, input)?;
        if self.low_fee_challenge_batches.contains_key(&batch.batch_id) {
            return Err("low-fee slh-dsa dispute batch already exists".to_string());
        }
        for dispute_id in &batch.dispute_ids {
            if let Some(dispute) = self.slh_dsa_disputes.get_mut(dispute_id) {
                dispute.status = DisputeStatus::Batched;
                dispute.batch_id = Some(batch.batch_id.clone());
            }
        }
        let batch_id = batch.batch_id.clone();
        self.low_fee_challenge_batches
            .insert(batch_id.clone(), batch);
        self.refresh();
        Ok(batch_id)
    }

    pub fn settle_low_fee_challenge_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .low_fee_challenge_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown low-fee slh-dsa dispute batch".to_string())?;
        batch.status = BatchStatus::Settled;
        for dispute_id in &batch.dispute_ids {
            if let Some(dispute) = self.slh_dsa_disputes.get_mut(dispute_id) {
                dispute.status = DisputeStatus::Settled;
                if let Some(entry) = self.exit_nullifier_entries.get_mut(&dispute.exit_entry_id) {
                    if entry.status == ExitNullifierStatus::Repaired {
                        entry.reward_locked_atomic = entry
                            .reward_locked_atomic
                            .saturating_sub(dispute.reward_atomic);
                    }
                }
            }
        }
        self.refresh();
        Ok(())
    }

    pub fn finalize_dispute_window(&mut self, window_id: &str, finalized_slot: u64) -> Result<()> {
        let window = self
            .dispute_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown slh-dsa dispute window".to_string())?;
        if finalized_slot < window.settlement_slot {
            return Err("slh-dsa dispute window cannot finalize before settlement".to_string());
        }
        let has_accepted_dispute = self.slh_dsa_disputes.values().any(|dispute| {
            dispute.window_id == window.window_id
                && matches!(
                    dispute.status,
                    DisputeStatus::Accepted | DisputeStatus::Batched | DisputeStatus::Settled
                )
        });
        if has_accepted_dispute {
            return Err("slh-dsa dispute window has accepted dispute".to_string());
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
        let mut dispute_ids = BTreeSet::new();
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
                    slh_dsa_signature_commitment_root: sample_root(
                        "slh-dsa-signature-commitment",
                        index,
                    ),
                    encrypted_receipt_payload_root: sample_root("encrypted-receipt", index),
                    receipt_nullifier: sample_root("receipt-nullifier", index),
                    observed_state_root: sample_root("observed-state-root", index),
                    committed_slot: self.slot + index * 8 + 1,
                })
                .expect("devnet slh-dsa pq receipt must commit");
            let window_id = self
                .open_dispute_window(DisputeWindowInput {
                    exit_entry_id: exit_entry_id.clone(),
                    receipt_id: receipt_id.clone(),
                    nullifier_bucket: (index as u32) % self.config.nullifier_buckets,
                    nullifier_set_root: sample_root("nullifier-set-root", index),
                    pq_receipt_set_root: sample_root("pq-receipt-set-root", index),
                    state_root: sample_root("dispute-window-state", index),
                    opened_slot: self.slot + index * 8 + 2,
                })
                .expect("devnet slh-dsa dispute window must open");
            if index % 2 == 0 {
                let dispute_id = self
                    .submit_slh_dsa_dispute(SlhDsaDisputeInput {
                        window_id,
                        challenger_commitment: sample_root("challenger", index),
                        dispute_kind: match index {
                            0 => DisputeKind::DuplicateExitNullifier,
                            2 => DisputeKind::InvalidSlhDsaHypertreePath,
                            4 => DisputeKind::ReceiptCommitmentMismatch,
                            _ => DisputeKind::StateRootInconsistency,
                        },
                        slh_dsa_layer: (index as u8) % self.config.slh_dsa_layer_count,
                        hypertree_leaf_index: index * 19,
                        disputed_nullifier_commitment: sample_root("disputed-nullifier", index),
                        evidence_commitment_root: sample_root("evidence-commitment", index),
                        dispute_bond_atomic: self.config.dispute_bond_atomic,
                        opened_slot: self.slot + index * 8 + 9,
                    })
                    .expect("devnet slh-dsa dispute must submit");
                self.anchor_dispute_evidence(DisputeEvidenceInput {
                    dispute_id: dispute_id.clone(),
                    slh_dsa_auth_path_root: sample_root("slh-dsa-auth-path", index),
                    fors_digest_root: sample_root("fors-digest", index),
                    signature_transcript_root: sample_root("signature-transcript", index),
                    nullifier_membership_witness_root: sample_root("nullifier-membership", index),
                    receipt_opening_root: sample_root("receipt-opening", index),
                    state_transition_witness_root: sample_root("state-transition-witness", index),
                    accepted: index != 4,
                    anchored_slot: self.slot + index * 8 + 20,
                })
                .expect("devnet slh-dsa dispute evidence must anchor");
                if index != 4 {
                    dispute_ids.insert(dispute_id);
                }
            }
        }
        if dispute_ids.len() >= usize::from(self.config.min_batch_size) {
            let batch_id = self
                .post_low_fee_challenge_batch(LowFeeChallengeBatchInput {
                    sequencer_commitment: sample_root("challenge-batch-sequencer", 0),
                    dispute_ids,
                    aggregation_root: sample_root("challenge-batch-aggregation", 0),
                    fee_sponsor_commitment: sample_root("batch-fee-sponsor", 0),
                    batch_fee_micro_units: self.config.max_batch_fee_micro_units / 2,
                    posted_slot: self.slot + 256,
                })
                .expect("devnet low-fee slh-dsa dispute batch must post");
            self.settle_low_fee_challenge_batch(&batch_id)
                .expect("devnet low-fee slh-dsa dispute batch must settle");
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            exit_nullifier_entries: self.exit_nullifier_entries.len() as u64,
            pq_receipt_commitments: self.pq_receipt_commitments.len() as u64,
            dispute_windows: self.dispute_windows.len() as u64,
            slh_dsa_disputes: self.slh_dsa_disputes.len() as u64,
            dispute_evidence: self.dispute_evidence.len() as u64,
            low_fee_challenge_batches: self.low_fee_challenge_batches.len() as u64,
            pending_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| {
                    matches!(
                        entry.status,
                        ExitNullifierStatus::Pending
                            | ExitNullifierStatus::ReceiptCommitted
                            | ExitNullifierStatus::DisputeWindowOpen
                    )
                })
                .count() as u64,
            disputed_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| entry.status == ExitNullifierStatus::Disputed)
                .count() as u64,
            repaired_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| entry.status == ExitNullifierStatus::Repaired)
                .count() as u64,
            cleared_nullifiers: self
                .exit_nullifier_entries
                .values()
                .filter(|entry| entry.status == ExitNullifierStatus::Cleared)
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
            total_dispute_bond_atomic: self
                .slh_dsa_disputes
                .values()
                .map(|dispute| dispute.dispute_bond_atomic)
                .sum(),
            total_reward_atomic: self
                .slh_dsa_disputes
                .values()
                .filter(|dispute| {
                    matches!(
                        dispute.status,
                        DisputeStatus::Accepted | DisputeStatus::Batched | DisputeStatus::Settled
                    )
                })
                .map(|dispute| dispute.reward_atomic)
                .sum(),
            total_batch_fee_micro_units: self
                .low_fee_challenge_batches
                .values()
                .map(|batch| batch.batch_fee_micro_units)
                .sum(),
            total_batched_disputes: self
                .low_fee_challenge_batches
                .values()
                .map(|batch| batch.dispute_ids.len() as u64)
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
        let dispute_window_root = record_root(
            "dispute-windows",
            self.dispute_windows
                .values()
                .map(DisputeWindow::public_record)
                .collect(),
        );
        let slh_dsa_dispute_root = record_root(
            "slh-dsa-disputes",
            self.slh_dsa_disputes
                .values()
                .map(SlhDsaDispute::public_record)
                .collect(),
        );
        let dispute_evidence_root = record_root(
            "dispute-evidence",
            self.dispute_evidence
                .values()
                .map(DisputeEvidence::public_record)
                .collect(),
        );
        let low_fee_challenge_batch_root = record_root(
            "low-fee-challenge-batches",
            self.low_fee_challenge_batches
                .values()
                .map(LowFeeChallengeBatch::public_record)
                .collect(),
        );
        let private_accounting_root = value_root(
            "private-accounting",
            &json!({
                "exit_nullifier_entry_root": exit_nullifier_entry_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "dispute_window_root": dispute_window_root,
                "slh_dsa_dispute_root": slh_dsa_dispute_root,
                "dispute_evidence_root": dispute_evidence_root,
                "low_fee_challenge_batch_root": low_fee_challenge_batch_root,
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
                "dispute_window_root": dispute_window_root,
                "slh_dsa_dispute_root": slh_dsa_dispute_root,
                "dispute_evidence_root": dispute_evidence_root,
                "low_fee_challenge_batch_root": low_fee_challenge_batch_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-NULLIFIER-DISPUTE-STATE",
            &[
                HashPart::Json(&json!(self.config)),
                HashPart::Json(&json!(self.counters)),
                HashPart::Str(&exit_nullifier_entry_root),
                HashPart::Str(&pq_receipt_commitment_root),
                HashPart::Str(&dispute_window_root),
                HashPart::Str(&slh_dsa_dispute_root),
                HashPart::Str(&dispute_evidence_root),
                HashPart::Str(&low_fee_challenge_batch_root),
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
            dispute_window_root,
            slh_dsa_dispute_root,
            dispute_evidence_root,
            low_fee_challenge_batch_root,
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
            dispute_windows: BTreeMap::new(),
            slh_dsa_disputes: BTreeMap::new(),
            dispute_evidence: BTreeMap::new(),
            low_fee_challenge_batches: BTreeMap::new(),
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
        "slh_dsa_exit_nullifier_suite": SLH_DSA_EXIT_NULLIFIER_SUITE,
        "pq_receipt_commitment_suite": PQ_RECEIPT_COMMITMENT_SUITE,
        "dispute_window_suite": DISPUTE_WINDOW_SUITE,
        "dispute_bond_suite": DISPUTE_BOND_SUITE,
        "low_fee_challenge_batch_suite": LOW_FEE_CHALLENGE_BATCH_SUITE,
        "private_record_api_suite": PRIVATE_RECORD_API_SUITE,
        "config": json!(state.config),
        "counters": json!(state.counters),
        "roots": json!(state.roots),
        "exit_nullifier_entries": state
            .exit_nullifier_entries
            .values()
            .map(ExitNullifierEntry::public_record)
            .collect::<Vec<_>>(),
        "pq_receipt_commitments": state
            .pq_receipt_commitments
            .values()
            .map(PqReceiptCommitment::public_record)
            .collect::<Vec<_>>(),
        "dispute_windows": state
            .dispute_windows
            .values()
            .map(DisputeWindow::public_record)
            .collect::<Vec<_>>(),
        "slh_dsa_disputes": state
            .slh_dsa_disputes
            .values()
            .map(SlhDsaDispute::public_record)
            .collect::<Vec<_>>(),
        "dispute_evidence": state
            .dispute_evidence
            .values()
            .map(DisputeEvidence::public_record)
            .collect::<Vec<_>>(),
        "low_fee_challenge_batches": state
            .low_fee_challenge_batches
            .values()
            .map(LowFeeChallengeBatch::public_record)
            .collect::<Vec<_>>(),
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-NULLIFIER-DISPUTE-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-NULLIFIER-DISPUTE-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-NULLIFIER-DISPUTE-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-EXIT-NULLIFIER-DISPUTE-{domain}"),
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
