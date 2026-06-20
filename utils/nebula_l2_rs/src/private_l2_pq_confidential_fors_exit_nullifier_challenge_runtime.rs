use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialForsExitNullifierChallengeRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_FORS_EXIT_NULLIFIER_CHALLENGE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-fors-exit-nullifier-challenge-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_FORS_EXIT_NULLIFIER_CHALLENGE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FORS_NULLIFIER_SUITE: &str = "fors-sphincs-plus-exit-nullifier-challenge-v1";
pub const SPHINCS_PLUS_RECEIPT_SUITE: &str =
    "sphincs-plus-pq-confidential-exit-receipt-commitment-v1";
pub const NULLIFIER_CHALLENGE_WINDOW_SUITE: &str =
    "confidential-fors-exit-nullifier-challenge-window-v1";
pub const LOW_FEE_CHALLENGE_BATCH_SUITE: &str = "low-fee-fors-exit-nullifier-challenge-batch-v1";
pub const PRIVATE_RECORD_API_SUITE: &str =
    "privacy-preserving-fors-exit-nullifier-public-record-state-root-v1";
pub const DEVNET_HEIGHT: u64 = 8_680_000;
pub const DEVNET_EPOCH: u64 = 36_168;
pub const DEVNET_SLOT: u64 = 384;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_FORS_HEIGHT: u8 = 14;
pub const DEFAULT_FORS_TREES: u16 = 33;
pub const DEFAULT_FORS_MESSAGE_DIGEST_BYTES: u16 = 64;
pub const DEFAULT_FORS_AUTH_PATH_CAP: u16 = 462;
pub const DEFAULT_NULLIFIER_BUCKETS: u32 = 131_072;
pub const DEFAULT_NULLIFIER_CHALLENGE_WINDOW_SLOTS: u64 = 2_880;
pub const DEFAULT_EVIDENCE_GRACE_SLOTS: u64 = 720;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 1_200;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 40;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 28_000_000_000;
pub const DEFAULT_CHALLENGE_BOND_ATOMIC: u64 = 1_800_000_000;
pub const DEFAULT_SUCCESS_REWARD_BPS: u16 = 1_400;
pub const DEFAULT_NULLIFIER_REPAIR_BPS: u16 = 8_600;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 896;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 110;
pub const DEFAULT_EPOCH_BUCKET_TARGET_EXITS: u64 = 36_864;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitNullifierStatus {
    Pending,
    ReceiptCommitted,
    WindowOpen,
    Challenged,
    Cleared,
    Quarantined,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Committed,
    Windowed,
    Challenged,
    Superseded,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    DuplicateNullifier,
    ForgedForsLeaf,
    InvalidForsAuthPath,
    SphincsReceiptMismatch,
    NullifierBucketOmission,
    StateRootDrift,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::ForgedForsLeaf => "forged_fors_leaf",
            Self::InvalidForsAuthPath => "invalid_fors_auth_path",
            Self::SphincsReceiptMismatch => "sphincs_receipt_mismatch",
            Self::NullifierBucketOmission => "nullifier_bucket_omission",
            Self::StateRootDrift => "state_root_drift",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
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
    pub fors_nullifier_suite: String,
    pub sphincs_plus_receipt_suite: String,
    pub nullifier_challenge_window_suite: String,
    pub low_fee_challenge_batch_suite: String,
    pub private_record_api_suite: String,
    pub min_pq_security_bits: u16,
    pub fors_height: u8,
    pub fors_trees: u16,
    pub fors_message_digest_bytes: u16,
    pub fors_auth_path_cap: u16,
    pub nullifier_buckets: u32,
    pub nullifier_challenge_window_slots: u64,
    pub evidence_grace_slots: u64,
    pub settlement_delay_slots: u64,
    pub receipt_retention_epochs: u64,
    pub exit_bond_atomic: u64,
    pub challenge_bond_atomic: u64,
    pub success_reward_bps: u16,
    pub nullifier_repair_bps: u16,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_exits: u64,
    pub pq_receipt_commitments_required: bool,
    pub fors_auth_paths_required: bool,
    pub nullifier_windows_required: bool,
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
            fors_nullifier_suite: FORS_NULLIFIER_SUITE.to_string(),
            sphincs_plus_receipt_suite: SPHINCS_PLUS_RECEIPT_SUITE.to_string(),
            nullifier_challenge_window_suite: NULLIFIER_CHALLENGE_WINDOW_SUITE.to_string(),
            low_fee_challenge_batch_suite: LOW_FEE_CHALLENGE_BATCH_SUITE.to_string(),
            private_record_api_suite: PRIVATE_RECORD_API_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            fors_height: DEFAULT_FORS_HEIGHT,
            fors_trees: DEFAULT_FORS_TREES,
            fors_message_digest_bytes: DEFAULT_FORS_MESSAGE_DIGEST_BYTES,
            fors_auth_path_cap: DEFAULT_FORS_AUTH_PATH_CAP,
            nullifier_buckets: DEFAULT_NULLIFIER_BUCKETS,
            nullifier_challenge_window_slots: DEFAULT_NULLIFIER_CHALLENGE_WINDOW_SLOTS,
            evidence_grace_slots: DEFAULT_EVIDENCE_GRACE_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            challenge_bond_atomic: DEFAULT_CHALLENGE_BOND_ATOMIC,
            success_reward_bps: DEFAULT_SUCCESS_REWARD_BPS,
            nullifier_repair_bps: DEFAULT_NULLIFIER_REPAIR_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_exits: DEFAULT_EPOCH_BUCKET_TARGET_EXITS,
            pq_receipt_commitments_required: true,
            fors_auth_paths_required: true,
            nullifier_windows_required: true,
            low_fee_batching_enabled: true,
            privacy_preserving_public_records_required: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below fors nullifier minimum".to_string());
        }
        if self.fors_height < 8 || self.fors_height > 20 || self.fors_trees == 0 {
            return Err("invalid fors tree schedule".to_string());
        }
        if self.fors_message_digest_bytes < 32 || self.fors_auth_path_cap == 0 {
            return Err("invalid fors digest or auth path policy".to_string());
        }
        if self.nullifier_buckets == 0 || self.epoch_bucket_target_exits == 0 {
            return Err("nullifier buckets and epoch target exits must be positive".to_string());
        }
        if self.nullifier_challenge_window_slots == 0
            || self.evidence_grace_slots == 0
            || self.settlement_delay_slots == 0
        {
            return Err("nullifier challenge windows must be positive".to_string());
        }
        if self.exit_bond_atomic == 0 || self.challenge_bond_atomic == 0 {
            return Err("fors challenge bonds must be positive".to_string());
        }
        if u32::from(self.success_reward_bps) + u32::from(self.nullifier_repair_bps) != 10_000 {
            return Err("fors nullifier reward basis points must sum to 10000".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
            || self.max_batch_fee_micro_units == 0
        {
            return Err("invalid low-fee fors challenge batching policy".to_string());
        }
        if !self.pq_receipt_commitments_required
            || !self.fors_auth_paths_required
            || !self.nullifier_windows_required
            || !self.privacy_preserving_public_records_required
        {
            return Err("fors nullifier privacy and evidence gates are mandatory".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub exit_nullifier_intents: u64,
    pub pq_receipt_commitments: u64,
    pub nullifier_challenge_windows: u64,
    pub fors_challenges: u64,
    pub fors_evidence: u64,
    pub low_fee_challenge_batches: u64,
    pub challenged_nullifiers: u64,
    pub cleared_nullifiers: u64,
    pub quarantined_nullifiers: u64,
    pub finalized_nullifiers: u64,
    pub total_exit_bond_atomic: u64,
    pub total_challenge_bond_atomic: u64,
    pub total_reward_atomic: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_batched_challenges: u64,
}

impl Counters {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub exit_nullifier_intent_root: String,
    pub pq_receipt_commitment_root: String,
    pub nullifier_challenge_window_root: String,
    pub fors_challenge_root: String,
    pub fors_evidence_root: String,
    pub low_fee_challenge_batch_root: String,
    pub private_accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitNullifierIntentInput {
    pub account_commitment: String,
    pub exit_nullifier: String,
    pub fors_public_root: String,
    pub sphincs_public_root: String,
    pub encrypted_destination_root: String,
    pub nullifier_bucket: u32,
    pub epoch: u64,
    pub requested_slot: u64,
    pub exit_bond_atomic: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitmentInput {
    pub exit_intent_id: String,
    pub receipt_commitment_root: String,
    pub sphincs_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_nullifier: String,
    pub observed_state_root: String,
    pub committed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierChallengeWindowInput {
    pub exit_intent_id: String,
    pub receipt_id: String,
    pub nullifier_bucket: u32,
    pub nullifier_set_root: String,
    pub state_root: String,
    pub window_open_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForsChallengeInput {
    pub window_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub fors_tree_index: u16,
    pub fors_leaf_index: u64,
    pub disputed_nullifier_commitment: String,
    pub evidence_commitment_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForsEvidenceInput {
    pub challenge_id: String,
    pub fors_auth_path_root: String,
    pub fors_signature_digest_root: String,
    pub fors_leaf_preimage_commitment: String,
    pub nullifier_membership_witness_root: String,
    pub sphincs_receipt_transcript_root: String,
    pub state_transition_witness_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeChallengeBatchInput {
    pub sequencer_commitment: String,
    pub challenge_ids: BTreeSet<String>,
    pub aggregation_root: String,
    pub fee_sponsor_commitment: String,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitNullifierIntent {
    pub exit_intent_id: String,
    pub account_commitment: String,
    pub exit_nullifier: String,
    pub fors_public_root: String,
    pub sphincs_public_root: String,
    pub nullifier_bitmap_root: String,
    pub encrypted_destination_root: String,
    pub nullifier_bucket: u32,
    pub epoch: u64,
    pub requested_slot: u64,
    pub challenge_open_slot: u64,
    pub challenge_close_slot: u64,
    pub finality_slot: u64,
    pub exit_bond_atomic: u64,
    pub reward_locked_atomic: u64,
    pub status: ExitNullifierStatus,
}

impl ExitNullifierIntent {
    pub fn from_input(config: &Config, input: ExitNullifierIntentInput) -> Result<Self> {
        require_non_empty(&[
            (&input.account_commitment, "account commitment"),
            (&input.exit_nullifier, "exit nullifier"),
            (&input.fors_public_root, "fors public root"),
            (&input.sphincs_public_root, "sphincs public root"),
            (
                &input.encrypted_destination_root,
                "encrypted destination root",
            ),
        ])?;
        if input.nullifier_bucket >= config.nullifier_buckets {
            return Err("nullifier bucket exceeds configured bucket count".to_string());
        }
        if input.exit_bond_atomic < config.challenge_bond_atomic
            || input.exit_bond_atomic > config.exit_bond_atomic
        {
            return Err("exit bond amount outside fors nullifier policy".to_string());
        }
        let exit_intent_id = deterministic_id(
            "exit-nullifier-intent",
            &[
                HashPart::Str(&input.account_commitment),
                HashPart::Str(&input.exit_nullifier),
                HashPart::Str(&input.fors_public_root),
                HashPart::U64(u64::from(input.nullifier_bucket)),
                HashPart::U64(input.epoch),
                HashPart::U64(input.requested_slot),
            ],
        );
        let nullifier_bitmap_root = deterministic_id(
            "nullifier-bitmap",
            &[
                HashPart::Str(&exit_intent_id),
                HashPart::Str(&input.exit_nullifier),
                HashPart::U64(u64::from(input.nullifier_bucket)),
            ],
        );
        let challenge_open_slot = input.requested_slot;
        let challenge_close_slot = challenge_open_slot + config.nullifier_challenge_window_slots;
        Ok(Self {
            exit_intent_id,
            account_commitment: input.account_commitment,
            exit_nullifier: input.exit_nullifier,
            fors_public_root: input.fors_public_root,
            sphincs_public_root: input.sphincs_public_root,
            nullifier_bitmap_root,
            encrypted_destination_root: input.encrypted_destination_root,
            nullifier_bucket: input.nullifier_bucket,
            epoch: input.epoch,
            requested_slot: input.requested_slot,
            challenge_open_slot,
            challenge_close_slot,
            finality_slot: challenge_close_slot + config.settlement_delay_slots,
            exit_bond_atomic: input.exit_bond_atomic,
            reward_locked_atomic: 0,
            status: ExitNullifierStatus::Pending,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitment {
    pub receipt_id: String,
    pub exit_intent_id: String,
    pub receipt_commitment_root: String,
    pub sphincs_signature_commitment_root: String,
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
            (&input.exit_intent_id, "exit intent id"),
            (&input.receipt_commitment_root, "receipt commitment root"),
            (
                &input.sphincs_signature_commitment_root,
                "sphincs signature commitment root",
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
                HashPart::Str(&input.exit_intent_id),
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::Str(&input.receipt_nullifier),
                HashPart::Str(&input.observed_state_root),
                HashPart::U64(input.committed_slot),
            ],
        );
        let receipt_state_root = value_root(
            "pq-receipt-state",
            &json!({
                "receipt_id": receipt_id,
                "receipt_commitment_root": input.receipt_commitment_root,
                "sphincs_signature_commitment_root": input.sphincs_signature_commitment_root,
                "encrypted_receipt_payload_root": input.encrypted_receipt_payload_root,
                "observed_state_root": input.observed_state_root,
            }),
        );
        Ok(Self {
            receipt_id,
            exit_intent_id: input.exit_intent_id,
            receipt_commitment_root: input.receipt_commitment_root,
            sphincs_signature_commitment_root: input.sphincs_signature_commitment_root,
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierChallengeWindow {
    pub window_id: String,
    pub exit_intent_id: String,
    pub receipt_id: String,
    pub nullifier_bucket: u32,
    pub nullifier_set_root: String,
    pub state_root: String,
    pub window_open_slot: u64,
    pub window_close_slot: u64,
    pub evidence_deadline_slot: u64,
    pub settlement_slot: u64,
    pub status: ExitNullifierStatus,
}

impl NullifierChallengeWindow {
    pub fn from_input(config: &Config, input: NullifierChallengeWindowInput) -> Result<Self> {
        require_non_empty(&[
            (&input.exit_intent_id, "exit intent id"),
            (&input.receipt_id, "receipt id"),
            (&input.nullifier_set_root, "nullifier set root"),
            (&input.state_root, "state root"),
        ])?;
        if input.nullifier_bucket >= config.nullifier_buckets {
            return Err("nullifier bucket exceeds configured bucket count".to_string());
        }
        let window_id = deterministic_id(
            "nullifier-challenge-window",
            &[
                HashPart::Str(&input.exit_intent_id),
                HashPart::Str(&input.receipt_id),
                HashPart::U64(u64::from(input.nullifier_bucket)),
                HashPart::Str(&input.nullifier_set_root),
                HashPart::Str(&input.state_root),
            ],
        );
        let window_close_slot = input.window_open_slot + config.nullifier_challenge_window_slots;
        Ok(Self {
            window_id,
            exit_intent_id: input.exit_intent_id,
            receipt_id: input.receipt_id,
            nullifier_bucket: input.nullifier_bucket,
            nullifier_set_root: input.nullifier_set_root,
            state_root: input.state_root,
            window_open_slot: input.window_open_slot,
            window_close_slot,
            evidence_deadline_slot: window_close_slot + config.evidence_grace_slots,
            settlement_slot: window_close_slot + config.settlement_delay_slots,
            status: ExitNullifierStatus::WindowOpen,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForsChallenge {
    pub challenge_id: String,
    pub window_id: String,
    pub exit_intent_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub fors_tree_index: u16,
    pub fors_leaf_index: u64,
    pub disputed_nullifier_commitment: String,
    pub evidence_commitment_root: String,
    pub challenge_bond_commitment: String,
    pub challenge_bond_atomic: u64,
    pub reward_atomic: u64,
    pub opened_slot: u64,
    pub evidence_deadline_slot: u64,
    pub batch_id: Option<String>,
    pub status: ChallengeStatus,
}

impl ForsChallenge {
    pub fn from_input(
        config: &Config,
        window: &NullifierChallengeWindow,
        input: ForsChallengeInput,
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
        if input.fors_tree_index >= config.fors_trees {
            return Err("fors tree index exceeds configured tree count".to_string());
        }
        let max_leaf_index = 1_u64
            .checked_shl(u32::from(config.fors_height))
            .unwrap_or(0)
            .saturating_sub(1);
        if input.fors_leaf_index > max_leaf_index {
            return Err("fors leaf index exceeds configured tree height".to_string());
        }
        if input.opened_slot > window.evidence_deadline_slot {
            return Err("fors nullifier challenge opened after deadline".to_string());
        }
        let challenge_id = deterministic_id(
            "fors-nullifier-challenge",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.challenger_commitment),
                HashPart::Str(input.challenge_kind.as_str()),
                HashPart::U64(u64::from(input.fors_tree_index)),
                HashPart::U64(input.fors_leaf_index),
                HashPart::Str(&input.disputed_nullifier_commitment),
                HashPart::Str(&input.evidence_commitment_root),
            ],
        );
        let challenge_bond_commitment = deterministic_id(
            "challenge-bond-commitment",
            &[
                HashPart::Str(&challenge_id),
                HashPart::Str(&input.challenger_commitment),
            ],
        );
        Ok(Self {
            challenge_id,
            window_id: input.window_id,
            exit_intent_id: window.exit_intent_id.clone(),
            receipt_id: window.receipt_id.clone(),
            challenger_commitment: input.challenger_commitment,
            challenge_kind: input.challenge_kind,
            fors_tree_index: input.fors_tree_index,
            fors_leaf_index: input.fors_leaf_index,
            disputed_nullifier_commitment: input.disputed_nullifier_commitment,
            evidence_commitment_root: input.evidence_commitment_root,
            challenge_bond_commitment,
            challenge_bond_atomic: config.challenge_bond_atomic,
            reward_atomic: config.exit_bond_atomic * u64::from(config.success_reward_bps) / 10_000,
            opened_slot: input.opened_slot,
            evidence_deadline_slot: input.opened_slot + config.evidence_grace_slots,
            batch_id: None,
            status: ChallengeStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForsEvidence {
    pub evidence_id: String,
    pub challenge_id: String,
    pub fors_auth_path_root: String,
    pub fors_signature_digest_root: String,
    pub fors_leaf_preimage_commitment: String,
    pub nullifier_membership_witness_root: String,
    pub sphincs_receipt_transcript_root: String,
    pub state_transition_witness_root: String,
    pub replay_guard_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

impl ForsEvidence {
    pub fn from_input(input: ForsEvidenceInput) -> Result<Self> {
        require_non_empty(&[
            (&input.challenge_id, "challenge id"),
            (&input.fors_auth_path_root, "fors auth path root"),
            (
                &input.fors_signature_digest_root,
                "fors signature digest root",
            ),
            (
                &input.fors_leaf_preimage_commitment,
                "fors leaf preimage commitment",
            ),
            (
                &input.nullifier_membership_witness_root,
                "nullifier membership witness root",
            ),
            (
                &input.sphincs_receipt_transcript_root,
                "sphincs receipt transcript root",
            ),
            (
                &input.state_transition_witness_root,
                "state transition witness root",
            ),
        ])?;
        let evidence_id = deterministic_id(
            "fors-evidence",
            &[
                HashPart::Str(&input.challenge_id),
                HashPart::Str(&input.fors_auth_path_root),
                HashPart::Str(&input.fors_signature_digest_root),
                HashPart::Str(&input.nullifier_membership_witness_root),
                HashPart::Str(&input.sphincs_receipt_transcript_root),
            ],
        );
        let replay_guard_root = deterministic_id(
            "fors-evidence-replay-guard",
            &[
                HashPart::Str(&evidence_id),
                HashPart::Str(&input.fors_leaf_preimage_commitment),
                HashPart::Str(&input.state_transition_witness_root),
            ],
        );
        Ok(Self {
            evidence_id,
            challenge_id: input.challenge_id,
            fors_auth_path_root: input.fors_auth_path_root,
            fors_signature_digest_root: input.fors_signature_digest_root,
            fors_leaf_preimage_commitment: input.fors_leaf_preimage_commitment,
            nullifier_membership_witness_root: input.nullifier_membership_witness_root,
            sphincs_receipt_transcript_root: input.sphincs_receipt_transcript_root,
            state_transition_witness_root: input.state_transition_witness_root,
            replay_guard_root,
            accepted: input.accepted,
            anchored_slot: input.anchored_slot,
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
    pub challenge_ids: BTreeSet<String>,
    pub exit_intent_ids: BTreeSet<String>,
    pub aggregate_challenge_root: String,
    pub aggregate_evidence_root: String,
    pub aggregation_root: String,
    pub fee_sponsor_commitment: String,
    pub batch_fee_micro_units: u64,
    pub per_challenge_fee_micro_units: u64,
    pub posted_slot: u64,
    pub status: BatchStatus,
}

impl LowFeeChallengeBatch {
    pub fn from_input(
        config: &Config,
        challenges: &BTreeMap<String, ForsChallenge>,
        input: LowFeeChallengeBatchInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.sequencer_commitment, "sequencer commitment"),
            (&input.aggregation_root, "aggregation root"),
            (&input.fee_sponsor_commitment, "fee sponsor commitment"),
        ])?;
        if input.challenge_ids.len() < usize::from(config.min_batch_size)
            || input.challenge_ids.len() > usize::from(config.low_fee_batch_limit)
        {
            return Err("low-fee fors challenge batch size outside policy".to_string());
        }
        if input.batch_fee_micro_units > config.max_batch_fee_micro_units {
            return Err("low-fee fors challenge batch fee exceeds cap".to_string());
        }
        let exit_intent_ids = input
            .challenge_ids
            .iter()
            .map(|challenge_id| {
                challenges
                    .get(challenge_id)
                    .map(|challenge| challenge.exit_intent_id.clone())
                    .ok_or_else(|| format!("batch references unknown challenge {challenge_id}"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let batch_id = deterministic_id(
            "low-fee-fors-challenge-batch",
            &[
                HashPart::Str(&input.sequencer_commitment),
                HashPart::Str(&input.aggregation_root),
                HashPart::Str(&input.fee_sponsor_commitment),
                HashPart::U64(input.challenge_ids.len() as u64),
                HashPart::U64(input.posted_slot),
            ],
        );
        let per_challenge_fee_micro_units =
            input.batch_fee_micro_units / input.challenge_ids.len() as u64;
        Ok(Self {
            batch_id,
            sequencer_commitment: input.sequencer_commitment,
            challenge_ids: input.challenge_ids,
            exit_intent_ids,
            aggregate_challenge_root: sample_root("aggregate-fors-challenge", input.posted_slot),
            aggregate_evidence_root: sample_root("aggregate-fors-evidence", input.posted_slot),
            aggregation_root: input.aggregation_root,
            fee_sponsor_commitment: input.fee_sponsor_commitment,
            batch_fee_micro_units: input.batch_fee_micro_units,
            per_challenge_fee_micro_units,
            posted_slot: input.posted_slot,
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
    pub exit_nullifier_intents: BTreeMap<String, ExitNullifierIntent>,
    pub pq_receipt_commitments: BTreeMap<String, PqReceiptCommitment>,
    pub nullifier_challenge_windows: BTreeMap<String, NullifierChallengeWindow>,
    pub fors_challenges: BTreeMap<String, ForsChallenge>,
    pub fors_evidence: BTreeMap<String, ForsEvidence>,
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

    pub fn register_exit_nullifier_intent(
        &mut self,
        input: ExitNullifierIntentInput,
    ) -> Result<String> {
        self.config.validate()?;
        let intent = ExitNullifierIntent::from_input(&self.config, input)?;
        if self
            .exit_nullifier_intents
            .contains_key(&intent.exit_intent_id)
        {
            return Err("exit nullifier intent already exists".to_string());
        }
        if self
            .exit_nullifier_intents
            .values()
            .any(|existing| existing.exit_nullifier == intent.exit_nullifier)
        {
            return Err("exit nullifier already registered".to_string());
        }
        let exit_intent_id = intent.exit_intent_id.clone();
        self.exit_nullifier_intents
            .insert(exit_intent_id.clone(), intent);
        self.refresh();
        Ok(exit_intent_id)
    }

    pub fn commit_pq_receipt(&mut self, input: PqReceiptCommitmentInput) -> Result<String> {
        if !self
            .exit_nullifier_intents
            .contains_key(&input.exit_intent_id)
        {
            return Err("pq receipt references unknown exit nullifier intent".to_string());
        }
        let receipt = PqReceiptCommitment::from_input(&self.config, self.epoch, input)?;
        if self
            .pq_receipt_commitments
            .contains_key(&receipt.receipt_id)
        {
            return Err("pq receipt commitment already exists".to_string());
        }
        if let Some(intent) = self.exit_nullifier_intents.get_mut(&receipt.exit_intent_id) {
            intent.status = ExitNullifierStatus::ReceiptCommitted;
        }
        let receipt_id = receipt.receipt_id.clone();
        self.pq_receipt_commitments
            .insert(receipt_id.clone(), receipt);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn open_nullifier_challenge_window(
        &mut self,
        input: NullifierChallengeWindowInput,
    ) -> Result<String> {
        let intent = self
            .exit_nullifier_intents
            .get(&input.exit_intent_id)
            .ok_or_else(|| "window references unknown exit nullifier intent".to_string())?;
        if intent.nullifier_bucket != input.nullifier_bucket {
            return Err("window nullifier bucket does not match exit intent".to_string());
        }
        if input.window_open_slot < intent.challenge_open_slot
            || input.window_open_slot > intent.challenge_close_slot
        {
            return Err("nullifier challenge window opened outside intent window".to_string());
        }
        let receipt = self
            .pq_receipt_commitments
            .get(&input.receipt_id)
            .ok_or_else(|| "window references unknown pq receipt".to_string())?;
        if receipt.exit_intent_id != input.exit_intent_id {
            return Err("window receipt does not match exit intent".to_string());
        }
        let window = NullifierChallengeWindow::from_input(&self.config, input)?;
        if self
            .nullifier_challenge_windows
            .contains_key(&window.window_id)
        {
            return Err("nullifier challenge window already exists".to_string());
        }
        if let Some(intent) = self.exit_nullifier_intents.get_mut(&window.exit_intent_id) {
            intent.status = ExitNullifierStatus::WindowOpen;
        }
        if let Some(receipt) = self.pq_receipt_commitments.get_mut(&window.receipt_id) {
            receipt.status = ReceiptStatus::Windowed;
        }
        let window_id = window.window_id.clone();
        self.nullifier_challenge_windows
            .insert(window_id.clone(), window);
        self.refresh();
        Ok(window_id)
    }

    pub fn submit_fors_challenge(&mut self, input: ForsChallengeInput) -> Result<String> {
        let window = self
            .nullifier_challenge_windows
            .get(&input.window_id)
            .ok_or_else(|| "fors challenge references unknown window".to_string())?;
        let challenge = ForsChallenge::from_input(&self.config, window, input)?;
        if self.fors_challenges.contains_key(&challenge.challenge_id) {
            return Err("fors nullifier challenge already exists".to_string());
        }
        if let Some(intent) = self
            .exit_nullifier_intents
            .get_mut(&challenge.exit_intent_id)
        {
            intent.status = ExitNullifierStatus::Challenged;
            intent.reward_locked_atomic = intent
                .reward_locked_atomic
                .saturating_add(challenge.reward_atomic);
        }
        if let Some(receipt) = self.pq_receipt_commitments.get_mut(&challenge.receipt_id) {
            receipt.status = ReceiptStatus::Challenged;
        }
        if let Some(window) = self
            .nullifier_challenge_windows
            .get_mut(&challenge.window_id)
        {
            window.status = ExitNullifierStatus::Challenged;
        }
        let challenge_id = challenge.challenge_id.clone();
        self.fors_challenges.insert(challenge_id.clone(), challenge);
        self.refresh();
        Ok(challenge_id)
    }

    pub fn anchor_fors_evidence(&mut self, input: ForsEvidenceInput) -> Result<String> {
        let challenge = self
            .fors_challenges
            .get(&input.challenge_id)
            .ok_or_else(|| "fors evidence references unknown challenge".to_string())?;
        if input.anchored_slot > challenge.evidence_deadline_slot {
            return Err("fors evidence anchored after evidence deadline".to_string());
        }
        let evidence = ForsEvidence::from_input(input)?;
        if self.fors_evidence.contains_key(&evidence.evidence_id) {
            return Err("fors evidence already exists".to_string());
        }
        if let Some(challenge) = self.fors_challenges.get_mut(&evidence.challenge_id) {
            challenge.status = ChallengeStatus::EvidenceAnchored;
            challenge.status = if evidence.accepted {
                ChallengeStatus::Accepted
            } else {
                ChallengeStatus::Rejected
            };
        }
        let challenge = self
            .fors_challenges
            .get(&evidence.challenge_id)
            .ok_or_else(|| "fors evidence lost challenge reference".to_string())?;
        if evidence.accepted {
            if let Some(intent) = self
                .exit_nullifier_intents
                .get_mut(&challenge.exit_intent_id)
            {
                intent.status = ExitNullifierStatus::Quarantined;
            }
            if let Some(receipt) = self.pq_receipt_commitments.get_mut(&challenge.receipt_id) {
                receipt.status = ReceiptStatus::Superseded;
            }
            if let Some(window) = self
                .nullifier_challenge_windows
                .get_mut(&challenge.window_id)
            {
                window.status = ExitNullifierStatus::Quarantined;
            }
        } else if let Some(intent) = self
            .exit_nullifier_intents
            .get_mut(&challenge.exit_intent_id)
        {
            intent.status = ExitNullifierStatus::Cleared;
        }
        let evidence_id = evidence.evidence_id.clone();
        self.fors_evidence.insert(evidence_id.clone(), evidence);
        self.refresh();
        Ok(evidence_id)
    }

    pub fn post_low_fee_challenge_batch(
        &mut self,
        input: LowFeeChallengeBatchInput,
    ) -> Result<String> {
        let batch = LowFeeChallengeBatch::from_input(&self.config, &self.fors_challenges, input)?;
        if self.low_fee_challenge_batches.contains_key(&batch.batch_id) {
            return Err("low-fee fors challenge batch already exists".to_string());
        }
        for challenge_id in &batch.challenge_ids {
            if let Some(challenge) = self.fors_challenges.get_mut(challenge_id) {
                challenge.status = ChallengeStatus::Batched;
                challenge.batch_id = Some(batch.batch_id.clone());
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
            .ok_or_else(|| "unknown low-fee fors challenge batch".to_string())?;
        batch.status = BatchStatus::Settled;
        for challenge_id in &batch.challenge_ids {
            if let Some(challenge) = self.fors_challenges.get_mut(challenge_id) {
                challenge.status = ChallengeStatus::Settled;
                if let Some(intent) = self
                    .exit_nullifier_intents
                    .get_mut(&challenge.exit_intent_id)
                {
                    if intent.status == ExitNullifierStatus::Quarantined {
                        intent.reward_locked_atomic = intent
                            .reward_locked_atomic
                            .saturating_sub(challenge.reward_atomic);
                    }
                }
            }
        }
        self.refresh();
        Ok(())
    }

    pub fn finalize_window(&mut self, window_id: &str, finalized_slot: u64) -> Result<()> {
        let window = self
            .nullifier_challenge_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown nullifier challenge window".to_string())?;
        if finalized_slot < window.settlement_slot {
            return Err("nullifier challenge window cannot finalize before settlement".to_string());
        }
        let has_accepted_challenge = self.fors_challenges.values().any(|challenge| {
            challenge.window_id == window.window_id
                && matches!(
                    challenge.status,
                    ChallengeStatus::Accepted | ChallengeStatus::Batched | ChallengeStatus::Settled
                )
        });
        if has_accepted_challenge {
            return Err("nullifier challenge window has accepted challenge".to_string());
        }
        window.status = ExitNullifierStatus::Finalized;
        if let Some(intent) = self.exit_nullifier_intents.get_mut(&window.exit_intent_id) {
            intent.status = ExitNullifierStatus::Finalized;
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
        let mut challenge_ids = BTreeSet::new();
        for index in 0_u64..8 {
            let exit_intent_id = self
                .register_exit_nullifier_intent(ExitNullifierIntentInput {
                    account_commitment: sample_root("account-commitment", index),
                    exit_nullifier: sample_root("exit-nullifier", index),
                    fors_public_root: sample_root("fors-public-root", index),
                    sphincs_public_root: sample_root("sphincs-public-root", index),
                    encrypted_destination_root: sample_root("encrypted-destination", index),
                    nullifier_bucket: (index as u32) % self.config.nullifier_buckets,
                    epoch: self.epoch,
                    requested_slot: self.slot + index * 7,
                    exit_bond_atomic: self.config.exit_bond_atomic,
                })
                .expect("devnet fors exit nullifier intent must register");
            let receipt_id = self
                .commit_pq_receipt(PqReceiptCommitmentInput {
                    exit_intent_id: exit_intent_id.clone(),
                    receipt_commitment_root: sample_root("pq-receipt-commitment", index),
                    sphincs_signature_commitment_root: sample_root(
                        "sphincs-signature-commitment",
                        index,
                    ),
                    encrypted_receipt_payload_root: sample_root("encrypted-receipt", index),
                    receipt_nullifier: sample_root("receipt-nullifier", index),
                    observed_state_root: sample_root("observed-state-root", index),
                    committed_slot: self.slot + index * 7 + 1,
                })
                .expect("devnet pq receipt must commit");
            let window_id = self
                .open_nullifier_challenge_window(NullifierChallengeWindowInput {
                    exit_intent_id: exit_intent_id.clone(),
                    receipt_id: receipt_id.clone(),
                    nullifier_bucket: (index as u32) % self.config.nullifier_buckets,
                    nullifier_set_root: sample_root("nullifier-set-root", index),
                    state_root: sample_root("challenge-window-state", index),
                    window_open_slot: self.slot + index * 7 + 2,
                })
                .expect("devnet nullifier challenge window must open");
            if index % 2 == 0 {
                let challenge_id = self
                    .submit_fors_challenge(ForsChallengeInput {
                        window_id,
                        challenger_commitment: sample_root("challenger", index),
                        challenge_kind: match index {
                            0 => ChallengeKind::DuplicateNullifier,
                            2 => ChallengeKind::InvalidForsAuthPath,
                            4 => ChallengeKind::SphincsReceiptMismatch,
                            _ => ChallengeKind::StateRootDrift,
                        },
                        fors_tree_index: (index as u16) % self.config.fors_trees,
                        fors_leaf_index: index * 17,
                        disputed_nullifier_commitment: sample_root("disputed-nullifier", index),
                        evidence_commitment_root: sample_root("evidence-commitment", index),
                        opened_slot: self.slot + index * 7 + 8,
                    })
                    .expect("devnet fors challenge must submit");
                self.anchor_fors_evidence(ForsEvidenceInput {
                    challenge_id: challenge_id.clone(),
                    fors_auth_path_root: sample_root("fors-auth-path", index),
                    fors_signature_digest_root: sample_root("fors-signature-digest", index),
                    fors_leaf_preimage_commitment: sample_root("fors-leaf-preimage", index),
                    nullifier_membership_witness_root: sample_root("nullifier-membership", index),
                    sphincs_receipt_transcript_root: sample_root("sphincs-transcript", index),
                    state_transition_witness_root: sample_root("state-transition-witness", index),
                    accepted: index != 4,
                    anchored_slot: self.slot + index * 7 + 18,
                })
                .expect("devnet fors evidence must anchor");
                if index != 4 {
                    challenge_ids.insert(challenge_id);
                }
            }
        }
        if challenge_ids.len() >= usize::from(self.config.min_batch_size) {
            let batch_id = self
                .post_low_fee_challenge_batch(LowFeeChallengeBatchInput {
                    sequencer_commitment: sample_root("challenge-batch-sequencer", 0),
                    challenge_ids,
                    aggregation_root: sample_root("challenge-batch-aggregation", 0),
                    fee_sponsor_commitment: sample_root("batch-fee-sponsor", 0),
                    batch_fee_micro_units: self.config.max_batch_fee_micro_units / 2,
                    posted_slot: self.slot + 224,
                })
                .expect("devnet low-fee fors challenge batch must post");
            self.settle_low_fee_challenge_batch(&batch_id)
                .expect("devnet low-fee fors challenge batch must settle");
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            exit_nullifier_intents: self.exit_nullifier_intents.len() as u64,
            pq_receipt_commitments: self.pq_receipt_commitments.len() as u64,
            nullifier_challenge_windows: self.nullifier_challenge_windows.len() as u64,
            fors_challenges: self.fors_challenges.len() as u64,
            fors_evidence: self.fors_evidence.len() as u64,
            low_fee_challenge_batches: self.low_fee_challenge_batches.len() as u64,
            challenged_nullifiers: self
                .exit_nullifier_intents
                .values()
                .filter(|intent| intent.status == ExitNullifierStatus::Challenged)
                .count() as u64,
            cleared_nullifiers: self
                .exit_nullifier_intents
                .values()
                .filter(|intent| intent.status == ExitNullifierStatus::Cleared)
                .count() as u64,
            quarantined_nullifiers: self
                .exit_nullifier_intents
                .values()
                .filter(|intent| intent.status == ExitNullifierStatus::Quarantined)
                .count() as u64,
            finalized_nullifiers: self
                .exit_nullifier_intents
                .values()
                .filter(|intent| intent.status == ExitNullifierStatus::Finalized)
                .count() as u64,
            total_exit_bond_atomic: self
                .exit_nullifier_intents
                .values()
                .map(|intent| intent.exit_bond_atomic)
                .sum(),
            total_challenge_bond_atomic: self
                .fors_challenges
                .values()
                .map(|challenge| challenge.challenge_bond_atomic)
                .sum(),
            total_reward_atomic: self
                .fors_challenges
                .values()
                .filter(|challenge| {
                    matches!(
                        challenge.status,
                        ChallengeStatus::Accepted
                            | ChallengeStatus::Batched
                            | ChallengeStatus::Settled
                    )
                })
                .map(|challenge| challenge.reward_atomic)
                .sum(),
            total_batch_fee_micro_units: self
                .low_fee_challenge_batches
                .values()
                .map(|batch| batch.batch_fee_micro_units)
                .sum(),
            total_batched_challenges: self
                .low_fee_challenge_batches
                .values()
                .map(|batch| batch.challenge_ids.len() as u64)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let exit_nullifier_intent_root = record_root(
            "exit-nullifier-intents",
            self.exit_nullifier_intents
                .values()
                .map(|intent| json!(intent))
                .collect(),
        );
        let pq_receipt_commitment_root = record_root(
            "pq-receipt-commitments",
            self.pq_receipt_commitments
                .values()
                .map(|receipt| json!(receipt))
                .collect(),
        );
        let nullifier_challenge_window_root = record_root(
            "nullifier-challenge-windows",
            self.nullifier_challenge_windows
                .values()
                .map(|window| json!(window))
                .collect(),
        );
        let fors_challenge_root = record_root(
            "fors-challenges",
            self.fors_challenges
                .values()
                .map(|challenge| json!(challenge))
                .collect(),
        );
        let fors_evidence_root = record_root(
            "fors-evidence",
            self.fors_evidence
                .values()
                .map(|evidence| json!(evidence))
                .collect(),
        );
        let low_fee_challenge_batch_root = record_root(
            "low-fee-challenge-batches",
            self.low_fee_challenge_batches
                .values()
                .map(|batch| json!(batch))
                .collect(),
        );
        let private_accounting_root = value_root(
            "private-accounting",
            &json!({
                "exit_nullifier_intent_root": exit_nullifier_intent_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "nullifier_challenge_window_root": nullifier_challenge_window_root,
                "fors_challenge_root": fors_challenge_root,
                "fors_evidence_root": fors_evidence_root,
                "low_fee_challenge_batch_root": low_fee_challenge_batch_root,
                "redacted_totals": json!(self.counters),
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": json!(self.config),
                "counters": json!(self.counters),
                "exit_nullifier_intent_root": exit_nullifier_intent_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "nullifier_challenge_window_root": nullifier_challenge_window_root,
                "fors_challenge_root": fors_challenge_root,
                "fors_evidence_root": fors_evidence_root,
                "low_fee_challenge_batch_root": low_fee_challenge_batch_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-FORS-EXIT-NULLIFIER-CHALLENGE-STATE",
            &[
                HashPart::Json(&json!(self.config)),
                HashPart::Json(&json!(self.counters)),
                HashPart::Str(&exit_nullifier_intent_root),
                HashPart::Str(&pq_receipt_commitment_root),
                HashPart::Str(&nullifier_challenge_window_root),
                HashPart::Str(&fors_challenge_root),
                HashPart::Str(&fors_evidence_root),
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
            exit_nullifier_intent_root,
            pq_receipt_commitment_root,
            nullifier_challenge_window_root,
            fors_challenge_root,
            fors_evidence_root,
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
            exit_nullifier_intents: BTreeMap::new(),
            pq_receipt_commitments: BTreeMap::new(),
            nullifier_challenge_windows: BTreeMap::new(),
            fors_challenges: BTreeMap::new(),
            fors_evidence: BTreeMap::new(),
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
        "fors_nullifier_suite": FORS_NULLIFIER_SUITE,
        "sphincs_plus_receipt_suite": SPHINCS_PLUS_RECEIPT_SUITE,
        "nullifier_challenge_window_suite": NULLIFIER_CHALLENGE_WINDOW_SUITE,
        "low_fee_challenge_batch_suite": LOW_FEE_CHALLENGE_BATCH_SUITE,
        "private_record_api_suite": PRIVATE_RECORD_API_SUITE,
        "config": json!(state.config),
        "counters": json!(state.counters),
        "roots": json!(state.roots),
        "exit_nullifier_intents": state
            .exit_nullifier_intents
            .values()
            .map(|intent| json!(intent))
            .collect::<Vec<_>>(),
        "pq_receipt_commitments": state
            .pq_receipt_commitments
            .values()
            .map(|receipt| json!(receipt))
            .collect::<Vec<_>>(),
        "nullifier_challenge_windows": state
            .nullifier_challenge_windows
            .values()
            .map(|window| json!(window))
            .collect::<Vec<_>>(),
        "fors_challenges": state
            .fors_challenges
            .values()
            .map(|challenge| json!(challenge))
            .collect::<Vec<_>>(),
        "fors_evidence": state
            .fors_evidence
            .values()
            .map(|evidence| json!(evidence))
            .collect::<Vec<_>>(),
        "low_fee_challenge_batches": state
            .low_fee_challenge_batches
            .values()
            .map(|batch| json!(batch))
            .collect::<Vec<_>>(),
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FORS-EXIT-NULLIFIER-CHALLENGE-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-FORS-EXIT-NULLIFIER-CHALLENGE-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FORS-EXIT-NULLIFIER-CHALLENGE-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FORS-EXIT-NULLIFIER-CHALLENGE-{domain}"),
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
