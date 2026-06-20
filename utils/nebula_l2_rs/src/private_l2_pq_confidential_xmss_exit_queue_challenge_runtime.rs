use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialXmssExitQueueChallengeRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_XMSS_EXIT_QUEUE_CHALLENGE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-xmss-exit-queue-challenge-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_XMSS_EXIT_QUEUE_CHALLENGE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const XMSS_EXIT_QUEUE_SUITE: &str = "xmss-hash-based-exit-queue-challenge-v1";
pub const PQ_RECEIPT_COMMITMENT_SUITE: &str = "pq-confidential-exit-queue-receipt-commitment-v1";
pub const QUEUE_FINALITY_CHALLENGE_WINDOW_SUITE: &str =
    "confidential-exit-queue-finality-challenge-window-v1";
pub const LOW_FEE_CHALLENGE_BATCH_SUITE: &str = "low-fee-xmss-exit-queue-challenge-batch-v1";
pub const PRIVATE_RECORD_API_SUITE: &str =
    "privacy-preserving-xmss-exit-queue-public-record-state-root-v1";
pub const DEVNET_HEIGHT: u64 = 8_648_000;
pub const DEVNET_EPOCH: u64 = 36_084;
pub const DEVNET_SLOT: u64 = 288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_XMSS_TREE_HEIGHT: u8 = 20;
pub const DEFAULT_XMSS_LAYER_COUNT: u8 = 2;
pub const DEFAULT_XMSS_WINTERNITZ_PARAMETER: u8 = 16;
pub const DEFAULT_QUEUE_CAPACITY: u32 = 65_536;
pub const DEFAULT_QUEUE_FINALITY_WINDOW_SLOTS: u64 = 2_400;
pub const DEFAULT_CHALLENGE_GRACE_SLOTS: u64 = 480;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 960;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 32;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 24_000_000_000;
pub const DEFAULT_CHALLENGE_BOND_ATOMIC: u64 = 1_600_000_000;
pub const DEFAULT_SUCCESS_REWARD_BPS: u16 = 1_250;
pub const DEFAULT_QUEUE_REPAIR_BPS: u16 = 8_750;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 768;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 120;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_EPOCH_BUCKET_TARGET_EXITS: u64 = 32_768;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitQueueStatus {
    Open,
    Sealed,
    FinalityPending,
    Challenged,
    Repaired,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Committed,
    InQueue,
    Challenged,
    Superseded,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    XmssLeafReuse,
    InvalidAuthPath,
    QueueOmission,
    QueueReordering,
    ReceiptRootMismatch,
    FinalityWindowViolation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XmssLeafReuse => "xmss_leaf_reuse",
            Self::InvalidAuthPath => "invalid_auth_path",
            Self::QueueOmission => "queue_omission",
            Self::QueueReordering => "queue_reordering",
            Self::ReceiptRootMismatch => "receipt_root_mismatch",
            Self::FinalityWindowViolation => "finality_window_violation",
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
    pub xmss_exit_queue_suite: String,
    pub pq_receipt_commitment_suite: String,
    pub queue_finality_challenge_window_suite: String,
    pub low_fee_challenge_batch_suite: String,
    pub private_record_api_suite: String,
    pub min_pq_security_bits: u16,
    pub xmss_tree_height: u8,
    pub xmss_layer_count: u8,
    pub xmss_winternitz_parameter: u8,
    pub queue_capacity: u32,
    pub queue_finality_window_slots: u64,
    pub challenge_grace_slots: u64,
    pub settlement_delay_slots: u64,
    pub receipt_retention_epochs: u64,
    pub exit_bond_atomic: u64,
    pub challenge_bond_atomic: u64,
    pub success_reward_bps: u16,
    pub queue_repair_bps: u16,
    pub low_fee_batch_limit: u16,
    pub max_batch_fee_micro_units: u64,
    pub min_batch_size: u16,
    pub epoch_bucket_target_exits: u64,
    pub pq_receipt_commitments_required: bool,
    pub xmss_auth_paths_required: bool,
    pub queue_finality_windows_required: bool,
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
            xmss_exit_queue_suite: XMSS_EXIT_QUEUE_SUITE.to_string(),
            pq_receipt_commitment_suite: PQ_RECEIPT_COMMITMENT_SUITE.to_string(),
            queue_finality_challenge_window_suite: QUEUE_FINALITY_CHALLENGE_WINDOW_SUITE
                .to_string(),
            low_fee_challenge_batch_suite: LOW_FEE_CHALLENGE_BATCH_SUITE.to_string(),
            private_record_api_suite: PRIVATE_RECORD_API_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            xmss_tree_height: DEFAULT_XMSS_TREE_HEIGHT,
            xmss_layer_count: DEFAULT_XMSS_LAYER_COUNT,
            xmss_winternitz_parameter: DEFAULT_XMSS_WINTERNITZ_PARAMETER,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            queue_finality_window_slots: DEFAULT_QUEUE_FINALITY_WINDOW_SLOTS,
            challenge_grace_slots: DEFAULT_CHALLENGE_GRACE_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            challenge_bond_atomic: DEFAULT_CHALLENGE_BOND_ATOMIC,
            success_reward_bps: DEFAULT_SUCCESS_REWARD_BPS,
            queue_repair_bps: DEFAULT_QUEUE_REPAIR_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            epoch_bucket_target_exits: DEFAULT_EPOCH_BUCKET_TARGET_EXITS,
            pq_receipt_commitments_required: true,
            xmss_auth_paths_required: true,
            queue_finality_windows_required: true,
            low_fee_batching_enabled: true,
            privacy_preserving_public_records_required: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below xmss exit queue minimum".to_string());
        }
        if self.xmss_tree_height < 10 || self.xmss_layer_count == 0 {
            return Err("invalid xmss tree schedule".to_string());
        }
        if !matches!(self.xmss_winternitz_parameter, 4 | 8 | 16) {
            return Err("unsupported xmss winternitz parameter".to_string());
        }
        if self.queue_capacity == 0 || self.epoch_bucket_target_exits == 0 {
            return Err("exit queue capacity and epoch bucket target must be positive".to_string());
        }
        if self.queue_finality_window_slots == 0
            || self.challenge_grace_slots == 0
            || self.settlement_delay_slots == 0
        {
            return Err("queue-finality challenge windows must be positive".to_string());
        }
        if self.challenge_grace_slots > self.queue_finality_window_slots {
            return Err("challenge grace cannot exceed queue-finality window".to_string());
        }
        if self.exit_bond_atomic == 0 || self.challenge_bond_atomic == 0 {
            return Err("exit queue challenge bonds must be positive".to_string());
        }
        if u32::from(self.success_reward_bps) + u32::from(self.queue_repair_bps) != 10_000 {
            return Err("queue challenge reward basis points must sum to 10000".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.max_batch_fee_micro_units == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
        {
            return Err("invalid low-fee challenge batching policy".to_string());
        }
        if !self.pq_receipt_commitments_required
            || !self.xmss_auth_paths_required
            || !self.queue_finality_windows_required
            || !self.privacy_preserving_public_records_required
        {
            return Err("xmss exit queue privacy and finality gates are mandatory".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub exit_queue_entries: u64,
    pub pq_receipt_commitments: u64,
    pub queue_finality_windows: u64,
    pub xmss_challenges: u64,
    pub xmss_evidence: u64,
    pub low_fee_challenge_batches: u64,
    pub open_queue_entries: u64,
    pub challenged_queue_entries: u64,
    pub finalized_queue_entries: u64,
    pub repaired_queue_entries: u64,
    pub total_exit_bond_atomic: u64,
    pub total_challenge_bond_atomic: u64,
    pub total_reward_atomic: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_batched_challenges: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub exit_queue_entry_root: String,
    pub pq_receipt_commitment_root: String,
    pub queue_finality_window_root: String,
    pub xmss_challenge_root: String,
    pub xmss_evidence_root: String,
    pub low_fee_challenge_batch_root: String,
    pub private_accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitQueueEntryInput {
    pub account_commitment: String,
    pub withdrawal_nullifier: String,
    pub xmss_public_root: String,
    pub queue_commitment: String,
    pub encrypted_destination_root: String,
    pub epoch: u64,
    pub requested_slot: u64,
    pub exit_bond_atomic: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitmentInput {
    pub queue_entry_id: String,
    pub receipt_commitment_root: String,
    pub pq_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_nullifier: String,
    pub committed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueFinalityWindowInput {
    pub queue_entry_id: String,
    pub receipt_id: String,
    pub queue_position: u64,
    pub queue_root: String,
    pub state_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XmssChallengeInput {
    pub window_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub challenged_leaf_index: u64,
    pub evidence_commitment_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XmssEvidenceInput {
    pub challenge_id: String,
    pub xmss_auth_path_root: String,
    pub xmss_signature_digest_root: String,
    pub leaf_preimage_commitment: String,
    pub queue_membership_witness_root: String,
    pub transcript_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeChallengeBatchInput {
    pub sequencer_commitment: String,
    pub challenge_ids: BTreeSet<String>,
    pub aggregation_root: String,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitQueueEntry {
    pub queue_entry_id: String,
    pub account_commitment: String,
    pub withdrawal_nullifier: String,
    pub xmss_public_root: String,
    pub xmss_leaf_bitmap_root: String,
    pub queue_commitment: String,
    pub encrypted_destination_root: String,
    pub epoch: u64,
    pub requested_slot: u64,
    pub finality_slot: u64,
    pub exit_bond_atomic: u64,
    pub reward_locked_atomic: u64,
    pub status: ExitQueueStatus,
}

impl ExitQueueEntry {
    pub fn from_input(config: &Config, input: ExitQueueEntryInput) -> Result<Self> {
        require_non_empty(&[
            (&input.account_commitment, "account commitment"),
            (&input.withdrawal_nullifier, "withdrawal nullifier"),
            (&input.xmss_public_root, "xmss public root"),
            (&input.queue_commitment, "queue commitment"),
            (
                &input.encrypted_destination_root,
                "encrypted destination root",
            ),
        ])?;
        if input.exit_bond_atomic < config.challenge_bond_atomic
            || input.exit_bond_atomic > config.exit_bond_atomic
        {
            return Err("exit bond amount outside xmss queue policy".to_string());
        }
        let queue_entry_id = deterministic_id(
            "exit-queue-entry",
            &[
                HashPart::Str(&input.account_commitment),
                HashPart::Str(&input.withdrawal_nullifier),
                HashPart::Str(&input.xmss_public_root),
                HashPart::U64(input.epoch),
                HashPart::U64(input.requested_slot),
            ],
        );
        let xmss_leaf_bitmap_root = deterministic_id(
            "xmss-leaf-bitmap",
            &[
                HashPart::Str(&queue_entry_id),
                HashPart::Str(&input.xmss_public_root),
            ],
        );
        Ok(Self {
            queue_entry_id,
            account_commitment: input.account_commitment,
            withdrawal_nullifier: input.withdrawal_nullifier,
            xmss_public_root: input.xmss_public_root,
            xmss_leaf_bitmap_root,
            queue_commitment: input.queue_commitment,
            encrypted_destination_root: input.encrypted_destination_root,
            epoch: input.epoch,
            requested_slot: input.requested_slot,
            finality_slot: input.requested_slot + config.queue_finality_window_slots,
            exit_bond_atomic: input.exit_bond_atomic,
            reward_locked_atomic: 0,
            status: ExitQueueStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitment {
    pub receipt_id: String,
    pub queue_entry_id: String,
    pub receipt_commitment_root: String,
    pub pq_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub receipt_nullifier: String,
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
            (&input.queue_entry_id, "queue entry id"),
            (&input.receipt_commitment_root, "receipt commitment root"),
            (
                &input.pq_signature_commitment_root,
                "pq signature commitment root",
            ),
            (
                &input.encrypted_receipt_payload_root,
                "encrypted receipt payload root",
            ),
            (&input.receipt_nullifier, "receipt nullifier"),
        ])?;
        let receipt_id = deterministic_id(
            "pq-receipt-commitment",
            &[
                HashPart::Str(&input.queue_entry_id),
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::Str(&input.receipt_nullifier),
                HashPart::U64(input.committed_slot),
            ],
        );
        let receipt_state_root = value_root(
            "pq-receipt-state",
            &json!({
                "receipt_id": receipt_id,
                "receipt_commitment_root": input.receipt_commitment_root,
                "pq_signature_commitment_root": input.pq_signature_commitment_root,
                "encrypted_receipt_payload_root": input.encrypted_receipt_payload_root,
            }),
        );
        Ok(Self {
            receipt_id,
            queue_entry_id: input.queue_entry_id,
            receipt_commitment_root: input.receipt_commitment_root,
            pq_signature_commitment_root: input.pq_signature_commitment_root,
            encrypted_receipt_payload_root: input.encrypted_receipt_payload_root,
            receipt_nullifier: input.receipt_nullifier,
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
pub struct QueueFinalityWindow {
    pub window_id: String,
    pub queue_entry_id: String,
    pub receipt_id: String,
    pub queue_position: u64,
    pub queue_root: String,
    pub state_root: String,
    pub window_open_slot: u64,
    pub window_close_slot: u64,
    pub challenge_deadline_slot: u64,
    pub settlement_slot: u64,
    pub status: ExitQueueStatus,
}

impl QueueFinalityWindow {
    pub fn from_input(config: &Config, input: QueueFinalityWindowInput) -> Result<Self> {
        require_non_empty(&[
            (&input.queue_entry_id, "queue entry id"),
            (&input.receipt_id, "receipt id"),
            (&input.queue_root, "queue root"),
            (&input.state_root, "state root"),
        ])?;
        if input.queue_position >= u64::from(config.queue_capacity) {
            return Err("queue position exceeds configured capacity".to_string());
        }
        let window_id = deterministic_id(
            "queue-finality-window",
            &[
                HashPart::Str(&input.queue_entry_id),
                HashPart::Str(&input.receipt_id),
                HashPart::U64(input.queue_position),
                HashPart::Str(&input.queue_root),
            ],
        );
        let window_close_slot = input.opened_slot + config.queue_finality_window_slots;
        Ok(Self {
            window_id,
            queue_entry_id: input.queue_entry_id,
            receipt_id: input.receipt_id,
            queue_position: input.queue_position,
            queue_root: input.queue_root,
            state_root: input.state_root,
            window_open_slot: input.opened_slot,
            window_close_slot,
            challenge_deadline_slot: window_close_slot + config.challenge_grace_slots,
            settlement_slot: window_close_slot + config.settlement_delay_slots,
            status: ExitQueueStatus::FinalityPending,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XmssChallenge {
    pub challenge_id: String,
    pub window_id: String,
    pub queue_entry_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub challenged_leaf_index: u64,
    pub evidence_commitment_root: String,
    pub challenge_bond_commitment: String,
    pub challenge_bond_atomic: u64,
    pub reward_atomic: u64,
    pub opened_slot: u64,
    pub evidence_deadline_slot: u64,
    pub batch_id: Option<String>,
    pub status: ChallengeStatus,
}

impl XmssChallenge {
    pub fn from_input(
        config: &Config,
        window: &QueueFinalityWindow,
        input: XmssChallengeInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.window_id, "window id"),
            (&input.challenger_commitment, "challenger commitment"),
            (&input.evidence_commitment_root, "evidence commitment root"),
        ])?;
        let max_leaf_index = 1_u64
            .checked_shl(u32::from(config.xmss_tree_height))
            .unwrap_or(0)
            .saturating_sub(1);
        if input.challenged_leaf_index > max_leaf_index {
            return Err("xmss challenged leaf index exceeds tree height".to_string());
        }
        if input.opened_slot > window.challenge_deadline_slot {
            return Err("xmss queue challenge opened after deadline".to_string());
        }
        let challenge_id = deterministic_id(
            "xmss-queue-challenge",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.challenger_commitment),
                HashPart::Str(input.challenge_kind.as_str()),
                HashPart::U64(input.challenged_leaf_index),
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
            queue_entry_id: window.queue_entry_id.clone(),
            receipt_id: window.receipt_id.clone(),
            challenger_commitment: input.challenger_commitment,
            challenge_kind: input.challenge_kind,
            challenged_leaf_index: input.challenged_leaf_index,
            evidence_commitment_root: input.evidence_commitment_root,
            challenge_bond_commitment,
            challenge_bond_atomic: config.challenge_bond_atomic,
            reward_atomic: config.exit_bond_atomic * u64::from(config.success_reward_bps) / 10_000,
            opened_slot: input.opened_slot,
            evidence_deadline_slot: input.opened_slot + config.challenge_grace_slots,
            batch_id: None,
            status: ChallengeStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XmssEvidence {
    pub evidence_id: String,
    pub challenge_id: String,
    pub xmss_auth_path_root: String,
    pub xmss_signature_digest_root: String,
    pub leaf_preimage_commitment: String,
    pub queue_membership_witness_root: String,
    pub transcript_root: String,
    pub replay_guard_root: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

impl XmssEvidence {
    pub fn from_input(input: XmssEvidenceInput) -> Result<Self> {
        require_non_empty(&[
            (&input.challenge_id, "challenge id"),
            (&input.xmss_auth_path_root, "xmss auth path root"),
            (
                &input.xmss_signature_digest_root,
                "xmss signature digest root",
            ),
            (&input.leaf_preimage_commitment, "leaf preimage commitment"),
            (
                &input.queue_membership_witness_root,
                "queue membership witness root",
            ),
            (&input.transcript_root, "transcript root"),
        ])?;
        let evidence_id = deterministic_id(
            "xmss-evidence",
            &[
                HashPart::Str(&input.challenge_id),
                HashPart::Str(&input.xmss_auth_path_root),
                HashPart::Str(&input.xmss_signature_digest_root),
                HashPart::Str(&input.transcript_root),
            ],
        );
        let replay_guard_root = deterministic_id(
            "xmss-evidence-replay-guard",
            &[
                HashPart::Str(&evidence_id),
                HashPart::Str(&input.leaf_preimage_commitment),
            ],
        );
        Ok(Self {
            evidence_id,
            challenge_id: input.challenge_id,
            xmss_auth_path_root: input.xmss_auth_path_root,
            xmss_signature_digest_root: input.xmss_signature_digest_root,
            leaf_preimage_commitment: input.leaf_preimage_commitment,
            queue_membership_witness_root: input.queue_membership_witness_root,
            transcript_root: input.transcript_root,
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
    pub queue_entry_ids: BTreeSet<String>,
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
        challenges: &BTreeMap<String, XmssChallenge>,
        input: LowFeeChallengeBatchInput,
    ) -> Result<Self> {
        require_non_empty(&[
            (&input.sequencer_commitment, "sequencer commitment"),
            (&input.aggregation_root, "aggregation root"),
        ])?;
        if input.challenge_ids.len() < usize::from(config.min_batch_size)
            || input.challenge_ids.len() > usize::from(config.low_fee_batch_limit)
        {
            return Err("low-fee challenge batch size outside policy".to_string());
        }
        if input.batch_fee_micro_units > config.max_batch_fee_micro_units {
            return Err("low-fee challenge batch fee exceeds cap".to_string());
        }
        let queue_entry_ids = input
            .challenge_ids
            .iter()
            .map(|challenge_id| {
                challenges
                    .get(challenge_id)
                    .map(|challenge| challenge.queue_entry_id.clone())
                    .ok_or_else(|| format!("batch references unknown challenge {challenge_id}"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let batch_id = deterministic_id(
            "low-fee-challenge-batch",
            &[
                HashPart::Str(&input.sequencer_commitment),
                HashPart::Str(&input.aggregation_root),
                HashPart::U64(input.challenge_ids.len() as u64),
                HashPart::U64(input.posted_slot),
            ],
        );
        let per_challenge_fee_micro_units =
            input.batch_fee_micro_units / input.challenge_ids.len() as u64;
        Ok(Self {
            batch_id: batch_id.clone(),
            sequencer_commitment: input.sequencer_commitment,
            challenge_ids: input.challenge_ids,
            queue_entry_ids,
            aggregate_challenge_root: sample_root("aggregate-xmss-challenge", input.posted_slot),
            aggregate_evidence_root: sample_root("aggregate-xmss-evidence", input.posted_slot),
            aggregation_root: input.aggregation_root,
            fee_sponsor_commitment: deterministic_id(
                "challenge-batch-fee-sponsor",
                &[HashPart::Str(&batch_id)],
            ),
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
    pub exit_queue_entries: BTreeMap<String, ExitQueueEntry>,
    pub pq_receipt_commitments: BTreeMap<String, PqReceiptCommitment>,
    pub queue_finality_windows: BTreeMap<String, QueueFinalityWindow>,
    pub xmss_challenges: BTreeMap<String, XmssChallenge>,
    pub xmss_evidence: BTreeMap<String, XmssEvidence>,
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

    pub fn register_exit_queue_entry(&mut self, input: ExitQueueEntryInput) -> Result<String> {
        self.config.validate()?;
        let entry = ExitQueueEntry::from_input(&self.config, input)?;
        if self.exit_queue_entries.contains_key(&entry.queue_entry_id) {
            return Err("exit queue entry already exists".to_string());
        }
        if self
            .exit_queue_entries
            .values()
            .any(|existing| existing.withdrawal_nullifier == entry.withdrawal_nullifier)
        {
            return Err("withdrawal nullifier already queued".to_string());
        }
        let queue_entry_id = entry.queue_entry_id.clone();
        self.exit_queue_entries
            .insert(queue_entry_id.clone(), entry);
        self.refresh();
        Ok(queue_entry_id)
    }

    pub fn commit_pq_receipt(&mut self, input: PqReceiptCommitmentInput) -> Result<String> {
        if !self.exit_queue_entries.contains_key(&input.queue_entry_id) {
            return Err("pq receipt references unknown queue entry".to_string());
        }
        let receipt = PqReceiptCommitment::from_input(&self.config, self.epoch, input)?;
        if self
            .pq_receipt_commitments
            .contains_key(&receipt.receipt_id)
        {
            return Err("pq receipt commitment already exists".to_string());
        }
        if self
            .pq_receipt_commitments
            .values()
            .any(|existing| existing.receipt_nullifier == receipt.receipt_nullifier)
        {
            return Err("pq receipt nullifier already committed".to_string());
        }
        if let Some(entry) = self.exit_queue_entries.get_mut(&receipt.queue_entry_id) {
            entry.status = ExitQueueStatus::Sealed;
        }
        let receipt_id = receipt.receipt_id.clone();
        self.pq_receipt_commitments
            .insert(receipt_id.clone(), receipt);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn open_queue_finality_window(
        &mut self,
        input: QueueFinalityWindowInput,
    ) -> Result<String> {
        if !self.exit_queue_entries.contains_key(&input.queue_entry_id) {
            return Err("queue finality window references unknown queue entry".to_string());
        }
        if !self.pq_receipt_commitments.contains_key(&input.receipt_id) {
            return Err("queue finality window references unknown pq receipt".to_string());
        }
        let window = QueueFinalityWindow::from_input(&self.config, input)?;
        if self.queue_finality_windows.contains_key(&window.window_id) {
            return Err("queue finality window already exists".to_string());
        }
        if let Some(entry) = self.exit_queue_entries.get_mut(&window.queue_entry_id) {
            entry.status = ExitQueueStatus::FinalityPending;
            entry.finality_slot = window.window_close_slot;
        }
        if let Some(receipt) = self.pq_receipt_commitments.get_mut(&window.receipt_id) {
            receipt.status = ReceiptStatus::InQueue;
        }
        let window_id = window.window_id.clone();
        self.queue_finality_windows
            .insert(window_id.clone(), window);
        self.refresh();
        Ok(window_id)
    }

    pub fn submit_xmss_challenge(&mut self, input: XmssChallengeInput) -> Result<String> {
        let window = self
            .queue_finality_windows
            .get(&input.window_id)
            .ok_or_else(|| "xmss challenge references unknown finality window".to_string())?;
        let challenge = XmssChallenge::from_input(&self.config, window, input)?;
        if self.xmss_challenges.contains_key(&challenge.challenge_id) {
            return Err("xmss queue challenge already exists".to_string());
        }
        if let Some(entry) = self.exit_queue_entries.get_mut(&challenge.queue_entry_id) {
            entry.status = ExitQueueStatus::Challenged;
            entry.reward_locked_atomic = entry
                .reward_locked_atomic
                .saturating_add(challenge.reward_atomic);
        }
        if let Some(receipt) = self.pq_receipt_commitments.get_mut(&challenge.receipt_id) {
            receipt.status = ReceiptStatus::Challenged;
        }
        if let Some(window) = self.queue_finality_windows.get_mut(&challenge.window_id) {
            window.status = ExitQueueStatus::Challenged;
        }
        let challenge_id = challenge.challenge_id.clone();
        self.xmss_challenges.insert(challenge_id.clone(), challenge);
        self.refresh();
        Ok(challenge_id)
    }

    pub fn anchor_xmss_evidence(&mut self, input: XmssEvidenceInput) -> Result<String> {
        let challenge = self
            .xmss_challenges
            .get(&input.challenge_id)
            .ok_or_else(|| "xmss evidence references unknown challenge".to_string())?;
        if input.anchored_slot > challenge.evidence_deadline_slot {
            return Err("xmss evidence anchored after evidence deadline".to_string());
        }
        let evidence = XmssEvidence::from_input(input)?;
        if self.xmss_evidence.contains_key(&evidence.evidence_id) {
            return Err("xmss evidence already exists".to_string());
        }
        if let Some(challenge) = self.xmss_challenges.get_mut(&evidence.challenge_id) {
            challenge.status = if evidence.accepted {
                ChallengeStatus::Accepted
            } else {
                ChallengeStatus::Rejected
            };
        }
        let challenge = self
            .xmss_challenges
            .get(&evidence.challenge_id)
            .ok_or_else(|| "xmss evidence lost challenge reference".to_string())?;
        if evidence.accepted {
            if let Some(entry) = self.exit_queue_entries.get_mut(&challenge.queue_entry_id) {
                entry.status = ExitQueueStatus::Repaired;
            }
            if let Some(receipt) = self.pq_receipt_commitments.get_mut(&challenge.receipt_id) {
                receipt.status = ReceiptStatus::Superseded;
            }
            if let Some(window) = self.queue_finality_windows.get_mut(&challenge.window_id) {
                window.status = ExitQueueStatus::Repaired;
            }
        }
        let evidence_id = evidence.evidence_id.clone();
        self.xmss_evidence.insert(evidence_id.clone(), evidence);
        self.refresh();
        Ok(evidence_id)
    }

    pub fn post_low_fee_challenge_batch(
        &mut self,
        input: LowFeeChallengeBatchInput,
    ) -> Result<String> {
        let batch = LowFeeChallengeBatch::from_input(&self.config, &self.xmss_challenges, input)?;
        if self.low_fee_challenge_batches.contains_key(&batch.batch_id) {
            return Err("low-fee challenge batch already exists".to_string());
        }
        for challenge_id in &batch.challenge_ids {
            if let Some(challenge) = self.xmss_challenges.get_mut(challenge_id) {
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
            .ok_or_else(|| "unknown low-fee challenge batch".to_string())?;
        batch.status = BatchStatus::Settled;
        for challenge_id in &batch.challenge_ids {
            if let Some(challenge) = self.xmss_challenges.get_mut(challenge_id) {
                challenge.status = ChallengeStatus::Settled;
                if let Some(entry) = self.exit_queue_entries.get_mut(&challenge.queue_entry_id) {
                    if entry.status == ExitQueueStatus::Repaired {
                        entry.reward_locked_atomic = entry
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
            .queue_finality_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown queue finality window".to_string())?;
        if finalized_slot < window.settlement_slot {
            return Err("queue finality window cannot finalize before settlement slot".to_string());
        }
        let has_accepted_challenge = self.xmss_challenges.values().any(|challenge| {
            challenge.window_id == window.window_id
                && matches!(
                    challenge.status,
                    ChallengeStatus::Accepted | ChallengeStatus::Batched | ChallengeStatus::Settled
                )
        });
        if has_accepted_challenge {
            return Err("queue finality window has accepted challenge".to_string());
        }
        window.status = ExitQueueStatus::Finalized;
        if let Some(entry) = self.exit_queue_entries.get_mut(&window.queue_entry_id) {
            entry.status = ExitQueueStatus::Finalized;
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
        for index in 0_u64..7 {
            let queue_entry_id = self
                .register_exit_queue_entry(ExitQueueEntryInput {
                    account_commitment: sample_root("account-commitment", index),
                    withdrawal_nullifier: sample_root("withdrawal-nullifier", index),
                    xmss_public_root: sample_root("xmss-public-root", index),
                    queue_commitment: sample_root("queue-commitment", index),
                    encrypted_destination_root: sample_root("encrypted-destination", index),
                    epoch: self.epoch,
                    requested_slot: self.slot + index * 6,
                    exit_bond_atomic: self.config.exit_bond_atomic,
                })
                .expect("devnet xmss exit queue entry must register");
            let receipt_id = self
                .commit_pq_receipt(PqReceiptCommitmentInput {
                    queue_entry_id: queue_entry_id.clone(),
                    receipt_commitment_root: sample_root("pq-receipt-commitment", index),
                    pq_signature_commitment_root: sample_root("pq-signature-commitment", index),
                    encrypted_receipt_payload_root: sample_root("encrypted-receipt", index),
                    receipt_nullifier: sample_root("receipt-nullifier", index),
                    committed_slot: self.slot + index * 6 + 1,
                })
                .expect("devnet pq receipt must commit");
            let window_id = self
                .open_queue_finality_window(QueueFinalityWindowInput {
                    queue_entry_id: queue_entry_id.clone(),
                    receipt_id: receipt_id.clone(),
                    queue_position: index,
                    queue_root: sample_root("queue-root", index),
                    state_root: sample_root("observed-state-root", index),
                    opened_slot: self.slot + index * 6 + 2,
                })
                .expect("devnet queue finality window must open");
            if index % 2 == 0 {
                let challenge_id = self
                    .submit_xmss_challenge(XmssChallengeInput {
                        window_id,
                        challenger_commitment: sample_root("challenger", index),
                        challenge_kind: match index {
                            0 => ChallengeKind::XmssLeafReuse,
                            2 => ChallengeKind::QueueOmission,
                            4 => ChallengeKind::ReceiptRootMismatch,
                            _ => ChallengeKind::InvalidAuthPath,
                        },
                        challenged_leaf_index: index * 11,
                        evidence_commitment_root: sample_root("evidence-commitment", index),
                        opened_slot: self.slot + index * 6 + 8,
                    })
                    .expect("devnet xmss challenge must submit");
                self.anchor_xmss_evidence(XmssEvidenceInput {
                    challenge_id: challenge_id.clone(),
                    xmss_auth_path_root: sample_root("xmss-auth-path", index),
                    xmss_signature_digest_root: sample_root("xmss-signature-digest", index),
                    leaf_preimage_commitment: sample_root("leaf-preimage", index),
                    queue_membership_witness_root: sample_root("queue-membership", index),
                    transcript_root: sample_root("challenge-transcript", index),
                    accepted: index != 4,
                    anchored_slot: self.slot + index * 6 + 16,
                })
                .expect("devnet xmss evidence must anchor");
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
                    batch_fee_micro_units: self.config.max_batch_fee_micro_units / 2,
                    posted_slot: self.slot + 192,
                })
                .expect("devnet low-fee xmss challenge batch must post");
            self.settle_low_fee_challenge_batch(&batch_id)
                .expect("devnet low-fee xmss challenge batch must settle");
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            exit_queue_entries: self.exit_queue_entries.len() as u64,
            pq_receipt_commitments: self.pq_receipt_commitments.len() as u64,
            queue_finality_windows: self.queue_finality_windows.len() as u64,
            xmss_challenges: self.xmss_challenges.len() as u64,
            xmss_evidence: self.xmss_evidence.len() as u64,
            low_fee_challenge_batches: self.low_fee_challenge_batches.len() as u64,
            open_queue_entries: self
                .exit_queue_entries
                .values()
                .filter(|entry| {
                    matches!(
                        entry.status,
                        ExitQueueStatus::Open | ExitQueueStatus::Sealed
                    )
                })
                .count() as u64,
            challenged_queue_entries: self
                .exit_queue_entries
                .values()
                .filter(|entry| entry.status == ExitQueueStatus::Challenged)
                .count() as u64,
            finalized_queue_entries: self
                .exit_queue_entries
                .values()
                .filter(|entry| entry.status == ExitQueueStatus::Finalized)
                .count() as u64,
            repaired_queue_entries: self
                .exit_queue_entries
                .values()
                .filter(|entry| entry.status == ExitQueueStatus::Repaired)
                .count() as u64,
            total_exit_bond_atomic: self
                .exit_queue_entries
                .values()
                .map(|entry| entry.exit_bond_atomic)
                .sum(),
            total_challenge_bond_atomic: self
                .xmss_challenges
                .values()
                .map(|challenge| challenge.challenge_bond_atomic)
                .sum(),
            total_reward_atomic: self
                .xmss_challenges
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
        let exit_queue_entry_root = record_root(
            "exit-queue-entries",
            self.exit_queue_entries
                .values()
                .map(ExitQueueEntry::public_record)
                .collect(),
        );
        let pq_receipt_commitment_root = record_root(
            "pq-receipt-commitments",
            self.pq_receipt_commitments
                .values()
                .map(PqReceiptCommitment::public_record)
                .collect(),
        );
        let queue_finality_window_root = record_root(
            "queue-finality-windows",
            self.queue_finality_windows
                .values()
                .map(QueueFinalityWindow::public_record)
                .collect(),
        );
        let xmss_challenge_root = record_root(
            "xmss-challenges",
            self.xmss_challenges
                .values()
                .map(XmssChallenge::public_record)
                .collect(),
        );
        let xmss_evidence_root = record_root(
            "xmss-evidence",
            self.xmss_evidence
                .values()
                .map(XmssEvidence::public_record)
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
                "exit_queue_entry_root": exit_queue_entry_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "queue_finality_window_root": queue_finality_window_root,
                "xmss_challenge_root": xmss_challenge_root,
                "xmss_evidence_root": xmss_evidence_root,
                "low_fee_challenge_batch_root": low_fee_challenge_batch_root,
                "redacted_totals": self.counters.public_record(),
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "exit_queue_entry_root": exit_queue_entry_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "queue_finality_window_root": queue_finality_window_root,
                "xmss_challenge_root": xmss_challenge_root,
                "xmss_evidence_root": xmss_evidence_root,
                "low_fee_challenge_batch_root": low_fee_challenge_batch_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-XMSS-EXIT-QUEUE-CHALLENGE-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&exit_queue_entry_root),
                HashPart::Str(&pq_receipt_commitment_root),
                HashPart::Str(&queue_finality_window_root),
                HashPart::Str(&xmss_challenge_root),
                HashPart::Str(&xmss_evidence_root),
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
            exit_queue_entry_root,
            pq_receipt_commitment_root,
            queue_finality_window_root,
            xmss_challenge_root,
            xmss_evidence_root,
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
            exit_queue_entries: BTreeMap::new(),
            pq_receipt_commitments: BTreeMap::new(),
            queue_finality_windows: BTreeMap::new(),
            xmss_challenges: BTreeMap::new(),
            xmss_evidence: BTreeMap::new(),
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
        "xmss_exit_queue_suite": XMSS_EXIT_QUEUE_SUITE,
        "pq_receipt_commitment_suite": PQ_RECEIPT_COMMITMENT_SUITE,
        "queue_finality_challenge_window_suite": QUEUE_FINALITY_CHALLENGE_WINDOW_SUITE,
        "low_fee_challenge_batch_suite": LOW_FEE_CHALLENGE_BATCH_SUITE,
        "private_record_api_suite": PRIVATE_RECORD_API_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "exit_queue_entries": state
            .exit_queue_entries
            .values()
            .map(ExitQueueEntry::public_record)
            .collect::<Vec<_>>(),
        "pq_receipt_commitments": state
            .pq_receipt_commitments
            .values()
            .map(PqReceiptCommitment::public_record)
            .collect::<Vec<_>>(),
        "queue_finality_windows": state
            .queue_finality_windows
            .values()
            .map(QueueFinalityWindow::public_record)
            .collect::<Vec<_>>(),
        "xmss_challenges": state
            .xmss_challenges
            .values()
            .map(XmssChallenge::public_record)
            .collect::<Vec<_>>(),
        "xmss_evidence": state
            .xmss_evidence
            .values()
            .map(XmssEvidence::public_record)
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-XMSS-EXIT-QUEUE-CHALLENGE-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-XMSS-EXIT-QUEUE-CHALLENGE-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-XMSS-EXIT-QUEUE-CHALLENGE-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-XMSS-EXIT-QUEUE-CHALLENGE-{domain}"),
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
