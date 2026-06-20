use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialWinternitzExitBondSlashingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_WINTERNITZ_EXIT_BOND_SLASHING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-winternitz-exit-bond-slashing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_WINTERNITZ_EXIT_BOND_SLASHING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const WINTERNITZ_SLASHING_SUITE: &str =
    "winternitz-hash-based-exit-bond-slashing-commitment-v1";
pub const PQ_RECEIPT_COMMITMENT_SUITE: &str = "pq-confidential-exit-slashing-receipt-commitment-v1";
pub const SLASHING_CHALLENGE_WINDOW_SUITE: &str =
    "confidential-exit-bond-slashing-challenge-window-v1";
pub const LOW_FEE_SLASHING_BATCH_SUITE: &str = "low-fee-winternitz-exit-bond-slashing-batch-v1";
pub const PRIVATE_RECORD_API_SUITE: &str = "privacy-preserving-exit-slashing-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 8_616_000;
pub const DEVNET_EPOCH: u64 = 35_946;
pub const DEVNET_SLOT: u64 = 192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_WINTERNITZ_PARAMETER: u8 = 16;
pub const DEFAULT_WINTERNITZ_CHAIN_COUNT: u16 = 67;
pub const DEFAULT_WINTERNITZ_CHECKSUM_BITS: u16 = 14;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 32_000_000_000;
pub const DEFAULT_MIN_SLASH_ATOMIC: u64 = 8_000_000_000;
pub const DEFAULT_MAX_SLASH_ATOMIC: u64 = 32_000_000_000;
pub const DEFAULT_CHALLENGE_BOND_ATOMIC: u64 = 2_800_000_000;
pub const DEFAULT_WHISTLEBLOWER_REWARD_BPS: u16 = 1_500;
pub const DEFAULT_TREASURY_REWARD_BPS: u16 = 8_500;
pub const DEFAULT_SLASHING_WINDOW_SLOTS: u64 = 2_160;
pub const DEFAULT_EVIDENCE_GRACE_SLOTS: u64 = 720;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 1_440;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 32;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 512;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 140;
pub const DEFAULT_EPOCH_BUCKET_TARGET_EXITS: u64 = 24_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitBondStatus {
    Registered,
    ReceiptCommitted,
    ChallengeOpen,
    SlashPending,
    Slashed,
}

impl ExitBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::ReceiptCommitted => "receipt_committed",
            Self::ChallengeOpen => "challenge_open",
            Self::SlashPending => "slash_pending",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Anchored,
    Challenged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anchored => "anchored",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    DoubleExit,
    InvalidReceipt,
    BurnMismatch,
    WithheldPreimage,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleExit => "double_exit",
            Self::InvalidReceipt => "invalid_receipt",
            Self::BurnMismatch => "burn_mismatch",
            Self::WithheldPreimage => "withheld_preimage",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Submitted,
    Accepted,
    Rejected,
    Settled,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Posted,
    Settled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Settled => "settled",
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
    pub winternitz_slashing_suite: String,
    pub pq_receipt_commitment_suite: String,
    pub slashing_challenge_window_suite: String,
    pub low_fee_slashing_batch_suite: String,
    pub private_record_api_suite: String,
    pub min_pq_security_bits: u16,
    pub winternitz_parameter: u8,
    pub winternitz_chain_count: u16,
    pub winternitz_checksum_bits: u16,
    pub exit_bond_atomic: u64,
    pub min_slash_atomic: u64,
    pub max_slash_atomic: u64,
    pub challenge_bond_atomic: u64,
    pub whistleblower_reward_bps: u16,
    pub treasury_reward_bps: u16,
    pub slashing_window_slots: u64,
    pub evidence_grace_slots: u64,
    pub settlement_delay_slots: u64,
    pub receipt_retention_epochs: u64,
    pub low_fee_batch_limit: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_exits: u64,
    pub pq_receipt_commitments_required: bool,
    pub winternitz_public_keys_required: bool,
    pub challenge_windows_required: bool,
    pub low_fee_batching_enabled: bool,
    pub public_record_redaction_required: bool,
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
            winternitz_slashing_suite: WINTERNITZ_SLASHING_SUITE.to_string(),
            pq_receipt_commitment_suite: PQ_RECEIPT_COMMITMENT_SUITE.to_string(),
            slashing_challenge_window_suite: SLASHING_CHALLENGE_WINDOW_SUITE.to_string(),
            low_fee_slashing_batch_suite: LOW_FEE_SLASHING_BATCH_SUITE.to_string(),
            private_record_api_suite: PRIVATE_RECORD_API_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            winternitz_parameter: DEFAULT_WINTERNITZ_PARAMETER,
            winternitz_chain_count: DEFAULT_WINTERNITZ_CHAIN_COUNT,
            winternitz_checksum_bits: DEFAULT_WINTERNITZ_CHECKSUM_BITS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            min_slash_atomic: DEFAULT_MIN_SLASH_ATOMIC,
            max_slash_atomic: DEFAULT_MAX_SLASH_ATOMIC,
            challenge_bond_atomic: DEFAULT_CHALLENGE_BOND_ATOMIC,
            whistleblower_reward_bps: DEFAULT_WHISTLEBLOWER_REWARD_BPS,
            treasury_reward_bps: DEFAULT_TREASURY_REWARD_BPS,
            slashing_window_slots: DEFAULT_SLASHING_WINDOW_SLOTS,
            evidence_grace_slots: DEFAULT_EVIDENCE_GRACE_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_exits: DEFAULT_EPOCH_BUCKET_TARGET_EXITS,
            pq_receipt_commitments_required: true,
            winternitz_public_keys_required: true,
            challenge_windows_required: true,
            low_fee_batching_enabled: true,
            public_record_redaction_required: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below winternitz slashing minimum".to_string());
        }
        if !matches!(self.winternitz_parameter, 4 | 8 | 16) {
            return Err("unsupported winternitz parameter".to_string());
        }
        if self.winternitz_chain_count == 0 || self.winternitz_checksum_bits == 0 {
            return Err("invalid winternitz chain schedule".to_string());
        }
        if self.exit_bond_atomic == 0
            || self.min_slash_atomic == 0
            || self.max_slash_atomic == 0
            || self.min_slash_atomic > self.max_slash_atomic
            || self.max_slash_atomic > self.exit_bond_atomic
        {
            return Err("invalid exit bond slashing economics".to_string());
        }
        if u32::from(self.whistleblower_reward_bps) + u32::from(self.treasury_reward_bps) != 10_000
        {
            return Err("slashing reward basis points must sum to 10000".to_string());
        }
        if self.slashing_window_slots == 0
            || self.evidence_grace_slots == 0
            || self.settlement_delay_slots == 0
        {
            return Err("slashing challenge windows must be positive".to_string());
        }
        if self.low_fee_batch_limit == 0 || self.max_batch_fee_micro_units == 0 {
            return Err("low fee slashing batch limits must be positive".to_string());
        }
        if self.epoch_bucket_target_exits == 0 {
            return Err("epoch bucket target exits must be positive".to_string());
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
            "winternitz_slashing_suite": self.winternitz_slashing_suite,
            "pq_receipt_commitment_suite": self.pq_receipt_commitment_suite,
            "slashing_challenge_window_suite": self.slashing_challenge_window_suite,
            "low_fee_slashing_batch_suite": self.low_fee_slashing_batch_suite,
            "private_record_api_suite": self.private_record_api_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "winternitz_parameter": self.winternitz_parameter,
            "winternitz_chain_count": self.winternitz_chain_count,
            "winternitz_checksum_bits": self.winternitz_checksum_bits,
            "exit_bond_atomic": self.exit_bond_atomic,
            "min_slash_atomic": self.min_slash_atomic,
            "max_slash_atomic": self.max_slash_atomic,
            "challenge_bond_atomic": self.challenge_bond_atomic,
            "whistleblower_reward_bps": self.whistleblower_reward_bps,
            "treasury_reward_bps": self.treasury_reward_bps,
            "slashing_window_slots": self.slashing_window_slots,
            "evidence_grace_slots": self.evidence_grace_slots,
            "settlement_delay_slots": self.settlement_delay_slots,
            "receipt_retention_epochs": self.receipt_retention_epochs,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "max_batch_fee_micro_units": self.max_batch_fee_micro_units,
            "epoch_bucket_target_exits": self.epoch_bucket_target_exits,
            "pq_receipt_commitments_required": self.pq_receipt_commitments_required,
            "winternitz_public_keys_required": self.winternitz_public_keys_required,
            "challenge_windows_required": self.challenge_windows_required,
            "low_fee_batching_enabled": self.low_fee_batching_enabled,
            "public_record_redaction_required": self.public_record_redaction_required,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub exit_bonds: u64,
    pub receipt_commitments: u64,
    pub slashing_challenges: u64,
    pub winternitz_evidence: u64,
    pub slashing_batches: u64,
    pub public_api_snapshots: u64,
    pub slash_pending_bonds: u64,
    pub slashed_bonds: u64,
    pub total_exit_bond_atomic: u64,
    pub total_slash_pending_atomic: u64,
    pub total_slashed_atomic: u64,
    pub total_challenge_bond_atomic: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_batched_challenges: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "exit_bonds": self.exit_bonds,
            "receipt_commitments": self.receipt_commitments,
            "slashing_challenges": self.slashing_challenges,
            "winternitz_evidence": self.winternitz_evidence,
            "slashing_batches": self.slashing_batches,
            "public_api_snapshots": self.public_api_snapshots,
            "slash_pending_bonds": self.slash_pending_bonds,
            "slashed_bonds": self.slashed_bonds,
            "total_exit_bond_atomic": self.total_exit_bond_atomic,
            "total_slash_pending_atomic": self.total_slash_pending_atomic,
            "total_slashed_atomic": self.total_slashed_atomic,
            "total_challenge_bond_atomic": self.total_challenge_bond_atomic,
            "total_batch_fee_micro_units": self.total_batch_fee_micro_units,
            "total_batched_challenges": self.total_batched_challenges,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub exit_bond_root: String,
    pub pq_receipt_commitment_root: String,
    pub slashing_challenge_root: String,
    pub winternitz_evidence_root: String,
    pub low_fee_slashing_batch_root: String,
    pub public_api_snapshot_root: String,
    pub private_accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "exit_bond_root": self.exit_bond_root,
            "pq_receipt_commitment_root": self.pq_receipt_commitment_root,
            "slashing_challenge_root": self.slashing_challenge_root,
            "winternitz_evidence_root": self.winternitz_evidence_root,
            "low_fee_slashing_batch_root": self.low_fee_slashing_batch_root,
            "public_api_snapshot_root": self.public_api_snapshot_root,
            "private_accounting_root": self.private_accounting_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitBondInput {
    pub validator_commitment: String,
    pub exit_nullifier: String,
    pub winternitz_public_key_root: String,
    pub pq_identity_commitment: String,
    pub epoch: u64,
    pub slot: u64,
    pub exit_bond_atomic: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptCommitmentInput {
    pub exit_bond_id: String,
    pub receipt_commitment: String,
    pub receipt_nullifier: String,
    pub pq_signature_commitment: String,
    pub observed_state_root: String,
    pub anchor_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingChallengeInput {
    pub exit_bond_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub evidence_root: String,
    pub slash_amount_atomic: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinternitzEvidenceInput {
    pub challenge_id: String,
    pub chain_disclosure_root: String,
    pub message_digest_root: String,
    pub checksum_root: String,
    pub replay_guard: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSlashingBatchInput {
    pub sequencer_commitment: String,
    pub challenge_ids: Vec<String>,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicApiSnapshotInput {
    pub snapshot_label: String,
    pub visibility_root: String,
    pub request_count: u64,
    pub emitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitBond {
    pub exit_bond_id: String,
    pub validator_commitment: String,
    pub exit_nullifier: String,
    pub winternitz_public_key_root: String,
    pub pq_identity_commitment: String,
    pub status: ExitBondStatus,
    pub epoch: u64,
    pub slot: u64,
    pub exit_bond_atomic: u64,
    pub slash_locked_atomic: u64,
    pub slashed_atomic: u64,
    pub challenge_window_open_slot: u64,
    pub challenge_window_close_slot: u64,
    pub release_slot: u64,
}

impl ExitBond {
    pub fn from_input(config: &Config, input: ExitBondInput) -> Result<Self> {
        if input.validator_commitment.is_empty()
            || input.exit_nullifier.is_empty()
            || input.winternitz_public_key_root.is_empty()
            || input.pq_identity_commitment.is_empty()
        {
            return Err("exit bond commitments must be non-empty".to_string());
        }
        if input.exit_bond_atomic < config.min_slash_atomic
            || input.exit_bond_atomic > config.exit_bond_atomic
        {
            return Err("exit bond amount outside slashing policy".to_string());
        }
        let exit_bond_id = deterministic_id(
            "EXIT-BOND",
            &[
                HashPart::Str(&input.validator_commitment),
                HashPart::Str(&input.exit_nullifier),
                HashPart::Str(&input.winternitz_public_key_root),
                HashPart::U64(input.epoch),
                HashPart::U64(input.slot),
            ],
        );
        let challenge_window_open_slot = input.slot;
        let challenge_window_close_slot = input.slot + config.slashing_window_slots;
        let release_slot = challenge_window_close_slot + config.settlement_delay_slots;
        Ok(Self {
            exit_bond_id,
            validator_commitment: input.validator_commitment,
            exit_nullifier: input.exit_nullifier,
            winternitz_public_key_root: input.winternitz_public_key_root,
            pq_identity_commitment: input.pq_identity_commitment,
            status: ExitBondStatus::Registered,
            epoch: input.epoch,
            slot: input.slot,
            exit_bond_atomic: input.exit_bond_atomic,
            slash_locked_atomic: 0,
            slashed_atomic: 0,
            challenge_window_open_slot,
            challenge_window_close_slot,
            release_slot,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_bond_id": self.exit_bond_id,
            "validator_commitment": self.validator_commitment,
            "exit_nullifier": self.exit_nullifier,
            "winternitz_public_key_root": self.winternitz_public_key_root,
            "pq_identity_commitment": self.pq_identity_commitment,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "slot": self.slot,
            "exit_bond_atomic": self.exit_bond_atomic,
            "slash_locked_atomic": self.slash_locked_atomic,
            "slashed_atomic": self.slashed_atomic,
            "challenge_window_open_slot": self.challenge_window_open_slot,
            "challenge_window_close_slot": self.challenge_window_close_slot,
            "release_slot": self.release_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitment {
    pub receipt_id: String,
    pub exit_bond_id: String,
    pub receipt_commitment: String,
    pub receipt_nullifier: String,
    pub pq_signature_commitment: String,
    pub observed_state_root: String,
    pub status: ReceiptStatus,
    pub anchor_slot: u64,
    pub expires_epoch: u64,
}

impl PqReceiptCommitment {
    pub fn from_input(
        config: &Config,
        current_epoch: u64,
        input: ReceiptCommitmentInput,
    ) -> Result<Self> {
        if input.exit_bond_id.is_empty()
            || input.receipt_commitment.is_empty()
            || input.receipt_nullifier.is_empty()
            || input.pq_signature_commitment.is_empty()
            || input.observed_state_root.is_empty()
        {
            return Err("pq receipt commitment fields must be non-empty".to_string());
        }
        let receipt_id = deterministic_id(
            "PQ-RECEIPT",
            &[
                HashPart::Str(&input.exit_bond_id),
                HashPart::Str(&input.receipt_commitment),
                HashPart::Str(&input.receipt_nullifier),
                HashPart::Str(&input.observed_state_root),
                HashPart::U64(input.anchor_slot),
            ],
        );
        Ok(Self {
            receipt_id,
            exit_bond_id: input.exit_bond_id,
            receipt_commitment: input.receipt_commitment,
            receipt_nullifier: input.receipt_nullifier,
            pq_signature_commitment: input.pq_signature_commitment,
            observed_state_root: input.observed_state_root,
            status: ReceiptStatus::Anchored,
            anchor_slot: input.anchor_slot,
            expires_epoch: current_epoch + config.receipt_retention_epochs,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "exit_bond_id": self.exit_bond_id,
            "receipt_commitment": self.receipt_commitment,
            "receipt_nullifier": self.receipt_nullifier,
            "pq_signature_commitment": self.pq_signature_commitment,
            "observed_state_root": self.observed_state_root,
            "status": self.status.as_str(),
            "anchor_slot": self.anchor_slot,
            "expires_epoch": self.expires_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingChallenge {
    pub challenge_id: String,
    pub exit_bond_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub evidence_root: String,
    pub status: ChallengeStatus,
    pub slash_amount_atomic: u64,
    pub challenge_bond_atomic: u64,
    pub opened_slot: u64,
    pub evidence_deadline_slot: u64,
    pub settlement_slot: u64,
    pub batch_id: Option<String>,
}

impl SlashingChallenge {
    pub fn from_input(config: &Config, input: SlashingChallengeInput) -> Result<Self> {
        if input.exit_bond_id.is_empty()
            || input.receipt_id.is_empty()
            || input.challenger_commitment.is_empty()
            || input.evidence_root.is_empty()
        {
            return Err("slashing challenge commitments must be non-empty".to_string());
        }
        if input.slash_amount_atomic < config.min_slash_atomic
            || input.slash_amount_atomic > config.max_slash_atomic
        {
            return Err("slash amount outside configured range".to_string());
        }
        let challenge_id = deterministic_id(
            "SLASHING-CHALLENGE",
            &[
                HashPart::Str(&input.exit_bond_id),
                HashPart::Str(&input.receipt_id),
                HashPart::Str(&input.challenger_commitment),
                HashPart::Str(input.evidence_kind.as_str()),
                HashPart::Str(&input.evidence_root),
                HashPart::U64(input.opened_slot),
            ],
        );
        Ok(Self {
            challenge_id,
            exit_bond_id: input.exit_bond_id,
            receipt_id: input.receipt_id,
            challenger_commitment: input.challenger_commitment,
            evidence_kind: input.evidence_kind,
            evidence_root: input.evidence_root,
            status: ChallengeStatus::Submitted,
            slash_amount_atomic: input.slash_amount_atomic,
            challenge_bond_atomic: config.challenge_bond_atomic,
            opened_slot: input.opened_slot,
            evidence_deadline_slot: input.opened_slot + config.evidence_grace_slots,
            settlement_slot: input.opened_slot
                + config.evidence_grace_slots
                + config.settlement_delay_slots,
            batch_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "exit_bond_id": self.exit_bond_id,
            "receipt_id": self.receipt_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "slash_amount_atomic": self.slash_amount_atomic,
            "challenge_bond_atomic": self.challenge_bond_atomic,
            "opened_slot": self.opened_slot,
            "evidence_deadline_slot": self.evidence_deadline_slot,
            "settlement_slot": self.settlement_slot,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinternitzEvidence {
    pub evidence_id: String,
    pub challenge_id: String,
    pub chain_disclosure_root: String,
    pub message_digest_root: String,
    pub checksum_root: String,
    pub replay_guard: String,
    pub accepted: bool,
    pub anchored_slot: u64,
}

impl WinternitzEvidence {
    pub fn from_input(input: WinternitzEvidenceInput) -> Result<Self> {
        if input.challenge_id.is_empty()
            || input.chain_disclosure_root.is_empty()
            || input.message_digest_root.is_empty()
            || input.checksum_root.is_empty()
            || input.replay_guard.is_empty()
        {
            return Err("winternitz evidence roots must be non-empty".to_string());
        }
        let evidence_id = deterministic_id(
            "WINTERNITZ-EVIDENCE",
            &[
                HashPart::Str(&input.challenge_id),
                HashPart::Str(&input.chain_disclosure_root),
                HashPart::Str(&input.message_digest_root),
                HashPart::Str(&input.checksum_root),
                HashPart::Str(&input.replay_guard),
                HashPart::U64(input.anchored_slot),
            ],
        );
        Ok(Self {
            evidence_id,
            challenge_id: input.challenge_id,
            chain_disclosure_root: input.chain_disclosure_root,
            message_digest_root: input.message_digest_root,
            checksum_root: input.checksum_root,
            replay_guard: input.replay_guard,
            accepted: input.accepted,
            anchored_slot: input.anchored_slot,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "challenge_id": self.challenge_id,
            "chain_disclosure_root": self.chain_disclosure_root,
            "message_digest_root": self.message_digest_root,
            "checksum_root": self.checksum_root,
            "replay_guard": self.replay_guard,
            "accepted": self.accepted,
            "anchored_slot": self.anchored_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSlashingBatch {
    pub batch_id: String,
    pub sequencer_commitment: String,
    pub challenge_ids: Vec<String>,
    pub status: BatchStatus,
    pub batch_fee_micro_units: u64,
    pub posted_slot: u64,
    pub settlement_root: String,
}

impl LowFeeSlashingBatch {
    pub fn from_input(config: &Config, input: LowFeeSlashingBatchInput) -> Result<Self> {
        if input.sequencer_commitment.is_empty() || input.challenge_ids.is_empty() {
            return Err("low fee slashing batch must include sequencer and challenges".to_string());
        }
        if input.challenge_ids.len() > usize::from(config.low_fee_batch_limit) {
            return Err("low fee slashing batch exceeds configured limit".to_string());
        }
        if input.batch_fee_micro_units > config.max_batch_fee_micro_units {
            return Err("low fee slashing batch fee exceeds cap".to_string());
        }
        let unique = input.challenge_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != input.challenge_ids.len() {
            return Err("low fee slashing batch contains duplicate challenges".to_string());
        }
        let challenge_root = record_root(
            "batch-challenge-members",
            input
                .challenge_ids
                .iter()
                .map(|challenge_id| json!({ "challenge_id": challenge_id }))
                .collect(),
        );
        let batch_id = deterministic_id(
            "LOW-FEE-SLASHING-BATCH",
            &[
                HashPart::Str(&input.sequencer_commitment),
                HashPart::Str(&challenge_root),
                HashPart::U64(input.posted_slot),
            ],
        );
        let settlement_root = value_root(
            "low-fee-slashing-batch-settlement",
            &json!({
                "batch_id": batch_id,
                "challenge_root": challenge_root,
                "batch_fee_micro_units": input.batch_fee_micro_units,
            }),
        );
        Ok(Self {
            batch_id,
            sequencer_commitment: input.sequencer_commitment,
            challenge_ids: input.challenge_ids,
            status: BatchStatus::Posted,
            batch_fee_micro_units: input.batch_fee_micro_units,
            posted_slot: input.posted_slot,
            settlement_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequencer_commitment": self.sequencer_commitment,
            "challenge_ids": self.challenge_ids,
            "status": self.status.as_str(),
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "posted_slot": self.posted_slot,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicApiSnapshot {
    pub snapshot_id: String,
    pub snapshot_label: String,
    pub visibility_root: String,
    pub exit_bond_root: String,
    pub receipt_commitment_root: String,
    pub slashing_challenge_root: String,
    pub state_root: String,
    pub request_count: u64,
    pub emitted_slot: u64,
}

impl PublicApiSnapshot {
    pub fn from_input(roots: &Roots, input: PublicApiSnapshotInput) -> Result<Self> {
        if input.snapshot_label.is_empty() || input.visibility_root.is_empty() {
            return Err("public api snapshot label and visibility root are required".to_string());
        }
        let snapshot_id = deterministic_id(
            "PUBLIC-API-SNAPSHOT",
            &[
                HashPart::Str(&input.snapshot_label),
                HashPart::Str(&input.visibility_root),
                HashPart::Str(&roots.state_root),
                HashPart::U64(input.emitted_slot),
            ],
        );
        Ok(Self {
            snapshot_id,
            snapshot_label: input.snapshot_label,
            visibility_root: input.visibility_root,
            exit_bond_root: roots.exit_bond_root.clone(),
            receipt_commitment_root: roots.pq_receipt_commitment_root.clone(),
            slashing_challenge_root: roots.slashing_challenge_root.clone(),
            state_root: roots.state_root.clone(),
            request_count: input.request_count,
            emitted_slot: input.emitted_slot,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "snapshot_label": self.snapshot_label,
            "visibility_root": self.visibility_root,
            "exit_bond_root": self.exit_bond_root,
            "receipt_commitment_root": self.receipt_commitment_root,
            "slashing_challenge_root": self.slashing_challenge_root,
            "state_root": self.state_root,
            "request_count": self.request_count,
            "emitted_slot": self.emitted_slot,
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
    pub exit_bonds: BTreeMap<String, ExitBond>,
    pub receipt_commitments: BTreeMap<String, PqReceiptCommitment>,
    pub slashing_challenges: BTreeMap<String, SlashingChallenge>,
    pub winternitz_evidence: BTreeMap<String, WinternitzEvidence>,
    pub slashing_batches: BTreeMap<String, LowFeeSlashingBatch>,
    pub public_api_snapshots: BTreeMap<String, PublicApiSnapshot>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::empty_devnet();
        state.refresh();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::empty_devnet();
        state.seed_demo();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        for receipt in self.receipt_commitments.values() {
            if !self.exit_bonds.contains_key(&receipt.exit_bond_id) {
                return Err(format!(
                    "receipt {} references missing exit bond",
                    receipt.receipt_id
                ));
            }
        }
        for challenge in self.slashing_challenges.values() {
            if !self.exit_bonds.contains_key(&challenge.exit_bond_id) {
                return Err(format!(
                    "challenge {} references missing exit bond",
                    challenge.challenge_id
                ));
            }
            if !self.receipt_commitments.contains_key(&challenge.receipt_id) {
                return Err(format!(
                    "challenge {} references missing receipt",
                    challenge.challenge_id
                ));
            }
        }
        for evidence in self.winternitz_evidence.values() {
            if !self
                .slashing_challenges
                .contains_key(&evidence.challenge_id)
            {
                return Err(format!(
                    "evidence {} references missing challenge",
                    evidence.evidence_id
                ));
            }
        }
        Ok(())
    }

    pub fn register_exit_bond(&mut self, input: ExitBondInput) -> Result<String> {
        let bond = ExitBond::from_input(&self.config, input)?;
        if self.exit_bonds.contains_key(&bond.exit_bond_id) {
            return Err("exit bond already registered".to_string());
        }
        let exit_bond_id = bond.exit_bond_id.clone();
        self.exit_bonds.insert(exit_bond_id.clone(), bond);
        self.refresh();
        Ok(exit_bond_id)
    }

    pub fn commit_receipt(&mut self, input: ReceiptCommitmentInput) -> Result<String> {
        if !self.exit_bonds.contains_key(&input.exit_bond_id) {
            return Err("receipt references unknown exit bond".to_string());
        }
        let receipt = PqReceiptCommitment::from_input(&self.config, self.epoch, input)?;
        if self.receipt_commitments.contains_key(&receipt.receipt_id) {
            return Err("pq receipt commitment already exists".to_string());
        }
        if let Some(bond) = self.exit_bonds.get_mut(&receipt.exit_bond_id) {
            bond.status = ExitBondStatus::ReceiptCommitted;
        }
        let receipt_id = receipt.receipt_id.clone();
        self.receipt_commitments.insert(receipt_id.clone(), receipt);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn open_slashing_challenge(&mut self, input: SlashingChallengeInput) -> Result<String> {
        let bond = self
            .exit_bonds
            .get(&input.exit_bond_id)
            .ok_or_else(|| "challenge references unknown exit bond".to_string())?;
        if input.opened_slot > bond.challenge_window_close_slot {
            return Err("slashing challenge opened after challenge window".to_string());
        }
        if !self.receipt_commitments.contains_key(&input.receipt_id) {
            return Err("challenge references unknown receipt".to_string());
        }
        let challenge = SlashingChallenge::from_input(&self.config, input)?;
        if self
            .slashing_challenges
            .contains_key(&challenge.challenge_id)
        {
            return Err("slashing challenge already exists".to_string());
        }
        if let Some(bond) = self.exit_bonds.get_mut(&challenge.exit_bond_id) {
            bond.status = ExitBondStatus::ChallengeOpen;
            bond.slash_locked_atomic = bond
                .slash_locked_atomic
                .saturating_add(challenge.slash_amount_atomic);
        }
        if let Some(receipt) = self.receipt_commitments.get_mut(&challenge.receipt_id) {
            receipt.status = ReceiptStatus::Challenged;
        }
        let challenge_id = challenge.challenge_id.clone();
        self.slashing_challenges
            .insert(challenge_id.clone(), challenge);
        self.refresh();
        Ok(challenge_id)
    }

    pub fn anchor_winternitz_evidence(&mut self, input: WinternitzEvidenceInput) -> Result<String> {
        let challenge = self
            .slashing_challenges
            .get(&input.challenge_id)
            .ok_or_else(|| "evidence references unknown challenge".to_string())?;
        if input.anchored_slot > challenge.evidence_deadline_slot {
            return Err("winternitz evidence anchored after evidence deadline".to_string());
        }
        let evidence = WinternitzEvidence::from_input(input)?;
        if self.winternitz_evidence.contains_key(&evidence.evidence_id) {
            return Err("winternitz evidence already exists".to_string());
        }
        if let Some(challenge) = self.slashing_challenges.get_mut(&evidence.challenge_id) {
            challenge.status = if evidence.accepted {
                ChallengeStatus::Accepted
            } else {
                ChallengeStatus::Rejected
            };
        }
        if evidence.accepted {
            let challenge = self
                .slashing_challenges
                .get(&evidence.challenge_id)
                .ok_or_else(|| "accepted evidence lost challenge reference".to_string())?;
            if let Some(bond) = self.exit_bonds.get_mut(&challenge.exit_bond_id) {
                bond.status = ExitBondStatus::SlashPending;
            }
        }
        let evidence_id = evidence.evidence_id.clone();
        self.winternitz_evidence
            .insert(evidence_id.clone(), evidence);
        self.refresh();
        Ok(evidence_id)
    }

    pub fn post_low_fee_slashing_batch(
        &mut self,
        input: LowFeeSlashingBatchInput,
    ) -> Result<String> {
        for challenge_id in &input.challenge_ids {
            if !self.slashing_challenges.contains_key(challenge_id) {
                return Err(format!("batch references unknown challenge {challenge_id}"));
            }
        }
        let batch = LowFeeSlashingBatch::from_input(&self.config, input)?;
        if self.slashing_batches.contains_key(&batch.batch_id) {
            return Err("low fee slashing batch already exists".to_string());
        }
        for challenge_id in &batch.challenge_ids {
            if let Some(challenge) = self.slashing_challenges.get_mut(challenge_id) {
                challenge.status = ChallengeStatus::Settled;
                challenge.batch_id = Some(batch.batch_id.clone());
                if let Some(bond) = self.exit_bonds.get_mut(&challenge.exit_bond_id) {
                    let slash = challenge
                        .slash_amount_atomic
                        .min(bond.exit_bond_atomic - bond.slashed_atomic);
                    bond.slashed_atomic = bond.slashed_atomic.saturating_add(slash);
                    bond.slash_locked_atomic = bond.slash_locked_atomic.saturating_sub(slash);
                    bond.status = ExitBondStatus::Slashed;
                }
            }
        }
        let batch_id = batch.batch_id.clone();
        self.slashing_batches.insert(batch_id.clone(), batch);
        self.refresh();
        Ok(batch_id)
    }

    pub fn add_public_api_snapshot(&mut self, input: PublicApiSnapshotInput) -> Result<String> {
        let snapshot = PublicApiSnapshot::from_input(&self.roots, input)?;
        if self
            .public_api_snapshots
            .contains_key(&snapshot.snapshot_id)
        {
            return Err("public api snapshot already exists".to_string());
        }
        let snapshot_id = snapshot.snapshot_id.clone();
        self.public_api_snapshots
            .insert(snapshot_id.clone(), snapshot);
        self.refresh();
        Ok(snapshot_id)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn seed_demo(&mut self) {
        for index in 0..6_u64 {
            let exit_bond_id = self
                .register_exit_bond(ExitBondInput {
                    validator_commitment: sample_root("winternitz-validator", index),
                    exit_nullifier: sample_root("exit-nullifier", index),
                    winternitz_public_key_root: sample_root("wots-public-key-root", index),
                    pq_identity_commitment: sample_root("pq-identity", index),
                    epoch: self.epoch,
                    slot: self.slot + index * 8,
                    exit_bond_atomic: self.config.exit_bond_atomic,
                })
                .expect("demo exit bond registration must succeed");
            let receipt_id = self
                .commit_receipt(ReceiptCommitmentInput {
                    exit_bond_id: exit_bond_id.clone(),
                    receipt_commitment: sample_root("pq-receipt", index),
                    receipt_nullifier: sample_root("receipt-nullifier", index),
                    pq_signature_commitment: sample_root("pq-signature", index),
                    observed_state_root: sample_root("observed-state", index),
                    anchor_slot: self.slot + index * 8 + 2,
                })
                .expect("demo receipt commitment must succeed");
            if index % 2 == 0 {
                let challenge_id = self
                    .open_slashing_challenge(SlashingChallengeInput {
                        exit_bond_id: exit_bond_id.clone(),
                        receipt_id,
                        challenger_commitment: sample_root("challenger", index),
                        evidence_kind: if index == 0 {
                            SlashingEvidenceKind::DoubleExit
                        } else {
                            SlashingEvidenceKind::InvalidReceipt
                        },
                        evidence_root: sample_root("evidence-root", index),
                        slash_amount_atomic: self.config.min_slash_atomic + index * 500_000_000,
                        opened_slot: self.slot + index * 8 + 12,
                    })
                    .expect("demo slashing challenge must succeed");
                self.anchor_winternitz_evidence(WinternitzEvidenceInput {
                    challenge_id,
                    chain_disclosure_root: sample_root("chain-disclosure", index),
                    message_digest_root: sample_root("message-digest", index),
                    checksum_root: sample_root("checksum", index),
                    replay_guard: sample_root("replay-guard", index),
                    accepted: true,
                    anchored_slot: self.slot + index * 8 + 24,
                })
                .expect("demo winternitz evidence must succeed");
            }
        }
        let challenge_ids = self
            .slashing_challenges
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Accepted)
            .map(|challenge| challenge.challenge_id.clone())
            .collect::<Vec<_>>();
        if !challenge_ids.is_empty() {
            self.post_low_fee_slashing_batch(LowFeeSlashingBatchInput {
                sequencer_commitment: sample_root("slashing-sequencer", 0),
                challenge_ids,
                batch_fee_micro_units: self.config.max_batch_fee_micro_units / 2,
                posted_slot: self.slot + 128,
            })
            .expect("demo low fee slashing batch must succeed");
        }
        self.add_public_api_snapshot(PublicApiSnapshotInput {
            snapshot_label: "devnet-redacted-slashed-exit-bonds".to_string(),
            visibility_root: sample_root("visibility-policy", 0),
            request_count: 42,
            emitted_slot: self.slot + 160,
        })
        .expect("demo public api snapshot must succeed");
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            exit_bonds: self.exit_bonds.len() as u64,
            receipt_commitments: self.receipt_commitments.len() as u64,
            slashing_challenges: self.slashing_challenges.len() as u64,
            winternitz_evidence: self.winternitz_evidence.len() as u64,
            slashing_batches: self.slashing_batches.len() as u64,
            public_api_snapshots: self.public_api_snapshots.len() as u64,
            slash_pending_bonds: self
                .exit_bonds
                .values()
                .filter(|bond| bond.status == ExitBondStatus::SlashPending)
                .count() as u64,
            slashed_bonds: self
                .exit_bonds
                .values()
                .filter(|bond| bond.status == ExitBondStatus::Slashed)
                .count() as u64,
            total_exit_bond_atomic: self
                .exit_bonds
                .values()
                .map(|bond| bond.exit_bond_atomic)
                .sum(),
            total_slash_pending_atomic: self
                .exit_bonds
                .values()
                .filter(|bond| bond.status == ExitBondStatus::SlashPending)
                .map(|bond| bond.slash_locked_atomic)
                .sum(),
            total_slashed_atomic: self
                .exit_bonds
                .values()
                .map(|bond| bond.slashed_atomic)
                .sum(),
            total_challenge_bond_atomic: self
                .slashing_challenges
                .values()
                .map(|challenge| challenge.challenge_bond_atomic)
                .sum(),
            total_batch_fee_micro_units: self
                .slashing_batches
                .values()
                .map(|batch| batch.batch_fee_micro_units)
                .sum(),
            total_batched_challenges: self
                .slashing_batches
                .values()
                .map(|batch| batch.challenge_ids.len() as u64)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let exit_bond_root = record_root(
            "exit-bonds",
            self.exit_bonds
                .values()
                .map(ExitBond::public_record)
                .collect(),
        );
        let pq_receipt_commitment_root = record_root(
            "pq-receipt-commitments",
            self.receipt_commitments
                .values()
                .map(PqReceiptCommitment::public_record)
                .collect(),
        );
        let slashing_challenge_root = record_root(
            "slashing-challenges",
            self.slashing_challenges
                .values()
                .map(SlashingChallenge::public_record)
                .collect(),
        );
        let winternitz_evidence_root = record_root(
            "winternitz-evidence",
            self.winternitz_evidence
                .values()
                .map(WinternitzEvidence::public_record)
                .collect(),
        );
        let low_fee_slashing_batch_root = record_root(
            "low-fee-slashing-batches",
            self.slashing_batches
                .values()
                .map(LowFeeSlashingBatch::public_record)
                .collect(),
        );
        let public_api_snapshot_root = record_root(
            "public-api-snapshots",
            self.public_api_snapshots
                .values()
                .map(PublicApiSnapshot::public_record)
                .collect(),
        );
        let private_accounting_root = value_root(
            "private-accounting",
            &json!({
                "exit_bond_root": exit_bond_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "slashing_challenge_root": slashing_challenge_root,
                "winternitz_evidence_root": winternitz_evidence_root,
                "low_fee_slashing_batch_root": low_fee_slashing_batch_root,
                "redacted_totals": self.counters.public_record(),
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "exit_bond_root": exit_bond_root,
                "pq_receipt_commitment_root": pq_receipt_commitment_root,
                "slashing_challenge_root": slashing_challenge_root,
                "winternitz_evidence_root": winternitz_evidence_root,
                "low_fee_slashing_batch_root": low_fee_slashing_batch_root,
                "public_api_snapshot_root": public_api_snapshot_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-BOND-SLASHING-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&exit_bond_root),
                HashPart::Str(&pq_receipt_commitment_root),
                HashPart::Str(&slashing_challenge_root),
                HashPart::Str(&winternitz_evidence_root),
                HashPart::Str(&low_fee_slashing_batch_root),
                HashPart::Str(&public_api_snapshot_root),
                HashPart::Str(&private_accounting_root),
                HashPart::Str(&public_record_root),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slot),
            ],
            32,
        );
        Roots {
            exit_bond_root,
            pq_receipt_commitment_root,
            slashing_challenge_root,
            winternitz_evidence_root,
            low_fee_slashing_batch_root,
            public_api_snapshot_root,
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
            exit_bonds: BTreeMap::new(),
            receipt_commitments: BTreeMap::new(),
            slashing_challenges: BTreeMap::new(),
            winternitz_evidence: BTreeMap::new(),
            slashing_batches: BTreeMap::new(),
            public_api_snapshots: BTreeMap::new(),
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
        "winternitz_slashing_suite": WINTERNITZ_SLASHING_SUITE,
        "pq_receipt_commitment_suite": PQ_RECEIPT_COMMITMENT_SUITE,
        "slashing_challenge_window_suite": SLASHING_CHALLENGE_WINDOW_SUITE,
        "low_fee_slashing_batch_suite": LOW_FEE_SLASHING_BATCH_SUITE,
        "private_record_api_suite": PRIVATE_RECORD_API_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "exit_bonds": state
            .exit_bonds
            .values()
            .map(ExitBond::public_record)
            .collect::<Vec<_>>(),
        "receipt_commitments": state
            .receipt_commitments
            .values()
            .map(PqReceiptCommitment::public_record)
            .collect::<Vec<_>>(),
        "slashing_challenges": state
            .slashing_challenges
            .values()
            .map(SlashingChallenge::public_record)
            .collect::<Vec<_>>(),
        "winternitz_evidence": state
            .winternitz_evidence
            .values()
            .map(WinternitzEvidence::public_record)
            .collect::<Vec<_>>(),
        "slashing_batches": state
            .slashing_batches
            .values()
            .map(LowFeeSlashingBatch::public_record)
            .collect::<Vec<_>>(),
        "public_api_snapshots": state
            .public_api_snapshots
            .values()
            .map(PublicApiSnapshot::public_record)
            .collect::<Vec<_>>(),
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-BOND-SLASHING-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-BOND-SLASHING-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-BOND-SLASHING-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-BOND-SLASHING-{domain}"),
        &values,
    )
}
