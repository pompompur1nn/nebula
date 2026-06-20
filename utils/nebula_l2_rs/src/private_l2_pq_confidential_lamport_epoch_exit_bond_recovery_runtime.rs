use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialLamportEpochExitBondRecoveryRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_LAMPORT_EPOCH_EXIT_BOND_RECOVERY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-lamport-epoch-exit-bond-recovery-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_LAMPORT_EPOCH_EXIT_BOND_RECOVERY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LAMPORT_EXIT_RECOVERY_SUITE: &str = "lamport-hash-based-epoch-exit-bond-recovery-v1";
pub const PQ_RECEIPT_COMMITMENT_SUITE: &str = "pq-confidential-exit-receipt-commitment-v1";
pub const EXIT_BOND_CHALLENGE_SUITE: &str = "confidential-exit-bond-challenge-window-v1";
pub const LOW_FEE_EXIT_BATCH_SUITE: &str = "low-fee-lamport-exit-bond-recovery-batch-v1";
pub const PRIVATE_RECORD_API_SUITE: &str = "privacy-preserving-public-record-state-root-v1";
pub const DEVNET_HEIGHT: u64 = 8_584_000;
pub const DEVNET_EPOCH: u64 = 35_812;
pub const DEVNET_SLOT: u64 = 416;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LAMPORT_CHAIN_BITS: u16 = 256;
pub const DEFAULT_LAMPORT_KEY_ROUNDS: u16 = 2;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 32_000_000_000;
pub const DEFAULT_RECOVERY_COVERAGE_ATOMIC: u64 = 26_000_000_000;
pub const DEFAULT_CHALLENGE_BOND_ATOMIC: u64 = 2_400_000_000;
pub const DEFAULT_RECOVERY_FEE_ATOMIC: u64 = 320_000_000;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 384;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 180;
pub const DEFAULT_EXIT_CHALLENGE_WINDOW_SLOTS: u64 = 2_880;
pub const DEFAULT_EXIT_FINALITY_DELAY_SLOTS: u64 = 4_320;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 24;
pub const DEFAULT_EPOCH_BUCKET_TARGET_EXITS: u64 = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitBondStatus {
    Registered,
    ExitRequested,
    ReceiptCommitted,
    ChallengeOpen,
    Challenged,
    Recoverable,
    RecoveryQueued,
    Recovered,
    Expired,
}

impl ExitBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::ExitRequested => "exit_requested",
            Self::ReceiptCommitted => "receipt_committed",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::Recoverable => "recoverable",
            Self::RecoveryQueued => "recovery_queued",
            Self::Recovered => "recovered",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Anchored,
    WindowOpen,
    Disputed,
    Finalized,
    Recovered,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Anchored => "anchored",
            Self::WindowOpen => "window_open",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Recovered => "recovered",
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
    Slashed,
    Withdrawn,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::EvidenceAnchored => "evidence_anchored",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Withdrawn => "withdrawn",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Collecting,
    Sealed,
    Posted,
    Settled,
    Repriced,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::Repriced => "repriced",
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
    pub lamport_exit_recovery_suite: String,
    pub pq_receipt_commitment_suite: String,
    pub exit_bond_challenge_suite: String,
    pub low_fee_exit_batch_suite: String,
    pub private_record_api_suite: String,
    pub min_pq_security_bits: u16,
    pub lamport_chain_bits: u16,
    pub lamport_key_rounds: u16,
    pub exit_bond_atomic: u64,
    pub recovery_coverage_atomic: u64,
    pub challenge_bond_atomic: u64,
    pub recovery_fee_atomic: u64,
    pub low_fee_batch_limit: u16,
    pub max_batch_fee_micro_units: u64,
    pub exit_challenge_window_slots: u64,
    pub exit_finality_delay_slots: u64,
    pub receipt_retention_epochs: u64,
    pub epoch_bucket_target_exits: u64,
    pub pq_receipt_commitments_required: bool,
    pub lamport_witness_privacy_required: bool,
    pub challenge_windows_required: bool,
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
            lamport_exit_recovery_suite: LAMPORT_EXIT_RECOVERY_SUITE.to_string(),
            pq_receipt_commitment_suite: PQ_RECEIPT_COMMITMENT_SUITE.to_string(),
            exit_bond_challenge_suite: EXIT_BOND_CHALLENGE_SUITE.to_string(),
            low_fee_exit_batch_suite: LOW_FEE_EXIT_BATCH_SUITE.to_string(),
            private_record_api_suite: PRIVATE_RECORD_API_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            lamport_chain_bits: DEFAULT_LAMPORT_CHAIN_BITS,
            lamport_key_rounds: DEFAULT_LAMPORT_KEY_ROUNDS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            recovery_coverage_atomic: DEFAULT_RECOVERY_COVERAGE_ATOMIC,
            challenge_bond_atomic: DEFAULT_CHALLENGE_BOND_ATOMIC,
            recovery_fee_atomic: DEFAULT_RECOVERY_FEE_ATOMIC,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            exit_challenge_window_slots: DEFAULT_EXIT_CHALLENGE_WINDOW_SLOTS,
            exit_finality_delay_slots: DEFAULT_EXIT_FINALITY_DELAY_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            epoch_bucket_target_exits: DEFAULT_EPOCH_BUCKET_TARGET_EXITS,
            pq_receipt_commitments_required: true,
            lamport_witness_privacy_required: true,
            challenge_windows_required: true,
            low_fee_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below lamport exit bond recovery minimum".to_string());
        }
        if self.lamport_chain_bits < DEFAULT_LAMPORT_CHAIN_BITS || self.lamport_key_rounds == 0 {
            return Err("invalid lamport exit recovery key schedule".to_string());
        }
        if self.exit_bond_atomic == 0
            || self.recovery_coverage_atomic == 0
            || self.challenge_bond_atomic == 0
            || self.recovery_fee_atomic == 0
            || self.recovery_coverage_atomic > self.exit_bond_atomic
        {
            return Err("invalid lamport exit bond recovery economics".to_string());
        }
        if self.low_fee_batch_limit == 0 || self.max_batch_fee_micro_units == 0 {
            return Err("low-fee exit recovery batch limits must be positive".to_string());
        }
        if self.exit_challenge_window_slots == 0
            || self.exit_challenge_window_slots > self.exit_finality_delay_slots
        {
            return Err("invalid exit-bond challenge window".to_string());
        }
        if self.receipt_retention_epochs == 0 || self.epoch_bucket_target_exits == 0 {
            return Err("receipt retention and epoch bucket targets must be positive".to_string());
        }
        if !self.pq_receipt_commitments_required
            || !self.lamport_witness_privacy_required
            || !self.challenge_windows_required
        {
            return Err(
                "lamport exit recovery privacy and challenge gates are mandatory".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub exit_bonds: u64,
    pub receipt_commitments: u64,
    pub challenge_windows: u64,
    pub lamport_recovery_proofs: u64,
    pub recovery_batches: u64,
    pub public_api_snapshots: u64,
    pub active_exits: u64,
    pub challenged_exits: u64,
    pub recoverable_exits: u64,
    pub recovered_exits: u64,
    pub total_exit_bond_atomic: u64,
    pub total_recovery_coverage_atomic: u64,
    pub total_challenge_bond_atomic: u64,
    pub total_recovery_fee_atomic: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_batched_receipts: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub exit_bond_root: String,
    pub receipt_commitment_root: String,
    pub challenge_window_root: String,
    pub lamport_recovery_proof_root: String,
    pub recovery_batch_root: String,
    pub public_api_snapshot_root: String,
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
pub struct ExitBondRegistrationInput {
    pub validator_commitment: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub lamport_public_root: String,
    pub exit_bond_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitmentInput {
    pub exit_bond_id: String,
    pub exit_epoch: u64,
    pub receipt_commitment_root: String,
    pub pq_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindowInput {
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub challenge_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LamportRecoveryProofInput {
    pub receipt_id: String,
    pub lamport_witness_root: String,
    pub recovery_destination_root: String,
    pub zk_transcript_root: String,
    pub proof_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchInput {
    pub epoch: u64,
    pub receipt_ids: BTreeSet<String>,
    pub batch_fee_micro_units: u64,
    pub compression_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitBond {
    pub exit_bond_id: String,
    pub validator_commitment: String,
    pub operator_commitment: String,
    pub withdrawal_authority_commitment: String,
    pub epoch: u64,
    pub exit_bond_commitment: String,
    pub lamport_public_root: String,
    pub lamport_epoch_key_root: String,
    pub receipt_nullifier: String,
    pub exit_bond_atomic: u64,
    pub recovery_coverage_atomic: u64,
    pub recovery_fee_atomic: u64,
    pub status: ExitBondStatus,
}

impl ExitBond {
    pub fn public_record(&self) -> Value {
        json!({
            "exit_bond_id": self.exit_bond_id,
            "validator_commitment": self.validator_commitment,
            "operator_commitment": self.operator_commitment,
            "withdrawal_authority_commitment": self.withdrawal_authority_commitment,
            "epoch": self.epoch,
            "exit_bond_commitment": self.exit_bond_commitment,
            "lamport_public_root": self.lamport_public_root,
            "lamport_epoch_key_root": self.lamport_epoch_key_root,
            "receipt_nullifier": self.receipt_nullifier,
            "exit_bond_atomic": self.exit_bond_atomic,
            "recovery_coverage_atomic": self.recovery_coverage_atomic,
            "recovery_fee_atomic": self.recovery_fee_atomic,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptCommitment {
    pub receipt_id: String,
    pub exit_bond_id: String,
    pub exit_epoch: u64,
    pub receipt_commitment_root: String,
    pub pq_signature_commitment_root: String,
    pub encrypted_receipt_payload_root: String,
    pub exit_intent_root: String,
    pub receipt_nullifier: String,
    pub committed_slot: u64,
    pub challenge_window_start_slot: u64,
    pub challenge_window_end_slot: u64,
    pub pq_security_bits: u16,
    pub status: ReceiptStatus,
}

impl PqReceiptCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "exit_bond_id": self.exit_bond_id,
            "exit_epoch": self.exit_epoch,
            "receipt_commitment_root": self.receipt_commitment_root,
            "pq_signature_commitment_root": self.pq_signature_commitment_root,
            "encrypted_receipt_payload_root": self.encrypted_receipt_payload_root,
            "exit_intent_root": self.exit_intent_root,
            "receipt_nullifier": self.receipt_nullifier,
            "committed_slot": self.committed_slot,
            "challenge_window_start_slot": self.challenge_window_start_slot,
            "challenge_window_end_slot": self.challenge_window_end_slot,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitBondChallengeWindow {
    pub challenge_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub counter_witness_root: String,
    pub challenge_bond_commitment: String,
    pub challenge_bond_atomic: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub status: ChallengeStatus,
}

impl ExitBondChallengeWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "receipt_id": self.receipt_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "counter_witness_root": self.counter_witness_root,
            "challenge_bond_commitment": self.challenge_bond_commitment,
            "challenge_bond_atomic": self.challenge_bond_atomic,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LamportRecoveryProof {
    pub proof_id: String,
    pub receipt_id: String,
    pub exit_bond_id: String,
    pub lamport_witness_root: String,
    pub lamport_one_time_signature_root: String,
    pub lamport_chain_position_root: String,
    pub recovery_destination_root: String,
    pub recovery_amount_commitment: String,
    pub zk_transcript_root: String,
    pub nullifier_check_root: String,
    pub proof_slot: u64,
    pub accepted: bool,
}

impl LamportRecoveryProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "receipt_id": self.receipt_id,
            "exit_bond_id": self.exit_bond_id,
            "lamport_witness_root": self.lamport_witness_root,
            "lamport_one_time_signature_root": self.lamport_one_time_signature_root,
            "lamport_chain_position_root": self.lamport_chain_position_root,
            "recovery_destination_root": self.recovery_destination_root,
            "recovery_amount_commitment": self.recovery_amount_commitment,
            "zk_transcript_root": self.zk_transcript_root,
            "nullifier_check_root": self.nullifier_check_root,
            "proof_slot": self.proof_slot,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeExitRecoveryBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub receipt_ids: BTreeSet<String>,
    pub proof_ids: BTreeSet<String>,
    pub aggregate_receipt_root: String,
    pub aggregate_lamport_witness_root: String,
    pub compression_commitment_root: String,
    pub fee_sponsor_commitment: String,
    pub batch_fee_micro_units: u64,
    pub per_receipt_fee_micro_units: u64,
    pub status: BatchStatus,
}

impl LowFeeExitRecoveryBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "receipt_ids": self.receipt_ids,
            "proof_ids": self.proof_ids,
            "aggregate_receipt_root": self.aggregate_receipt_root,
            "aggregate_lamport_witness_root": self.aggregate_lamport_witness_root,
            "compression_commitment_root": self.compression_commitment_root,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "per_receipt_fee_micro_units": self.per_receipt_fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicApiSnapshot {
    pub snapshot_id: String,
    pub epoch: u64,
    pub exposed_state_root: String,
    pub exposed_receipt_root: String,
    pub exposed_challenge_root: String,
    pub privacy_budget_root: String,
    pub redaction_policy_root: String,
    pub created_slot: u64,
}

impl PublicApiSnapshot {
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
    pub exit_bonds: BTreeMap<String, ExitBond>,
    pub receipt_commitments: BTreeMap<String, PqReceiptCommitment>,
    pub challenge_windows: BTreeMap<String, ExitBondChallengeWindow>,
    pub lamport_recovery_proofs: BTreeMap<String, LamportRecoveryProof>,
    pub recovery_batches: BTreeMap<String, LowFeeExitRecoveryBatch>,
    pub public_api_snapshots: BTreeMap<String, PublicApiSnapshot>,
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
            exit_bonds: BTreeMap::new(),
            receipt_commitments: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            lamport_recovery_proofs: BTreeMap::new(),
            recovery_batches: BTreeMap::new(),
            public_api_snapshots: BTreeMap::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH, DEVNET_SLOT)
            .unwrap_or_else(|_| Self::empty_devnet());
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn register_exit_bond(&mut self, input: ExitBondRegistrationInput) -> Result<String> {
        if input.epoch + self.config.receipt_retention_epochs < self.epoch {
            return Err("exit bond registration epoch is outside receipt retention".to_string());
        }
        let exit_bond_id = deterministic_id(
            "exit-bond",
            &[
                HashPart::Str(&input.validator_commitment),
                HashPart::Str(&input.exit_bond_commitment),
                HashPart::U64(input.epoch),
            ],
        );
        let bond = ExitBond {
            exit_bond_id: exit_bond_id.clone(),
            validator_commitment: input.validator_commitment,
            operator_commitment: input.operator_commitment,
            withdrawal_authority_commitment: sample_root("withdrawal-authority", input.epoch),
            epoch: input.epoch,
            exit_bond_commitment: input.exit_bond_commitment,
            lamport_public_root: input.lamport_public_root.clone(),
            lamport_epoch_key_root: value_root(
                "lamport-epoch-key",
                &json!({
                    "epoch": input.epoch,
                    "lamport_public_root": input.lamport_public_root,
                    "rounds": self.config.lamport_key_rounds,
                }),
            ),
            receipt_nullifier: sample_root("receipt-nullifier", input.epoch),
            exit_bond_atomic: self.config.exit_bond_atomic,
            recovery_coverage_atomic: self.config.recovery_coverage_atomic,
            recovery_fee_atomic: self.config.recovery_fee_atomic,
            status: ExitBondStatus::Registered,
        };
        self.exit_bonds.insert(exit_bond_id.clone(), bond);
        self.refresh();
        Ok(exit_bond_id)
    }

    pub fn commit_pq_receipt(&mut self, input: PqReceiptCommitmentInput) -> Result<String> {
        if !self.exit_bonds.contains_key(&input.exit_bond_id) {
            return Err("unknown exit bond for pq receipt commitment".to_string());
        }
        let receipt_id = deterministic_id(
            "pq-receipt",
            &[
                HashPart::Str(&input.exit_bond_id),
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::U64(input.exit_epoch),
            ],
        );
        let window_start = self.slot;
        let window_end = window_start + self.config.exit_challenge_window_slots;
        let receipt = PqReceiptCommitment {
            receipt_id: receipt_id.clone(),
            exit_bond_id: input.exit_bond_id.clone(),
            exit_epoch: input.exit_epoch,
            receipt_commitment_root: input.receipt_commitment_root,
            pq_signature_commitment_root: input.pq_signature_commitment_root,
            encrypted_receipt_payload_root: input.encrypted_receipt_payload_root,
            exit_intent_root: sample_root("exit-intent", input.exit_epoch),
            receipt_nullifier: sample_root("pq-receipt-nullifier", input.exit_epoch),
            committed_slot: self.slot,
            challenge_window_start_slot: window_start,
            challenge_window_end_slot: window_end,
            pq_security_bits: self.config.min_pq_security_bits,
            status: ReceiptStatus::WindowOpen,
        };
        if let Some(bond) = self.exit_bonds.get_mut(&input.exit_bond_id) {
            bond.status = ExitBondStatus::ChallengeOpen;
        }
        self.receipt_commitments.insert(receipt_id.clone(), receipt);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn open_challenge_window(&mut self, input: ChallengeWindowInput) -> Result<String> {
        let receipt = self
            .receipt_commitments
            .get(&input.receipt_id)
            .ok_or_else(|| "unknown receipt for exit-bond challenge".to_string())?;
        if input.challenge_slot > receipt.challenge_window_end_slot {
            return Err("exit-bond challenge submitted after challenge window".to_string());
        }
        let challenge_id = deterministic_id(
            "exit-bond-challenge",
            &[
                HashPart::Str(&input.receipt_id),
                HashPart::Str(&input.challenger_commitment),
                HashPart::Str(&input.evidence_root),
            ],
        );
        let challenge = ExitBondChallengeWindow {
            challenge_id: challenge_id.clone(),
            receipt_id: input.receipt_id.clone(),
            challenger_commitment: input.challenger_commitment,
            evidence_root: input.evidence_root,
            counter_witness_root: sample_root("challenge-counter-witness", input.challenge_slot),
            challenge_bond_commitment: sample_root(
                "challenge-bond-commitment",
                input.challenge_slot,
            ),
            challenge_bond_atomic: self.config.challenge_bond_atomic,
            opened_slot: input.challenge_slot,
            expires_slot: receipt.challenge_window_end_slot,
            status: ChallengeStatus::EvidenceAnchored,
        };
        if let Some(receipt) = self.receipt_commitments.get_mut(&input.receipt_id) {
            receipt.status = ReceiptStatus::Disputed;
            if let Some(bond) = self.exit_bonds.get_mut(&receipt.exit_bond_id) {
                bond.status = ExitBondStatus::Challenged;
            }
        }
        self.challenge_windows
            .insert(challenge_id.clone(), challenge);
        self.refresh();
        Ok(challenge_id)
    }

    pub fn accept_lamport_recovery_proof(
        &mut self,
        input: LamportRecoveryProofInput,
    ) -> Result<String> {
        let receipt = self
            .receipt_commitments
            .get(&input.receipt_id)
            .ok_or_else(|| "unknown receipt for lamport recovery proof".to_string())?;
        if input.proof_slot < receipt.challenge_window_end_slot {
            return Err(
                "lamport recovery proof arrived before challenge window closed".to_string(),
            );
        }
        if input.proof_slot
            > receipt.challenge_window_end_slot + self.config.exit_finality_delay_slots
        {
            return Err("lamport recovery proof arrived after finality delay".to_string());
        }
        let proof_id = deterministic_id(
            "lamport-recovery-proof",
            &[
                HashPart::Str(&input.receipt_id),
                HashPart::Str(&input.lamport_witness_root),
                HashPart::Str(&input.zk_transcript_root),
            ],
        );
        let proof = LamportRecoveryProof {
            proof_id: proof_id.clone(),
            receipt_id: input.receipt_id.clone(),
            exit_bond_id: receipt.exit_bond_id.clone(),
            lamport_witness_root: input.lamport_witness_root,
            lamport_one_time_signature_root: sample_root(
                "lamport-one-time-signature",
                input.proof_slot,
            ),
            lamport_chain_position_root: sample_root("lamport-chain-position", input.proof_slot),
            recovery_destination_root: input.recovery_destination_root,
            recovery_amount_commitment: sample_root("recovery-amount", input.proof_slot),
            zk_transcript_root: input.zk_transcript_root,
            nullifier_check_root: sample_root("lamport-nullifier-check", input.proof_slot),
            proof_slot: input.proof_slot,
            accepted: true,
        };
        if let Some(receipt) = self.receipt_commitments.get_mut(&input.receipt_id) {
            receipt.status = ReceiptStatus::Recovered;
            if let Some(bond) = self.exit_bonds.get_mut(&receipt.exit_bond_id) {
                bond.status = ExitBondStatus::Recovered;
            }
        }
        self.lamport_recovery_proofs.insert(proof_id.clone(), proof);
        self.refresh();
        Ok(proof_id)
    }

    pub fn seal_low_fee_batch(&mut self, input: LowFeeBatchInput) -> Result<String> {
        if input.receipt_ids.is_empty() {
            return Err("low-fee recovery batch cannot be empty".to_string());
        }
        if input.receipt_ids.len() > usize::from(self.config.low_fee_batch_limit) {
            return Err("low-fee recovery batch exceeds configured limit".to_string());
        }
        if input.batch_fee_micro_units > self.config.max_batch_fee_micro_units {
            return Err("low-fee recovery batch fee exceeds configured maximum".to_string());
        }
        let proof_ids = self
            .lamport_recovery_proofs
            .values()
            .filter(|proof| input.receipt_ids.contains(&proof.receipt_id))
            .map(|proof| proof.proof_id.clone())
            .collect::<BTreeSet<_>>();
        let batch_id = deterministic_id(
            "low-fee-exit-recovery-batch",
            &[
                HashPart::U64(input.epoch),
                HashPart::U64(input.receipt_ids.len() as u64),
                HashPart::Str(&input.compression_root),
            ],
        );
        let per_receipt_fee_micro_units =
            input.batch_fee_micro_units / input.receipt_ids.len() as u64;
        let batch = LowFeeExitRecoveryBatch {
            batch_id: batch_id.clone(),
            epoch: input.epoch,
            receipt_ids: input.receipt_ids,
            proof_ids,
            aggregate_receipt_root: sample_root("aggregate-receipt", input.epoch),
            aggregate_lamport_witness_root: sample_root("aggregate-lamport-witness", input.epoch),
            compression_commitment_root: input.compression_root,
            fee_sponsor_commitment: sample_root("batch-fee-sponsor", input.epoch),
            batch_fee_micro_units: input.batch_fee_micro_units,
            per_receipt_fee_micro_units,
            status: BatchStatus::Settled,
        };
        self.recovery_batches.insert(batch_id.clone(), batch);
        self.refresh();
        Ok(batch_id)
    }

    fn seed_devnet(&mut self) {
        for index in 0_u64..5 {
            let exit_bond_id = deterministic_id(
                "exit-bond",
                &[HashPart::U64(self.epoch), HashPart::U64(index)],
            );
            let status = match index {
                0 | 1 => ExitBondStatus::Recovered,
                2 => ExitBondStatus::Challenged,
                3 => ExitBondStatus::RecoveryQueued,
                _ => ExitBondStatus::ChallengeOpen,
            };
            self.exit_bonds.insert(
                exit_bond_id.clone(),
                ExitBond {
                    exit_bond_id: exit_bond_id.clone(),
                    validator_commitment: sample_root("validator-exit-commitment", index),
                    operator_commitment: sample_root("operator-exit-commitment", index),
                    withdrawal_authority_commitment: sample_root("withdrawal-authority", index),
                    epoch: self.epoch,
                    exit_bond_commitment: sample_root("exit-bond-commitment", index),
                    lamport_public_root: sample_root("lamport-public-root", index),
                    lamport_epoch_key_root: sample_root("lamport-epoch-key-root", index),
                    receipt_nullifier: sample_root("receipt-nullifier", index),
                    exit_bond_atomic: self.config.exit_bond_atomic,
                    recovery_coverage_atomic: self.config.recovery_coverage_atomic,
                    recovery_fee_atomic: self.config.recovery_fee_atomic,
                    status,
                },
            );
            let receipt_id = deterministic_id(
                "pq-receipt",
                &[HashPart::Str(&exit_bond_id), HashPart::U64(index)],
            );
            self.receipt_commitments.insert(
                receipt_id.clone(),
                PqReceiptCommitment {
                    receipt_id: receipt_id.clone(),
                    exit_bond_id: exit_bond_id.clone(),
                    exit_epoch: self.epoch + index,
                    receipt_commitment_root: sample_root("pq-receipt-commitment", index),
                    pq_signature_commitment_root: sample_root("pq-signature-commitment", index),
                    encrypted_receipt_payload_root: sample_root("encrypted-receipt-payload", index),
                    exit_intent_root: sample_root("exit-intent", index),
                    receipt_nullifier: sample_root("pq-receipt-nullifier", index),
                    committed_slot: self.slot + index * 8,
                    challenge_window_start_slot: self.slot + index * 8,
                    challenge_window_end_slot: self.slot
                        + index * 8
                        + self.config.exit_challenge_window_slots,
                    pq_security_bits: self.config.min_pq_security_bits,
                    status: if index == 2 {
                        ReceiptStatus::Disputed
                    } else {
                        ReceiptStatus::Finalized
                    },
                },
            );
            if index < 3 {
                let challenge_id = deterministic_id(
                    "exit-bond-challenge",
                    &[HashPart::Str(&receipt_id), HashPart::U64(index)],
                );
                self.challenge_windows.insert(
                    challenge_id.clone(),
                    ExitBondChallengeWindow {
                        challenge_id,
                        receipt_id: receipt_id.clone(),
                        challenger_commitment: sample_root("challenger-commitment", index),
                        evidence_root: sample_root("challenge-evidence", index),
                        counter_witness_root: sample_root("challenge-counter-witness", index),
                        challenge_bond_commitment: sample_root("challenge-bond", index),
                        challenge_bond_atomic: self.config.challenge_bond_atomic,
                        opened_slot: self.slot + 32 + index,
                        expires_slot: self.slot + self.config.exit_challenge_window_slots,
                        status: if index == 2 {
                            ChallengeStatus::Accepted
                        } else {
                            ChallengeStatus::Rejected
                        },
                    },
                );
            }
            if index < 4 {
                let proof_id = deterministic_id(
                    "lamport-recovery-proof",
                    &[HashPart::Str(&receipt_id), HashPart::U64(index)],
                );
                self.lamport_recovery_proofs.insert(
                    proof_id.clone(),
                    LamportRecoveryProof {
                        proof_id,
                        receipt_id: receipt_id.clone(),
                        exit_bond_id: exit_bond_id.clone(),
                        lamport_witness_root: sample_root("lamport-witness", index),
                        lamport_one_time_signature_root: sample_root("lamport-ots", index),
                        lamport_chain_position_root: sample_root("lamport-position", index),
                        recovery_destination_root: sample_root("recovery-destination", index),
                        recovery_amount_commitment: sample_root("recovery-amount", index),
                        zk_transcript_root: sample_root("lamport-recovery-zk", index),
                        nullifier_check_root: sample_root("lamport-nullifier-check", index),
                        proof_slot: self.slot
                            + self.config.exit_challenge_window_slots
                            + 16
                            + index,
                        accepted: index != 2,
                    },
                );
            }
        }
        let receipt_ids = self
            .receipt_commitments
            .keys()
            .take(4)
            .cloned()
            .collect::<BTreeSet<_>>();
        let proof_ids = self
            .lamport_recovery_proofs
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let batch_id = deterministic_id(
            "low-fee-exit-recovery-batch",
            &[
                HashPart::U64(self.epoch),
                HashPart::U64(receipt_ids.len() as u64),
            ],
        );
        self.recovery_batches.insert(
            batch_id.clone(),
            LowFeeExitRecoveryBatch {
                batch_id,
                epoch: self.epoch,
                receipt_ids,
                proof_ids,
                aggregate_receipt_root: sample_root("aggregate-receipt", 0),
                aggregate_lamport_witness_root: sample_root("aggregate-lamport-witness", 0),
                compression_commitment_root: sample_root("low-fee-compression", 0),
                fee_sponsor_commitment: sample_root("fee-sponsor", 0),
                batch_fee_micro_units: 140,
                per_receipt_fee_micro_units: 35,
                status: BatchStatus::Settled,
            },
        );
        for index in 0_u64..3 {
            let snapshot_id = deterministic_id(
                "public-api-snapshot",
                &[HashPart::U64(self.epoch), HashPart::U64(index)],
            );
            self.public_api_snapshots.insert(
                snapshot_id.clone(),
                PublicApiSnapshot {
                    snapshot_id,
                    epoch: self.epoch + index,
                    exposed_state_root: sample_root("exposed-state", index),
                    exposed_receipt_root: sample_root("exposed-receipt", index),
                    exposed_challenge_root: sample_root("exposed-challenge", index),
                    privacy_budget_root: sample_root("privacy-budget", index),
                    redaction_policy_root: sample_root("redaction-policy", index),
                    created_slot: self.slot + index * 64,
                },
            );
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            exit_bonds: self.exit_bonds.len() as u64,
            receipt_commitments: self.receipt_commitments.len() as u64,
            challenge_windows: self.challenge_windows.len() as u64,
            lamport_recovery_proofs: self.lamport_recovery_proofs.len() as u64,
            recovery_batches: self.recovery_batches.len() as u64,
            public_api_snapshots: self.public_api_snapshots.len() as u64,
            active_exits: self
                .exit_bonds
                .values()
                .filter(|bond| {
                    matches!(
                        bond.status,
                        ExitBondStatus::ExitRequested | ExitBondStatus::ChallengeOpen
                    )
                })
                .count() as u64,
            challenged_exits: self
                .exit_bonds
                .values()
                .filter(|bond| bond.status == ExitBondStatus::Challenged)
                .count() as u64,
            recoverable_exits: self
                .exit_bonds
                .values()
                .filter(|bond| {
                    matches!(
                        bond.status,
                        ExitBondStatus::Recoverable | ExitBondStatus::RecoveryQueued
                    )
                })
                .count() as u64,
            recovered_exits: self
                .exit_bonds
                .values()
                .filter(|bond| bond.status == ExitBondStatus::Recovered)
                .count() as u64,
            total_exit_bond_atomic: self
                .exit_bonds
                .values()
                .map(|bond| bond.exit_bond_atomic)
                .sum(),
            total_recovery_coverage_atomic: self
                .exit_bonds
                .values()
                .map(|bond| bond.recovery_coverage_atomic)
                .sum(),
            total_challenge_bond_atomic: self
                .challenge_windows
                .values()
                .map(|challenge| challenge.challenge_bond_atomic)
                .sum(),
            total_recovery_fee_atomic: self
                .exit_bonds
                .values()
                .map(|bond| bond.recovery_fee_atomic)
                .sum(),
            total_batch_fee_micro_units: self
                .recovery_batches
                .values()
                .map(|batch| batch.batch_fee_micro_units)
                .sum(),
            total_batched_receipts: self
                .recovery_batches
                .values()
                .map(|batch| batch.receipt_ids.len() as u64)
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
        let receipt_commitment_root = record_root(
            "pq-receipt-commitments",
            self.receipt_commitments
                .values()
                .map(PqReceiptCommitment::public_record)
                .collect(),
        );
        let challenge_window_root = record_root(
            "exit-bond-challenge-windows",
            self.challenge_windows
                .values()
                .map(ExitBondChallengeWindow::public_record)
                .collect(),
        );
        let lamport_recovery_proof_root = record_root(
            "lamport-recovery-proofs",
            self.lamport_recovery_proofs
                .values()
                .map(LamportRecoveryProof::public_record)
                .collect(),
        );
        let recovery_batch_root = record_root(
            "low-fee-recovery-batches",
            self.recovery_batches
                .values()
                .map(LowFeeExitRecoveryBatch::public_record)
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
                "receipt_commitment_root": receipt_commitment_root,
                "challenge_window_root": challenge_window_root,
                "lamport_recovery_proof_root": lamport_recovery_proof_root,
                "recovery_batch_root": recovery_batch_root,
                "redacted_totals": self.counters.public_record(),
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "exit_bond_root": exit_bond_root,
                "receipt_commitment_root": receipt_commitment_root,
                "challenge_window_root": challenge_window_root,
                "lamport_recovery_proof_root": lamport_recovery_proof_root,
                "recovery_batch_root": recovery_batch_root,
                "public_api_snapshot_root": public_api_snapshot_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EPOCH-EXIT-BOND-RECOVERY-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&exit_bond_root),
                HashPart::Str(&receipt_commitment_root),
                HashPart::Str(&challenge_window_root),
                HashPart::Str(&lamport_recovery_proof_root),
                HashPart::Str(&recovery_batch_root),
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
            receipt_commitment_root,
            challenge_window_root,
            lamport_recovery_proof_root,
            recovery_batch_root,
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
            challenge_windows: BTreeMap::new(),
            lamport_recovery_proofs: BTreeMap::new(),
            recovery_batches: BTreeMap::new(),
            public_api_snapshots: BTreeMap::new(),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "height": state.height,
        "epoch": state.epoch,
        "slot": state.slot,
        "hash_suite": HASH_SUITE,
        "lamport_exit_recovery_suite": LAMPORT_EXIT_RECOVERY_SUITE,
        "pq_receipt_commitment_suite": PQ_RECEIPT_COMMITMENT_SUITE,
        "exit_bond_challenge_suite": EXIT_BOND_CHALLENGE_SUITE,
        "low_fee_exit_batch_suite": LOW_FEE_EXIT_BATCH_SUITE,
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
        "challenge_windows": state
            .challenge_windows
            .values()
            .map(ExitBondChallengeWindow::public_record)
            .collect::<Vec<_>>(),
        "lamport_recovery_proofs": state
            .lamport_recovery_proofs
            .values()
            .map(LamportRecoveryProof::public_record)
            .collect::<Vec<_>>(),
        "recovery_batches": state
            .recovery_batches
            .values()
            .map(LowFeeExitRecoveryBatch::public_record)
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EPOCH-EXIT-BOND-RECOVERY-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EPOCH-EXIT-BOND-RECOVERY-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EPOCH-EXIT-BOND-RECOVERY-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EPOCH-EXIT-BOND-RECOVERY-{domain}"),
        &values,
    )
}
