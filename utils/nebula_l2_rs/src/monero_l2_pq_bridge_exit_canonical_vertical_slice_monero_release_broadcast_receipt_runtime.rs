use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceMoneroReleaseBroadcastReceiptRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_RELEASE_BROADCAST_RECEIPT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-monero-release-broadcast-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_RELEASE_BROADCAST_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BROADCAST_RECEIPT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-monero-release-broadcast-receipt-v1";
pub const TX_ENVELOPE_COMMITMENT_SUITE: &str =
    "monero-release-transaction-envelope-commitment-roots-only-v1";
pub const MEMPOOL_OBSERVATION_SUITE: &str =
    "monero-release-broadcast-mempool-observation-roots-only-v1";
pub const DEFAULT_NETWORK: &str = "monero-devnet";
pub const DEFAULT_RELEASE_LANE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-release-broadcast-lane-devnet-v1";
pub const DEFAULT_OBSERVER_SET_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-release-broadcast-observers-devnet-v1";
pub const DEFAULT_CONFIRMATION_TARGET: u64 = 20;
pub const DEFAULT_REORG_WATCH_BLOCKS: u64 = 16;
pub const DEFAULT_CURRENT_MONERO_HEIGHT: u64 = 3_514_320;
pub const DEFAULT_MIN_OBSERVER_WEIGHT: u64 = 67;
pub const DEFAULT_MAX_BROADCAST_ATTEMPTS: u64 = 3;
pub const DEFAULT_MAX_FEE_PICONERO: u64 = 18_000_000;
pub const DEFAULT_MAX_WEIGHT: u64 = 120_000;
pub const DEFAULT_MIN_WEIGHT: u64 = 1_200;
pub const DEFAULT_MAX_MEMPOOL_LAG_BLOCKS: u64 = 3;
pub const DEFAULT_MAX_HOLD_REASONS: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastReceiptStatus {
    Complete,
    PendingObservation,
    Held,
    Rejected,
}

impl BroadcastReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::PendingObservation => "pending_observation",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastAttemptStatus {
    AcceptedByPeer,
    AlreadyKnown,
    PendingEcho,
    RejectedByPolicy,
    NotAttempted,
}

impl BroadcastAttemptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedByPeer => "accepted_by_peer",
            Self::AlreadyKnown => "already_known",
            Self::PendingEcho => "pending_echo",
            Self::RejectedByPolicy => "rejected_by_policy",
            Self::NotAttempted => "not_attempted",
        }
    }

    pub fn contributes_to_broadcast(self) -> bool {
        matches!(self, Self::AcceptedByPeer | Self::AlreadyKnown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MempoolObservationStatus {
    Observed,
    SeenByQuorum,
    Missing,
    Conflicting,
    Expired,
}

impl MempoolObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::SeenByQuorum => "seen_by_quorum",
            Self::Missing => "missing",
            Self::Conflicting => "conflicting",
            Self::Expired => "expired",
        }
    }

    pub fn is_positive(self) -> bool {
        matches!(self, Self::Observed | Self::SeenByQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationWindowStatus {
    TargetReached,
    WaitingForTarget,
    WatchingReorg,
    ReorgDetected,
    Expired,
}

impl ConfirmationWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TargetReached => "target_reached",
            Self::WaitingForTarget => "waiting_for_target",
            Self::WatchingReorg => "watching_reorg",
            Self::ReorgDetected => "reorg_detected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReasonKind {
    PlannedTransactionRootMissing,
    TxEnvelopeCommitmentMissing,
    BroadcastAttemptRootMissing,
    BroadcastAttemptQuorumPending,
    FeeAboveBound,
    WeightAboveBound,
    WeightBelowBound,
    MempoolObservationRootMissing,
    MempoolObservationConflicting,
    ConfirmationTargetPending,
    ReorgWatchActive,
    ReorgDetected,
    RedactedPayoutRootMissing,
    ObserverWeightBelowThreshold,
    TooManyBroadcastAttempts,
    ReceiptRootMismatch,
}

impl HoldReasonKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlannedTransactionRootMissing => "planned_transaction_root_missing",
            Self::TxEnvelopeCommitmentMissing => "tx_envelope_commitment_missing",
            Self::BroadcastAttemptRootMissing => "broadcast_attempt_root_missing",
            Self::BroadcastAttemptQuorumPending => "broadcast_attempt_quorum_pending",
            Self::FeeAboveBound => "fee_above_bound",
            Self::WeightAboveBound => "weight_above_bound",
            Self::WeightBelowBound => "weight_below_bound",
            Self::MempoolObservationRootMissing => "mempool_observation_root_missing",
            Self::MempoolObservationConflicting => "mempool_observation_conflicting",
            Self::ConfirmationTargetPending => "confirmation_target_pending",
            Self::ReorgWatchActive => "reorg_watch_active",
            Self::ReorgDetected => "reorg_detected",
            Self::RedactedPayoutRootMissing => "redacted_payout_root_missing",
            Self::ObserverWeightBelowThreshold => "observer_weight_below_threshold",
            Self::TooManyBroadcastAttempts => "too_many_broadcast_attempts",
            Self::ReceiptRootMismatch => "receipt_root_mismatch",
        }
    }

    pub fn severity(self) -> u64 {
        match self {
            Self::ReorgDetected | Self::ReceiptRootMismatch => 4,
            Self::FeeAboveBound
            | Self::WeightAboveBound
            | Self::WeightBelowBound
            | Self::MempoolObservationConflicting
            | Self::TooManyBroadcastAttempts => 3,
            Self::PlannedTransactionRootMissing
            | Self::TxEnvelopeCommitmentMissing
            | Self::BroadcastAttemptRootMissing
            | Self::MempoolObservationRootMissing
            | Self::RedactedPayoutRootMissing
            | Self::ObserverWeightBelowThreshold => 2,
            Self::BroadcastAttemptQuorumPending
            | Self::ConfirmationTargetPending
            | Self::ReorgWatchActive => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub broadcast_receipt_suite: String,
    pub tx_envelope_commitment_suite: String,
    pub mempool_observation_suite: String,
    pub network: String,
    pub release_lane_id: String,
    pub observer_set_id: String,
    pub min_observer_weight: u64,
    pub max_broadcast_attempts: u64,
    pub max_fee_piconero: u64,
    pub min_weight: u64,
    pub max_weight: u64,
    pub confirmation_target: u64,
    pub reorg_watch_blocks: u64,
    pub max_mempool_lag_blocks: u64,
    pub max_hold_reasons: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            broadcast_receipt_suite: BROADCAST_RECEIPT_SUITE.to_string(),
            tx_envelope_commitment_suite: TX_ENVELOPE_COMMITMENT_SUITE.to_string(),
            mempool_observation_suite: MEMPOOL_OBSERVATION_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            release_lane_id: DEFAULT_RELEASE_LANE_ID.to_string(),
            observer_set_id: DEFAULT_OBSERVER_SET_ID.to_string(),
            min_observer_weight: DEFAULT_MIN_OBSERVER_WEIGHT,
            max_broadcast_attempts: DEFAULT_MAX_BROADCAST_ATTEMPTS,
            max_fee_piconero: DEFAULT_MAX_FEE_PICONERO,
            min_weight: DEFAULT_MIN_WEIGHT,
            max_weight: DEFAULT_MAX_WEIGHT,
            confirmation_target: DEFAULT_CONFIRMATION_TARGET,
            reorg_watch_blocks: DEFAULT_REORG_WATCH_BLOCKS,
            max_mempool_lag_blocks: DEFAULT_MAX_MEMPOOL_LAG_BLOCKS,
            max_hold_reasons: DEFAULT_MAX_HOLD_REASONS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "broadcast_receipt_suite": self.broadcast_receipt_suite,
            "tx_envelope_commitment_suite": self.tx_envelope_commitment_suite,
            "mempool_observation_suite": self.mempool_observation_suite,
            "network": self.network,
            "release_lane_id": self.release_lane_id,
            "observer_set_id": self.observer_set_id,
            "min_observer_weight": self.min_observer_weight,
            "max_broadcast_attempts": self.max_broadcast_attempts,
            "max_fee_piconero": self.max_fee_piconero,
            "min_weight": self.min_weight,
            "max_weight": self.max_weight,
            "confirmation_target": self.confirmation_target,
            "reorg_watch_blocks": self.reorg_watch_blocks,
            "max_mempool_lag_blocks": self.max_mempool_lag_blocks,
            "max_hold_reasons": self.max_hold_reasons
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_bridge_exit_broadcast_receipt_config",
            &[HashPart::Json(self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlannedTransactionEvidence {
    pub plan_id: String,
    pub planned_transaction_root: String,
    pub transaction_prefix_root: String,
    pub input_set_root: String,
    pub output_set_root: String,
    pub change_commitment_root: String,
    pub release_instruction_root: String,
    pub custody_debit_root: String,
    pub plan_height: u64,
    pub plan_ordinal: u64,
}

impl PlannedTransactionEvidence {
    pub fn evidence_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_planned_transaction_evidence",
            &[
                HashPart::Str(&self.plan_id),
                HashPart::Str(&self.planned_transaction_root),
                HashPart::Str(&self.transaction_prefix_root),
                HashPart::Str(&self.input_set_root),
                HashPart::Str(&self.output_set_root),
                HashPart::Str(&self.change_commitment_root),
                HashPart::Str(&self.release_instruction_root),
                HashPart::Str(&self.custody_debit_root),
                HashPart::U64(self.plan_height),
                HashPart::U64(self.plan_ordinal),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "planned_transaction_root": self.planned_transaction_root,
            "transaction_prefix_root": self.transaction_prefix_root,
            "input_set_root": self.input_set_root,
            "output_set_root": self.output_set_root,
            "change_commitment_root": self.change_commitment_root,
            "release_instruction_root": self.release_instruction_root,
            "custody_debit_root": self.custody_debit_root,
            "plan_height": self.plan_height,
            "plan_ordinal": self.plan_ordinal,
            "evidence_root": self.evidence_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxEnvelopeCommitment {
    pub envelope_id: String,
    pub tx_envelope_commitment: String,
    pub tx_prefix_hash_commitment: String,
    pub tx_blob_length_commitment: String,
    pub signature_set_commitment: String,
    pub ring_member_root: String,
    pub key_image_commitment_root: String,
    pub bulletproof_commitment_root: String,
    pub amount_balance_root: String,
    pub metadata_root: String,
}

impl TxEnvelopeCommitment {
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_tx_envelope_commitment",
            &[
                HashPart::Str(&self.envelope_id),
                HashPart::Str(&self.tx_envelope_commitment),
                HashPart::Str(&self.tx_prefix_hash_commitment),
                HashPart::Str(&self.tx_blob_length_commitment),
                HashPart::Str(&self.signature_set_commitment),
                HashPart::Str(&self.ring_member_root),
                HashPart::Str(&self.key_image_commitment_root),
                HashPart::Str(&self.bulletproof_commitment_root),
                HashPart::Str(&self.amount_balance_root),
                HashPart::Str(&self.metadata_root),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "tx_envelope_commitment": self.tx_envelope_commitment,
            "tx_prefix_hash_commitment": self.tx_prefix_hash_commitment,
            "tx_blob_length_commitment": self.tx_blob_length_commitment,
            "signature_set_commitment": self.signature_set_commitment,
            "ring_member_root": self.ring_member_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "bulletproof_commitment_root": self.bulletproof_commitment_root,
            "amount_balance_root": self.amount_balance_root,
            "metadata_root": self.metadata_root,
            "commitment_root": self.commitment_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeWeightBounds {
    pub bound_id: String,
    pub claimed_fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub observed_weight: u64,
    pub min_weight: u64,
    pub max_weight: u64,
    pub fee_rate_floor: u64,
    pub fee_rate_ceiling: u64,
    pub fee_policy_root: String,
    pub weight_proof_root: String,
}

impl FeeWeightBounds {
    pub fn fee_within_bound(&self) -> bool {
        self.claimed_fee_piconero <= self.max_fee_piconero
    }

    pub fn weight_within_bound(&self) -> bool {
        self.observed_weight >= self.min_weight && self.observed_weight <= self.max_weight
    }

    pub fn bounds_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_fee_weight_bounds",
            &[
                HashPart::Str(&self.bound_id),
                HashPart::U64(self.claimed_fee_piconero),
                HashPart::U64(self.max_fee_piconero),
                HashPart::U64(self.observed_weight),
                HashPart::U64(self.min_weight),
                HashPart::U64(self.max_weight),
                HashPart::U64(self.fee_rate_floor),
                HashPart::U64(self.fee_rate_ceiling),
                HashPart::Str(&self.fee_policy_root),
                HashPart::Str(&self.weight_proof_root),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bound_id": self.bound_id,
            "claimed_fee_piconero": self.claimed_fee_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "observed_weight": self.observed_weight,
            "min_weight": self.min_weight,
            "max_weight": self.max_weight,
            "fee_rate_floor": self.fee_rate_floor,
            "fee_rate_ceiling": self.fee_rate_ceiling,
            "fee_policy_root": self.fee_policy_root,
            "weight_proof_root": self.weight_proof_root,
            "fee_within_bound": self.fee_within_bound(),
            "weight_within_bound": self.weight_within_bound(),
            "bounds_root": self.bounds_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BroadcastAttempt {
    pub attempt_id: String,
    pub attempt_ordinal: u64,
    pub relay_group_root: String,
    pub request_commitment_root: String,
    pub response_commitment_root: String,
    pub peer_policy_root: String,
    pub attempt_height: u64,
    pub observed_latency_ms: u64,
    pub observer_weight: u64,
    pub status: BroadcastAttemptStatus,
}

impl BroadcastAttempt {
    pub fn attempt_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_attempt",
            &[
                HashPart::Str(&self.attempt_id),
                HashPart::U64(self.attempt_ordinal),
                HashPart::Str(&self.relay_group_root),
                HashPart::Str(&self.request_commitment_root),
                HashPart::Str(&self.response_commitment_root),
                HashPart::Str(&self.peer_policy_root),
                HashPart::U64(self.attempt_height),
                HashPart::U64(self.observed_latency_ms),
                HashPart::U64(self.observer_weight),
                HashPart::Str(self.status.as_str()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attempt_id": self.attempt_id,
            "attempt_ordinal": self.attempt_ordinal,
            "relay_group_root": self.relay_group_root,
            "request_commitment_root": self.request_commitment_root,
            "response_commitment_root": self.response_commitment_root,
            "peer_policy_root": self.peer_policy_root,
            "attempt_height": self.attempt_height,
            "observed_latency_ms": self.observed_latency_ms,
            "observer_weight": self.observer_weight,
            "status": self.status.as_str(),
            "attempt_root": self.attempt_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BroadcastAttemptLedger {
    pub ledger_id: String,
    pub attempts: Vec<BroadcastAttempt>,
    pub quorum_policy_root: String,
}

impl BroadcastAttemptLedger {
    pub fn accepted_weight(&self) -> u64 {
        self.attempts
            .iter()
            .filter(|attempt| attempt.status.contributes_to_broadcast())
            .map(|attempt| attempt.observer_weight)
            .sum()
    }

    pub fn attempt_count(&self) -> u64 {
        self.attempts.len() as u64
    }

    pub fn attempt_roots(&self) -> Vec<String> {
        self.attempts
            .iter()
            .map(BroadcastAttempt::attempt_root)
            .collect()
    }

    pub fn broadcast_attempt_root(&self) -> String {
        let roots = self.attempt_roots();
        let attempt_root = merkle_root(&roots);
        domain_hash(
            "monero_release_broadcast_attempt_ledger",
            &[
                HashPart::Str(&self.ledger_id),
                HashPart::Str(&attempt_root),
                HashPart::Str(&self.quorum_policy_root),
                HashPart::U64(self.attempt_count()),
                HashPart::U64(self.accepted_weight()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        let attempts: Vec<Value> = self
            .attempts
            .iter()
            .map(BroadcastAttempt::public_record)
            .collect();
        json!({
            "ledger_id": self.ledger_id,
            "attempts": attempts,
            "quorum_policy_root": self.quorum_policy_root,
            "accepted_weight": self.accepted_weight(),
            "attempt_count": self.attempt_count(),
            "broadcast_attempt_root": self.broadcast_attempt_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MempoolObservation {
    pub observation_id: String,
    pub observer_id: String,
    pub observer_weight: u64,
    pub seen_height: u64,
    pub seen_mempool_epoch: u64,
    pub txid_commitment: String,
    pub tx_envelope_commitment: String,
    pub mempool_position_commitment: String,
    pub conflict_set_root: String,
    pub status: MempoolObservationStatus,
}

impl MempoolObservation {
    pub fn observation_leaf_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_mempool_observation_leaf",
            &[
                HashPart::Str(&self.observation_id),
                HashPart::Str(&self.observer_id),
                HashPart::U64(self.observer_weight),
                HashPart::U64(self.seen_height),
                HashPart::U64(self.seen_mempool_epoch),
                HashPart::Str(&self.txid_commitment),
                HashPart::Str(&self.tx_envelope_commitment),
                HashPart::Str(&self.mempool_position_commitment),
                HashPart::Str(&self.conflict_set_root),
                HashPart::Str(self.status.as_str()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "observer_id": self.observer_id,
            "observer_weight": self.observer_weight,
            "seen_height": self.seen_height,
            "seen_mempool_epoch": self.seen_mempool_epoch,
            "txid_commitment": self.txid_commitment,
            "tx_envelope_commitment": self.tx_envelope_commitment,
            "mempool_position_commitment": self.mempool_position_commitment,
            "conflict_set_root": self.conflict_set_root,
            "status": self.status.as_str(),
            "observation_leaf_root": self.observation_leaf_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MempoolObservationLedger {
    pub ledger_id: String,
    pub observations: Vec<MempoolObservation>,
    pub observer_set_root: String,
    pub quorum_policy_root: String,
}

impl MempoolObservationLedger {
    pub fn positive_weight(&self) -> u64 {
        self.observations
            .iter()
            .filter(|observation| observation.status.is_positive())
            .map(|observation| observation.observer_weight)
            .sum()
    }

    pub fn has_conflict(&self) -> bool {
        self.observations
            .iter()
            .any(|observation| observation.status == MempoolObservationStatus::Conflicting)
    }

    pub fn earliest_seen_height(&self) -> u64 {
        self.observations
            .iter()
            .map(|observation| observation.seen_height)
            .min()
            .map_or(0, |height| height)
    }

    pub fn latest_seen_height(&self) -> u64 {
        self.observations
            .iter()
            .map(|observation| observation.seen_height)
            .max()
            .map_or(0, |height| height)
    }

    pub fn observation_roots(&self) -> Vec<String> {
        self.observations
            .iter()
            .map(MempoolObservation::observation_leaf_root)
            .collect()
    }

    pub fn mempool_observation_root(&self) -> String {
        let roots = self.observation_roots();
        let observation_root = merkle_root(&roots);
        domain_hash(
            "monero_release_broadcast_mempool_observation_ledger",
            &[
                HashPart::Str(&self.ledger_id),
                HashPart::Str(&observation_root),
                HashPart::Str(&self.observer_set_root),
                HashPart::Str(&self.quorum_policy_root),
                HashPart::U64(self.positive_weight()),
                HashPart::U64(self.earliest_seen_height()),
                HashPart::U64(self.latest_seen_height()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        let observations: Vec<Value> = self
            .observations
            .iter()
            .map(MempoolObservation::public_record)
            .collect();
        json!({
            "ledger_id": self.ledger_id,
            "observations": observations,
            "observer_set_root": self.observer_set_root,
            "quorum_policy_root": self.quorum_policy_root,
            "positive_weight": self.positive_weight(),
            "has_conflict": self.has_conflict(),
            "earliest_seen_height": self.earliest_seen_height(),
            "latest_seen_height": self.latest_seen_height(),
            "mempool_observation_root": self.mempool_observation_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfirmationTarget {
    pub target_id: String,
    pub broadcast_height: u64,
    pub current_height: u64,
    pub required_confirmations: u64,
    pub observed_confirmations: u64,
    pub target_height: u64,
    pub checkpoint_root: String,
    pub status: ConfirmationWindowStatus,
}

impl ConfirmationTarget {
    pub fn from_heights(
        target_id: String,
        broadcast_height: u64,
        current_height: u64,
        required_confirmations: u64,
        checkpoint_root: String,
    ) -> Self {
        let observed_confirmations = current_height.saturating_sub(broadcast_height);
        let target_height = broadcast_height.saturating_add(required_confirmations);
        let status = if observed_confirmations >= required_confirmations {
            ConfirmationWindowStatus::TargetReached
        } else {
            ConfirmationWindowStatus::WaitingForTarget
        };
        Self {
            target_id,
            broadcast_height,
            current_height,
            required_confirmations,
            observed_confirmations,
            target_height,
            checkpoint_root,
            status,
        }
    }

    pub fn target_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_confirmation_target",
            &[
                HashPart::Str(&self.target_id),
                HashPart::U64(self.broadcast_height),
                HashPart::U64(self.current_height),
                HashPart::U64(self.required_confirmations),
                HashPart::U64(self.observed_confirmations),
                HashPart::U64(self.target_height),
                HashPart::Str(&self.checkpoint_root),
                HashPart::Str(self.status.as_str()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "target_id": self.target_id,
            "broadcast_height": self.broadcast_height,
            "current_height": self.current_height,
            "required_confirmations": self.required_confirmations,
            "observed_confirmations": self.observed_confirmations,
            "target_height": self.target_height,
            "checkpoint_root": self.checkpoint_root,
            "status": self.status.as_str(),
            "target_root": self.target_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReorgWatch {
    pub watch_id: String,
    pub anchor_height: u64,
    pub current_height: u64,
    pub watch_blocks: u64,
    pub watch_until_height: u64,
    pub competing_chain_root: String,
    pub canonical_chain_root: String,
    pub watcher_attestation_root: String,
    pub status: ConfirmationWindowStatus,
}

impl ReorgWatch {
    pub fn new(
        watch_id: String,
        anchor_height: u64,
        current_height: u64,
        watch_blocks: u64,
        competing_chain_root: String,
        canonical_chain_root: String,
        watcher_attestation_root: String,
    ) -> Self {
        let watch_until_height = anchor_height.saturating_add(watch_blocks);
        let status = if current_height >= watch_until_height {
            ConfirmationWindowStatus::TargetReached
        } else {
            ConfirmationWindowStatus::WatchingReorg
        };
        Self {
            watch_id,
            anchor_height,
            current_height,
            watch_blocks,
            watch_until_height,
            competing_chain_root,
            canonical_chain_root,
            watcher_attestation_root,
            status,
        }
    }

    pub fn watch_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_reorg_watch",
            &[
                HashPart::Str(&self.watch_id),
                HashPart::U64(self.anchor_height),
                HashPart::U64(self.current_height),
                HashPart::U64(self.watch_blocks),
                HashPart::U64(self.watch_until_height),
                HashPart::Str(&self.competing_chain_root),
                HashPart::Str(&self.canonical_chain_root),
                HashPart::Str(&self.watcher_attestation_root),
                HashPart::Str(self.status.as_str()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watch_id": self.watch_id,
            "anchor_height": self.anchor_height,
            "current_height": self.current_height,
            "watch_blocks": self.watch_blocks,
            "watch_until_height": self.watch_until_height,
            "competing_chain_root": self.competing_chain_root,
            "canonical_chain_root": self.canonical_chain_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "status": self.status.as_str(),
            "watch_root": self.watch_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactedPayoutCommitment {
    pub payout_set_id: String,
    pub redacted_payout_root: String,
    pub payout_count: u64,
    pub amount_bucket_root: String,
    pub recipient_hint_root: String,
    pub view_tag_root: String,
    pub payout_opening_policy_root: String,
    pub disclosure_boundary_root: String,
}

impl RedactedPayoutCommitment {
    pub fn payout_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_redacted_payout_commitment",
            &[
                HashPart::Str(&self.payout_set_id),
                HashPart::Str(&self.redacted_payout_root),
                HashPart::U64(self.payout_count),
                HashPart::Str(&self.amount_bucket_root),
                HashPart::Str(&self.recipient_hint_root),
                HashPart::Str(&self.view_tag_root),
                HashPart::Str(&self.payout_opening_policy_root),
                HashPart::Str(&self.disclosure_boundary_root),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "payout_set_id": self.payout_set_id,
            "redacted_payout_root": self.redacted_payout_root,
            "payout_count": self.payout_count,
            "amount_bucket_root": self.amount_bucket_root,
            "recipient_hint_root": self.recipient_hint_root,
            "view_tag_root": self.view_tag_root,
            "payout_opening_policy_root": self.payout_opening_policy_root,
            "disclosure_boundary_root": self.disclosure_boundary_root,
            "payout_root": self.payout_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldReason {
    pub reason_id: String,
    pub kind: HoldReasonKind,
    pub severity: u64,
    pub subject_root: String,
    pub observed_value: String,
    pub required_value: String,
    pub clear_after_height: u64,
}

impl HoldReason {
    pub fn new(
        kind: HoldReasonKind,
        subject_root: String,
        observed_value: String,
        required_value: String,
        clear_after_height: u64,
    ) -> Self {
        let severity = kind.severity();
        let reason_id = domain_hash(
            "monero_release_broadcast_hold_reason_id",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::U64(severity),
                HashPart::Str(&subject_root),
                HashPart::Str(&observed_value),
                HashPart::Str(&required_value),
                HashPart::U64(clear_after_height),
            ],
        );
        Self {
            reason_id,
            kind,
            severity,
            subject_root,
            observed_value,
            required_value,
            clear_after_height,
        }
    }

    pub fn reason_root(&self) -> String {
        domain_hash(
            "monero_release_broadcast_hold_reason",
            &[
                HashPart::Str(&self.reason_id),
                HashPart::Str(self.kind.as_str()),
                HashPart::U64(self.severity),
                HashPart::Str(&self.subject_root),
                HashPart::Str(&self.observed_value),
                HashPart::Str(&self.required_value),
                HashPart::U64(self.clear_after_height),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reason_id": self.reason_id,
            "kind": self.kind.as_str(),
            "severity": self.severity,
            "subject_root": self.subject_root,
            "observed_value": self.observed_value,
            "required_value": self.required_value,
            "clear_after_height": self.clear_after_height,
            "reason_root": self.reason_root()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BroadcastReceiptRoots {
    pub planned_transaction_root: String,
    pub tx_envelope_commitment_root: String,
    pub broadcast_attempt_root: String,
    pub fee_weight_bounds_root: String,
    pub mempool_observation_root: String,
    pub confirmation_target_root: String,
    pub reorg_watch_root: String,
    pub redacted_payout_root: String,
    pub hold_reason_root: String,
    pub summary_root: String,
    pub receipt_root: String,
}

impl BroadcastReceiptRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "planned_transaction_root": self.planned_transaction_root,
            "tx_envelope_commitment_root": self.tx_envelope_commitment_root,
            "broadcast_attempt_root": self.broadcast_attempt_root,
            "fee_weight_bounds_root": self.fee_weight_bounds_root,
            "mempool_observation_root": self.mempool_observation_root,
            "confirmation_target_root": self.confirmation_target_root,
            "reorg_watch_root": self.reorg_watch_root,
            "redacted_payout_root": self.redacted_payout_root,
            "hold_reason_root": self.hold_reason_root,
            "summary_root": self.summary_root,
            "receipt_root": self.receipt_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BroadcastReceipt {
    pub receipt_id: String,
    pub release_id: String,
    pub status: BroadcastReceiptStatus,
    pub roots: BroadcastReceiptRoots,
    pub hold_reasons: Vec<HoldReason>,
    pub observed_at_l2_height: u64,
    pub observed_at_monero_height: u64,
}

impl BroadcastReceipt {
    pub fn public_record(&self) -> Value {
        let hold_reasons: Vec<Value> = self
            .hold_reasons
            .iter()
            .map(HoldReason::public_record)
            .collect();
        json!({
            "receipt_id": self.receipt_id,
            "release_id": self.release_id,
            "status": self.status.as_str(),
            "roots": self.roots.public_record(),
            "hold_reasons": hold_reasons,
            "observed_at_l2_height": self.observed_at_l2_height,
            "observed_at_monero_height": self.observed_at_monero_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub planned_transaction: PlannedTransactionEvidence,
    pub tx_envelope: TxEnvelopeCommitment,
    pub fee_weight_bounds: FeeWeightBounds,
    pub broadcast_attempts: BroadcastAttemptLedger,
    pub mempool_observations: MempoolObservationLedger,
    pub confirmation_target: ConfirmationTarget,
    pub reorg_watch: ReorgWatch,
    pub redacted_payout: RedactedPayoutCommitment,
    pub receipt: BroadcastReceipt,
    pub metadata: BTreeMap<String, String>,
}

impl State {
    pub fn new(
        config: Config,
        planned_transaction: PlannedTransactionEvidence,
        tx_envelope: TxEnvelopeCommitment,
        fee_weight_bounds: FeeWeightBounds,
        broadcast_attempts: BroadcastAttemptLedger,
        mempool_observations: MempoolObservationLedger,
        confirmation_target: ConfirmationTarget,
        reorg_watch: ReorgWatch,
        redacted_payout: RedactedPayoutCommitment,
        observed_at_l2_height: u64,
    ) -> Self {
        let mut metadata = BTreeMap::new();
        metadata.insert("runtime".to_string(), PROTOCOL_VERSION.to_string());
        metadata.insert("network".to_string(), config.network.clone());
        metadata.insert("lane".to_string(), config.release_lane_id.clone());

        let hold_reasons = derive_hold_reasons(
            &config,
            &planned_transaction,
            &tx_envelope,
            &fee_weight_bounds,
            &broadcast_attempts,
            &mempool_observations,
            &confirmation_target,
            &reorg_watch,
            &redacted_payout,
        );
        let roots = build_roots(
            &planned_transaction,
            &tx_envelope,
            &fee_weight_bounds,
            &broadcast_attempts,
            &mempool_observations,
            &confirmation_target,
            &reorg_watch,
            &redacted_payout,
            &hold_reasons,
        );
        let status = receipt_status(&hold_reasons, &confirmation_target, &reorg_watch);
        let receipt_id = domain_hash(
            "monero_release_broadcast_receipt_id",
            &[
                HashPart::Str(&planned_transaction.plan_id),
                HashPart::Str(&roots.receipt_root),
                HashPart::Str(status.as_str()),
                HashPart::U64(observed_at_l2_height),
                HashPart::U64(confirmation_target.current_height),
            ],
        );
        let receipt = BroadcastReceipt {
            receipt_id,
            release_id: planned_transaction.plan_id.clone(),
            status,
            roots,
            hold_reasons,
            observed_at_l2_height,
            observed_at_monero_height: confirmation_target.current_height,
        };
        Self {
            config,
            planned_transaction,
            tx_envelope,
            fee_weight_bounds,
            broadcast_attempts,
            mempool_observations,
            confirmation_target,
            reorg_watch,
            redacted_payout,
            receipt,
            metadata,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "planned_transaction": self.planned_transaction.public_record(),
            "tx_envelope": self.tx_envelope.public_record(),
            "fee_weight_bounds": self.fee_weight_bounds.public_record(),
            "broadcast_attempts": self.broadcast_attempts.public_record(),
            "mempool_observations": self.mempool_observations.public_record(),
            "confirmation_target": self.confirmation_target.public_record(),
            "reorg_watch": self.reorg_watch.public_record(),
            "redacted_payout": self.redacted_payout.public_record(),
            "receipt": self.receipt.public_record(),
            "metadata": self.metadata
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_bridge_exit_broadcast_receipt_state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.planned_transaction.evidence_root()),
                HashPart::Str(&self.tx_envelope.commitment_root()),
                HashPart::Str(&self.fee_weight_bounds.bounds_root()),
                HashPart::Str(&self.broadcast_attempts.broadcast_attempt_root()),
                HashPart::Str(&self.mempool_observations.mempool_observation_root()),
                HashPart::Str(&self.confirmation_target.target_root()),
                HashPart::Str(&self.reorg_watch.watch_root()),
                HashPart::Str(&self.redacted_payout.payout_root()),
                HashPart::Str(&self.receipt.roots.receipt_root),
                HashPart::Str(self.receipt.status.as_str()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err("chain_id_mismatch".to_string());
        }
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("protocol_version_mismatch".to_string());
        }
        if self.receipt.hold_reasons.len() > self.config.max_hold_reasons {
            return Err("hold_reason_limit_exceeded".to_string());
        }
        let expected_roots = build_roots(
            &self.planned_transaction,
            &self.tx_envelope,
            &self.fee_weight_bounds,
            &self.broadcast_attempts,
            &self.mempool_observations,
            &self.confirmation_target,
            &self.reorg_watch,
            &self.redacted_payout,
            &self.receipt.hold_reasons,
        );
        if expected_roots.receipt_root != self.receipt.roots.receipt_root {
            return Err("receipt_root_mismatch".to_string());
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let planned_transaction = PlannedTransactionEvidence {
        plan_id: "release-plan-devnet-0007".to_string(),
        planned_transaction_root: sample_root("planned-transaction", 7),
        transaction_prefix_root: sample_root("transaction-prefix", 7),
        input_set_root: sample_root("input-set", 7),
        output_set_root: sample_root("output-set", 7),
        change_commitment_root: sample_root("change-commitment", 7),
        release_instruction_root: sample_root("release-instruction", 7),
        custody_debit_root: sample_root("custody-debit", 7),
        plan_height: 8_881,
        plan_ordinal: 7,
    };
    let tx_envelope = TxEnvelopeCommitment {
        envelope_id: "tx-envelope-devnet-0007".to_string(),
        tx_envelope_commitment: sample_root("tx-envelope", 7),
        tx_prefix_hash_commitment: sample_root("tx-prefix-hash", 7),
        tx_blob_length_commitment: sample_root("tx-blob-length", 7),
        signature_set_commitment: sample_root("signature-set", 7),
        ring_member_root: sample_root("ring-member", 7),
        key_image_commitment_root: sample_root("key-image-commitment", 7),
        bulletproof_commitment_root: sample_root("bulletproof-commitment", 7),
        amount_balance_root: sample_root("amount-balance", 7),
        metadata_root: sample_root("metadata", 7),
    };
    let fee_weight_bounds = FeeWeightBounds {
        bound_id: "fee-weight-bound-devnet-0007".to_string(),
        claimed_fee_piconero: 12_400_000,
        max_fee_piconero: config.max_fee_piconero,
        observed_weight: 84_200,
        min_weight: config.min_weight,
        max_weight: config.max_weight,
        fee_rate_floor: 120,
        fee_rate_ceiling: 240,
        fee_policy_root: sample_root("fee-policy", 7),
        weight_proof_root: sample_root("weight-proof", 7),
    };
    let broadcast_attempts = BroadcastAttemptLedger {
        ledger_id: "broadcast-attempt-ledger-devnet-0007".to_string(),
        quorum_policy_root: sample_root("broadcast-quorum-policy", 7),
        attempts: vec![
            BroadcastAttempt {
                attempt_id: "broadcast-attempt-devnet-0007-a".to_string(),
                attempt_ordinal: 0,
                relay_group_root: sample_root("relay-group-a", 7),
                request_commitment_root: sample_root("relay-request-a", 7),
                response_commitment_root: sample_root("relay-response-a", 7),
                peer_policy_root: sample_root("peer-policy-a", 7),
                attempt_height: 3_514_300,
                observed_latency_ms: 840,
                observer_weight: 42,
                status: BroadcastAttemptStatus::AcceptedByPeer,
            },
            BroadcastAttempt {
                attempt_id: "broadcast-attempt-devnet-0007-b".to_string(),
                attempt_ordinal: 1,
                relay_group_root: sample_root("relay-group-b", 7),
                request_commitment_root: sample_root("relay-request-b", 7),
                response_commitment_root: sample_root("relay-response-b", 7),
                peer_policy_root: sample_root("peer-policy-b", 7),
                attempt_height: 3_514_301,
                observed_latency_ms: 1_120,
                observer_weight: 36,
                status: BroadcastAttemptStatus::AlreadyKnown,
            },
        ],
    };
    let mempool_observations = MempoolObservationLedger {
        ledger_id: "mempool-observation-ledger-devnet-0007".to_string(),
        observer_set_root: sample_root("observer-set", 7),
        quorum_policy_root: sample_root("mempool-quorum-policy", 7),
        observations: vec![
            MempoolObservation {
                observation_id: "mempool-observation-devnet-0007-a".to_string(),
                observer_id: "observer-devnet-a".to_string(),
                observer_weight: 35,
                seen_height: 3_514_301,
                seen_mempool_epoch: 91_200,
                txid_commitment: sample_root("txid-a", 7),
                tx_envelope_commitment: tx_envelope.commitment_root(),
                mempool_position_commitment: sample_root("mempool-position-a", 7),
                conflict_set_root: sample_root("empty-conflict-set-a", 7),
                status: MempoolObservationStatus::Observed,
            },
            MempoolObservation {
                observation_id: "mempool-observation-devnet-0007-b".to_string(),
                observer_id: "observer-devnet-b".to_string(),
                observer_weight: 34,
                seen_height: 3_514_302,
                seen_mempool_epoch: 91_201,
                txid_commitment: sample_root("txid-b", 7),
                tx_envelope_commitment: tx_envelope.commitment_root(),
                mempool_position_commitment: sample_root("mempool-position-b", 7),
                conflict_set_root: sample_root("empty-conflict-set-b", 7),
                status: MempoolObservationStatus::SeenByQuorum,
            },
        ],
    };
    let confirmation_target = ConfirmationTarget::from_heights(
        "confirmation-target-devnet-0007".to_string(),
        3_514_301,
        DEFAULT_CURRENT_MONERO_HEIGHT,
        config.confirmation_target,
        sample_root("confirmation-checkpoint", 7),
    );
    let reorg_watch = ReorgWatch::new(
        "reorg-watch-devnet-0007".to_string(),
        confirmation_target.target_height,
        DEFAULT_CURRENT_MONERO_HEIGHT,
        config.reorg_watch_blocks,
        sample_root("empty-competing-chain", 7),
        sample_root("canonical-chain", 7),
        sample_root("watcher-attestation", 7),
    );
    let redacted_payout = RedactedPayoutCommitment {
        payout_set_id: "redacted-payout-devnet-0007".to_string(),
        redacted_payout_root: sample_root("redacted-payout", 7),
        payout_count: 3,
        amount_bucket_root: sample_root("amount-bucket", 7),
        recipient_hint_root: sample_root("recipient-hint", 7),
        view_tag_root: sample_root("view-tag", 7),
        payout_opening_policy_root: sample_root("payout-opening-policy", 7),
        disclosure_boundary_root: sample_root("disclosure-boundary", 7),
    };
    State::new(
        config,
        planned_transaction,
        tx_envelope,
        fee_weight_bounds,
        broadcast_attempts,
        mempool_observations,
        confirmation_target,
        reorg_watch,
        redacted_payout,
        8_889,
    )
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn derive_hold_reasons(
    config: &Config,
    planned_transaction: &PlannedTransactionEvidence,
    tx_envelope: &TxEnvelopeCommitment,
    fee_weight_bounds: &FeeWeightBounds,
    broadcast_attempts: &BroadcastAttemptLedger,
    mempool_observations: &MempoolObservationLedger,
    confirmation_target: &ConfirmationTarget,
    reorg_watch: &ReorgWatch,
    redacted_payout: &RedactedPayoutCommitment,
) -> Vec<HoldReason> {
    let mut reasons = Vec::new();
    push_if_empty(
        &mut reasons,
        HoldReasonKind::PlannedTransactionRootMissing,
        &planned_transaction.planned_transaction_root,
        planned_transaction.evidence_root(),
        confirmation_target.current_height,
    );
    push_if_empty(
        &mut reasons,
        HoldReasonKind::TxEnvelopeCommitmentMissing,
        &tx_envelope.tx_envelope_commitment,
        tx_envelope.commitment_root(),
        confirmation_target.current_height,
    );
    push_if_empty(
        &mut reasons,
        HoldReasonKind::BroadcastAttemptRootMissing,
        &broadcast_attempts.broadcast_attempt_root(),
        broadcast_attempts.ledger_id.clone(),
        confirmation_target.current_height,
    );
    push_if_empty(
        &mut reasons,
        HoldReasonKind::MempoolObservationRootMissing,
        &mempool_observations.mempool_observation_root(),
        mempool_observations.ledger_id.clone(),
        confirmation_target.current_height,
    );
    push_if_empty(
        &mut reasons,
        HoldReasonKind::RedactedPayoutRootMissing,
        &redacted_payout.redacted_payout_root,
        redacted_payout.payout_root(),
        confirmation_target.current_height,
    );
    if broadcast_attempts.accepted_weight() < config.min_observer_weight {
        reasons.push(HoldReason::new(
            HoldReasonKind::BroadcastAttemptQuorumPending,
            broadcast_attempts.broadcast_attempt_root(),
            broadcast_attempts.accepted_weight().to_string(),
            config.min_observer_weight.to_string(),
            confirmation_target.current_height.saturating_add(1),
        ));
    }
    if broadcast_attempts.attempt_count() > config.max_broadcast_attempts {
        reasons.push(HoldReason::new(
            HoldReasonKind::TooManyBroadcastAttempts,
            broadcast_attempts.broadcast_attempt_root(),
            broadcast_attempts.attempt_count().to_string(),
            config.max_broadcast_attempts.to_string(),
            confirmation_target.current_height,
        ));
    }
    if !fee_weight_bounds.fee_within_bound() {
        reasons.push(HoldReason::new(
            HoldReasonKind::FeeAboveBound,
            fee_weight_bounds.bounds_root(),
            fee_weight_bounds.claimed_fee_piconero.to_string(),
            fee_weight_bounds.max_fee_piconero.to_string(),
            confirmation_target.current_height,
        ));
    }
    if fee_weight_bounds.observed_weight > fee_weight_bounds.max_weight {
        reasons.push(HoldReason::new(
            HoldReasonKind::WeightAboveBound,
            fee_weight_bounds.bounds_root(),
            fee_weight_bounds.observed_weight.to_string(),
            fee_weight_bounds.max_weight.to_string(),
            confirmation_target.current_height,
        ));
    }
    if fee_weight_bounds.observed_weight < fee_weight_bounds.min_weight {
        reasons.push(HoldReason::new(
            HoldReasonKind::WeightBelowBound,
            fee_weight_bounds.bounds_root(),
            fee_weight_bounds.observed_weight.to_string(),
            fee_weight_bounds.min_weight.to_string(),
            confirmation_target.current_height,
        ));
    }
    if mempool_observations.positive_weight() < config.min_observer_weight {
        reasons.push(HoldReason::new(
            HoldReasonKind::ObserverWeightBelowThreshold,
            mempool_observations.mempool_observation_root(),
            mempool_observations.positive_weight().to_string(),
            config.min_observer_weight.to_string(),
            confirmation_target.current_height.saturating_add(1),
        ));
    }
    if mempool_observations.has_conflict() {
        reasons.push(HoldReason::new(
            HoldReasonKind::MempoolObservationConflicting,
            mempool_observations.mempool_observation_root(),
            "conflict_seen".to_string(),
            "no_conflict".to_string(),
            confirmation_target.current_height,
        ));
    }
    if confirmation_target.observed_confirmations < confirmation_target.required_confirmations {
        reasons.push(HoldReason::new(
            HoldReasonKind::ConfirmationTargetPending,
            confirmation_target.target_root(),
            confirmation_target.observed_confirmations.to_string(),
            confirmation_target.required_confirmations.to_string(),
            confirmation_target.target_height,
        ));
    }
    if reorg_watch.status == ConfirmationWindowStatus::WatchingReorg {
        reasons.push(HoldReason::new(
            HoldReasonKind::ReorgWatchActive,
            reorg_watch.watch_root(),
            reorg_watch.current_height.to_string(),
            reorg_watch.watch_until_height.to_string(),
            reorg_watch.watch_until_height,
        ));
    }
    if reorg_watch.status == ConfirmationWindowStatus::ReorgDetected {
        reasons.push(HoldReason::new(
            HoldReasonKind::ReorgDetected,
            reorg_watch.watch_root(),
            reorg_watch.competing_chain_root.clone(),
            reorg_watch.canonical_chain_root.clone(),
            confirmation_target.current_height,
        ));
    }
    reasons.truncate(config.max_hold_reasons);
    reasons
}

fn push_if_empty(
    reasons: &mut Vec<HoldReason>,
    kind: HoldReasonKind,
    value: &str,
    subject_root: String,
    clear_after_height: u64,
) {
    if value.is_empty() {
        reasons.push(HoldReason::new(
            kind,
            subject_root,
            "missing".to_string(),
            "present".to_string(),
            clear_after_height,
        ));
    }
}

fn receipt_status(
    hold_reasons: &[HoldReason],
    confirmation_target: &ConfirmationTarget,
    reorg_watch: &ReorgWatch,
) -> BroadcastReceiptStatus {
    if hold_reasons.iter().any(|reason| reason.severity >= 4) {
        return BroadcastReceiptStatus::Rejected;
    }
    if !hold_reasons.is_empty() {
        return BroadcastReceiptStatus::Held;
    }
    if confirmation_target.status == ConfirmationWindowStatus::TargetReached
        && reorg_watch.status == ConfirmationWindowStatus::TargetReached
    {
        BroadcastReceiptStatus::Complete
    } else {
        BroadcastReceiptStatus::PendingObservation
    }
}

fn build_roots(
    planned_transaction: &PlannedTransactionEvidence,
    tx_envelope: &TxEnvelopeCommitment,
    fee_weight_bounds: &FeeWeightBounds,
    broadcast_attempts: &BroadcastAttemptLedger,
    mempool_observations: &MempoolObservationLedger,
    confirmation_target: &ConfirmationTarget,
    reorg_watch: &ReorgWatch,
    redacted_payout: &RedactedPayoutCommitment,
    hold_reasons: &[HoldReason],
) -> BroadcastReceiptRoots {
    let hold_reason_roots: Vec<String> = hold_reasons.iter().map(HoldReason::reason_root).collect();
    let hold_reason_root = merkle_root(&hold_reason_roots);
    let planned_transaction_root = planned_transaction.evidence_root();
    let tx_envelope_commitment_root = tx_envelope.commitment_root();
    let broadcast_attempt_root = broadcast_attempts.broadcast_attempt_root();
    let fee_weight_bounds_root = fee_weight_bounds.bounds_root();
    let mempool_observation_root = mempool_observations.mempool_observation_root();
    let confirmation_target_root = confirmation_target.target_root();
    let reorg_watch_root = reorg_watch.watch_root();
    let redacted_payout_root = redacted_payout.payout_root();
    let summary_root = domain_hash(
        "monero_release_broadcast_receipt_summary",
        &[
            HashPart::Str(&planned_transaction_root),
            HashPart::Str(&tx_envelope_commitment_root),
            HashPart::Str(&broadcast_attempt_root),
            HashPart::Str(&fee_weight_bounds_root),
            HashPart::Str(&mempool_observation_root),
            HashPart::Str(&confirmation_target_root),
            HashPart::Str(&reorg_watch_root),
            HashPart::Str(&redacted_payout_root),
            HashPart::Str(&hold_reason_root),
            HashPart::U64(hold_reasons.len() as u64),
        ],
    );
    let receipt_root = domain_hash(
        "monero_release_broadcast_receipt_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&summary_root),
            HashPart::Str(&planned_transaction.plan_id),
            HashPart::U64(confirmation_target.current_height),
            HashPart::U64(reorg_watch.watch_until_height),
        ],
    );
    BroadcastReceiptRoots {
        planned_transaction_root,
        tx_envelope_commitment_root,
        broadcast_attempt_root,
        fee_weight_bounds_root,
        mempool_observation_root,
        confirmation_target_root,
        reorg_watch_root,
        redacted_payout_root,
        hold_reason_root,
        summary_root,
        receipt_root,
    }
}

fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "monero_release_broadcast_receipt_devnet_sample",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
    )
}
